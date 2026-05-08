//! Background writer thread.
//!
//! The kernel pump must never block on disk I/O — if it stalls, events
//! pile up in the kernel ring and eventually get evicted with a
//! `drop_count`. So the pump only does a `try_send` over a bounded
//! channel; this thread is the one that actually touches the disk.
//!
//! # Pipeline
//!
//! ```text
//!  pump → mpsc::sync_channel(N) → writer thread → active.bin → batch-*.zst
//! ```
//!
//! # Drop policy
//!
//! Channel full = writer fell behind = drop the event and bump a counter.
//! The kernel already has its own drop counter; layering ours on top
//! gives us per-side visibility (was the event lost in the kernel ring,
//! or did the agent itself drop it?).
//!
//! # Rotation
//!
//! We rotate the active file when *either* of these triggers fires,
//! whichever comes first:
//! - the file has reached `max_bytes` (default 1 MiB)
//! - the file is older than `max_age` (default 10 s)
//!
//! Time-based rotation matters because a quiet endpoint would otherwise
//! never seal a batch — the uploader would have nothing to ship.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::spool::file::ActiveFile;

/// Tunables for the spool subsystem.
#[derive(Clone, Debug)]
pub struct SpoolConfig {
    /// Directory where `active.bin` and `batch-*.zst` live.
    pub dir: PathBuf,
    /// Rotate the active file when it reaches this many bytes.
    pub max_bytes_per_file: u64,
    /// Rotate the active file when it gets older than this, even if it
    /// hasn't reached `max_bytes_per_file`. Lets a quiet endpoint still
    /// produce batches periodically.
    pub max_age: Duration,
    /// Hard cap on the total size of sealed batches in `dir`. Oldest
    /// batches get evicted when this is exceeded.
    pub max_total_bytes: u64,
    /// Bounded channel capacity. Once full, the pump drops events
    /// (recorded under `events_dropped`).
    pub channel_capacity: usize,
    /// zstd compression level — 1 (fast) to 22 (slow). Level 3 is the
    /// "default" trade-off and matches what most production logging
    /// pipelines use.
    pub zstd_level: i32,
}

impl SpoolConfig {
    /// Sensible defaults for an endpoint agent.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self {
            dir,
            max_bytes_per_file: 1 * 1024 * 1024,        // 1 MiB
            max_age: Duration::from_secs(10),
            max_total_bytes: 256 * 1024 * 1024,         // 256 MiB
            channel_capacity: 1024,
            zstd_level: 3,
        }
    }
}

/// Counters published by the writer thread. The pump increments
/// `events_dropped` directly when its `try_send` fails; everything else
/// is the writer's job.
#[derive(Default)]
pub struct SpoolStats {
    pub events_written: AtomicU64,
    pub events_dropped: AtomicU64,
    pub batches_sealed: AtomicU64,
    pub batches_evicted: AtomicU64,
}

/// Front-end handle returned by [`spawn_writer`].
///
/// The pump loop only ever uses [`Self::try_submit`]; [`Self::shutdown`]
/// is called by `main` after the pump exits.
pub struct SpoolHandle {
    sender: SyncSender<Vec<u8>>,
    join: Option<JoinHandle<()>>,
    stats: Arc<SpoolStats>,
}

impl SpoolHandle {
    /// Submit one raw event payload to the writer thread.
    ///
    /// Returns `false` when the channel is full (the writer fell
    /// behind). The pump should NOT block — losing an event is far
    /// better than stalling the kernel queue.
    pub fn try_submit(&self, payload: Vec<u8>) -> bool {
        match self.sender.try_send(payload) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Read-only view onto the running counters.
    pub fn stats(&self) -> &SpoolStats {
        &self.stats
    }

    /// Drop the sender (so the writer sees `RecvError` and exits) and
    /// join the thread. Idempotent in the sense that calling it twice
    /// is a logic bug, not a memory bug — `Option::take` makes the
    /// second call a no-op.
    pub fn shutdown(mut self) {
        // Replace our SyncSender with one that's immediately dropped,
        // so the thread's recv side wakes up. We can't drop `self.sender`
        // by name because it's behind `&mut self` — swap with a fresh
        // closed-channel sender.
        let (dummy, _) = sync_channel::<Vec<u8>>(1);
        let real_sender = std::mem::replace(&mut self.sender, dummy);
        drop(real_sender);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the writer thread and return a handle for the pump.
///
/// On any setup failure (couldn't create the spool dir) the function
/// still returns a handle, but the writer thread exits immediately. The
/// pump will then drop every event — that's fine; it preserves the
/// "agent never crashes for a disk-side problem" contract.
pub fn spawn_writer(config: SpoolConfig) -> SpoolHandle {
    let stats = Arc::new(SpoolStats::default());
    let (sender, receiver) = sync_channel::<Vec<u8>>(config.channel_capacity);

    let stats_for_thread = Arc::clone(&stats);
    let join = thread::Builder::new()
        .name("wedr-spool".into())
        .spawn(move || writer_main(receiver, config, stats_for_thread))
        .expect("failed to spawn spool writer thread");

    SpoolHandle {
        sender,
        join: Some(join),
        stats,
    }
}

/// Writer thread entry point. Owns the active file and rotates it.
fn writer_main(rx: Receiver<Vec<u8>>, cfg: SpoolConfig, stats: Arc<SpoolStats>) {
    if let Err(e) = fs::create_dir_all(&cfg.dir) {
        eprintln!("[spool] failed to create dir {:?}: {}", cfg.dir, e);
        return;
    }

    // Always start fresh: any leftover active.bin from a previous run
    // is considered lost. Recovering it cleanly would require parsing
    // partial framing, which isn't worth the complexity yet.
    let active_path = cfg.dir.join("active.bin");
    let _ = fs::remove_file(&active_path);

    let mut active = match ActiveFile::create(&active_path) {
        Ok(f) => Some(f),
        Err(e) => {
            eprintln!("[spool] cannot create {:?}: {}", active_path, e);
            return;
        }
    };
    let mut active_started_at = Instant::now();

    loop {
        // Wait for the next event OR the time-based rotation deadline,
        // whichever fires first. The agent is mostly idle, so this
        // recv_timeout is what shapes the actual rotation cadence.
        let elapsed = active_started_at.elapsed();
        let timeout = cfg.max_age.saturating_sub(elapsed);

        match rx.recv_timeout(timeout) {
            Ok(payload) => {
                let f = match active.as_mut() {
                    Some(f) => f,
                    None => {
                        // No active file (creation failed earlier);
                        // count the drop and try again on next tick.
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                if let Err(e) = f.write_event(&payload) {
                    eprintln!("[spool] write failed, dropping event: {}", e);
                    stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats.events_written.fetch_add(1, Ordering::Relaxed);

                // Size-based rotation trigger. We let writes through
                // first so a single huge event never gets stuck waiting
                // for a rotation that hasn't happened yet.
                if f.bytes_written() >= cfg.max_bytes_per_file {
                    rotate(&mut active, &cfg, &stats, &active_path);
                    active_started_at = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // Time-based rotation. Skip if the active file only has
                // the header in it (no events) — sealing an empty batch
                // wastes both the rotation cost and the uploader's slot.
                if let Some(f) = active.as_ref() {
                    if f.bytes_written() > crate::spool::file::HEADER_LEN {
                        rotate(&mut active, &cfg, &stats, &active_path);
                    }
                }
                active_started_at = Instant::now();
            }
            Err(RecvTimeoutError::Disconnected) => {
                // Pump has hung up — finalise whatever is in the active
                // file (if non-empty) and exit cleanly.
                if let Some(f) = active.take() {
                    if f.bytes_written() > crate::spool::file::HEADER_LEN {
                        let _ = seal_active_file(f, &cfg, &stats, &active_path);
                    } else {
                        let _ = f.finish();
                        let _ = fs::remove_file(&active_path);
                    }
                }
                return;
            }
        }
    }
}

/// Replace the active file: seal the current one (if any) and open a
/// fresh empty `active.bin`. On error we drop the active file slot —
/// next event arriving will count as dropped, the writer keeps running.
fn rotate(
    active: &mut Option<ActiveFile>,
    cfg: &SpoolConfig,
    stats: &SpoolStats,
    active_path: &Path,
) {
    if let Some(f) = active.take() {
        if let Err(e) = seal_active_file(f, cfg, stats, active_path) {
            eprintln!("[spool] failed to seal batch: {}", e);
            // active_path may or may not still exist depending on where
            // sealing failed. Try to clean up so create() below doesn't
            // append into a partially-sealed file.
            let _ = fs::remove_file(active_path);
        }
    }
    match ActiveFile::create(active_path) {
        Ok(f) => *active = Some(f),
        Err(e) => {
            eprintln!("[spool] cannot reopen active file: {}", e);
            *active = None;
        }
    }
}

/// Seal the (already-flushed) active file: rename → compress → unlink.
///
/// We rename first so concurrent inspection of the spool directory
/// never sees a `batch-*.zst` whose content is still being written.
fn seal_active_file(
    file: ActiveFile,
    cfg: &SpoolConfig,
    stats: &SpoolStats,
    active_path: &Path,
) -> std::io::Result<()> {
    file.finish()?;

    // Pick a unique sealed name. Combining a unix timestamp with a
    // monotonic-ish suffix avoids collisions when multiple rotations
    // happen within the same second (e.g. burst of large events).
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seq = stats.batches_sealed.fetch_add(1, Ordering::Relaxed);
    let staging = cfg.dir.join(format!("batch-{}-{}.bin", ts, seq));
    let final_path = cfg.dir.join(format!("batch-{}-{}.zst", ts, seq));

    fs::rename(active_path, &staging)?;

    // Compress the staged file. We deliberately read from disk rather
    // than from memory: keeping ~1 MiB of bytes in RAM during sealing
    // would double the agent's resident set under bursty load.
    let input = fs::File::open(&staging)?;
    let output = fs::File::create(&final_path)?;
    let mut encoder = zstd::stream::Encoder::new(output, cfg.zstd_level)?;
    let mut reader = std::io::BufReader::new(input);
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    // Drop the uncompressed staging file — keeping it around would
    // double on-disk usage for no benefit (the .zst is the canonical
    // form, the staging file is post-rename of active.bin only because
    // we need a stable name during compression).
    let _ = fs::remove_file(&staging);

    // Now that we've added a new batch, evict old ones if we're over
    // budget. Doing it on every rotation amortises the cost.
    enforce_total_size_cap(cfg, stats);
    Ok(())
}

/// Delete oldest `batch-*.zst` files until total size is under budget.
///
/// "Oldest" = smallest `(timestamp, seq)` filename pair, which is the
/// rotation order. Sorting by mtime would be wrong: clock skew or NTP
/// jumps could reorder things relative to the actual sequence.
fn enforce_total_size_cap(cfg: &SpoolConfig, stats: &SpoolStats) {
    let entries = match fs::read_dir(&cfg.dir) {
        Ok(it) => it,
        Err(_) => return,
    };

    // Collect (filename, size) for sealed batches. We can't compute
    // total size without listing, so might as well do it once.
    let mut batches: Vec<(PathBuf, u64)> = Vec::new();
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };
        if !name.starts_with("batch-") || !name.ends_with(".zst") {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        total += size;
        batches.push((path, size));
    }

    if total <= cfg.max_total_bytes {
        return;
    }

    // Sort lexicographically by filename — works because the `batch-<ts>-<seq>`
    // prefix is monotonic per writer instance. Ascending = oldest first.
    batches.sort_by(|a, b| a.0.cmp(&b.0));

    for (path, size) in batches {
        if total <= cfg.max_total_bytes {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(size);
            stats.batches_evicted.fetch_add(1, Ordering::Relaxed);
        }
    }
}
