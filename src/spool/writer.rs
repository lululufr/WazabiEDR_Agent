//! Background writer thread.
//!
//! The pump (kernel or plugin) hands an already-serialised NDJSON line
//! to [`SpoolHandle::try_submit`]; this thread is the one that touches
//! the disk. The pump never blocks on I/O — `try_submit` is non-blocking
//! and accounts dropped events on a full channel.
//!
//! # Pipeline
//!
//! ```text
//!  caller → mpsc::sync_channel(N) → writer thread
//!                                     → active.ndjson  →  batch-<ts>-<seq>.zst
//! ```
//!
//! # Rotation
//!
//! The active file is sealed when *either* trigger fires:
//! - it reached `max_bytes` (default 1 MiB), or
//! - it is older than `max_age` (default 10 s).
//!
//! Time-based rotation matters because a quiet endpoint would otherwise
//! never seal a batch — the shipper would have nothing to send.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::spool::file::ActiveFile;

/// Shortest `recv_timeout` we'll ever wait. Without this, a `max_age`
/// elapsed-saturating-sub computation can collapse to 0 and the writer
/// busy-loops at full CPU until the next rotation. 100 ms is small
/// enough to be invisible to humans and large enough to leave the
/// scheduler alone.
const MIN_RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// File name we use for the in-flight active file. `.ndjson` makes the
/// content obvious to a human walking the spool directory.
const ACTIVE_FILE_NAME: &str = "active.ndjson";

/// Tunables for the spool subsystem.
#[derive(Clone, Debug)]
pub struct SpoolConfig {
    /// Directory where `active.ndjson` and `batch-*.zst` live.
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
    /// Bounded channel capacity. Once full, the producer drops events
    /// (recorded under `events_dropped`).
    pub channel_capacity: usize,
    /// zstd compression level — 1 (fast) to 22 (slow). Level 3 is the
    /// default trade-off and matches what most production logging
    /// pipelines use.
    pub zstd_level: i32,
}

/// Counters published by the writer thread. `events_dropped` is bumped
/// both from `try_submit` (channel full) and from inside the writer
/// (write error) — both mean "an event we wanted is gone."
#[derive(Default)]
pub struct SpoolStats {
    pub events_written: AtomicU64,
    pub events_dropped: AtomicU64,
    pub batches_sealed: AtomicU64,
    pub batches_evicted: AtomicU64,
}

/// Front-end handle returned by [`spawn_writer`].
pub struct SpoolHandle {
    sender: SyncSender<Arc<[u8]>>,
    join: Option<JoinHandle<()>>,
    stats: Arc<SpoolStats>,
    /// `true` while the writer thread is running. Flips to `false` if
    /// the thread exits early (failed setup, fatal write error). The
    /// caller checks it to surface the issue exactly once.
    alive: Arc<AtomicBool>,
}

impl SpoolHandle {
    /// Submit one NDJSON line (must already contain the trailing `\n`).
    ///
    /// Non-blocking. Returns `false` when the channel is full so the
    /// caller can update its own counter if it cares about the
    /// kernel-side vs. agent-side breakdown.
    pub fn try_submit(&self, line: Arc<[u8]>) -> bool {
        match self.sender.try_send(line) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn stats(&self) -> &SpoolStats {
        &self.stats
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub fn shutdown(mut self) {
        let (dummy, _) = sync_channel::<Arc<[u8]>>(1);
        let real_sender = std::mem::replace(&mut self.sender, dummy);
        drop(real_sender);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }

    /// Cheap, cloneable producer end. Hand this to threads that only
    /// need to submit (the plugin workers do — they don't own the
    /// writer thread's lifecycle).
    pub fn submitter(&self) -> SpoolSubmitter {
        SpoolSubmitter {
            sender: self.sender.clone(),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Clone-friendly view onto a [`SpoolHandle`] for code that only needs
/// to push events. Holding a `SpoolSubmitter` does NOT keep the writer
/// thread alive — `shutdown()` on the parent handle still drops the
/// real sender and lets the thread exit cleanly.
#[derive(Clone)]
pub struct SpoolSubmitter {
    sender: SyncSender<Arc<[u8]>>,
    stats: Arc<SpoolStats>,
}

impl SpoolSubmitter {
    pub fn try_submit(&self, line: Arc<[u8]>) -> bool {
        match self.sender.try_send(line) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Spawn the writer thread and return a handle. Multiple spools can run
/// side by side as long as their `dir` is distinct (the kernel and
/// plugin spools take advantage of this).
pub fn spawn_writer(config: SpoolConfig) -> io::Result<SpoolHandle> {
    let stats = Arc::new(SpoolStats::default());
    let alive = Arc::new(AtomicBool::new(true));
    let (sender, receiver) = sync_channel::<Arc<[u8]>>(config.channel_capacity);

    let stats_for_thread = Arc::clone(&stats);
    let alive_for_thread = Arc::clone(&alive);
    // Thread name carries the basename of the dir so two concurrent
    // spools are distinguishable in a debugger / `Get-Process` view.
    let dir_tag = config
        .dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("spool")
        .to_string();
    let thread_name = format!("wedr-spool-{}", dir_tag);
    let join = thread::Builder::new().name(thread_name).spawn(move || {
        writer_main(receiver, config, stats_for_thread);
        alive_for_thread.store(false, Ordering::Release);
    })?;

    Ok(SpoolHandle {
        sender,
        join: Some(join),
        stats,
        alive,
    })
}

fn writer_main(rx: Receiver<Arc<[u8]>>, cfg: SpoolConfig, stats: Arc<SpoolStats>) {
    if let Err(e) = fs::create_dir_all(&cfg.dir) {
        eprintln!("[spool] failed to create dir {:?}: {}", cfg.dir, e);
        return;
    }

    // Always start fresh: any leftover active file is considered lost.
    // Recovering partial NDJSON cleanly would mean parsing the tail to
    // find the last newline — easy, but the durability contract is
    // "agent crash loses a few seconds" so we don't bother.
    let active_path = cfg.dir.join(ACTIVE_FILE_NAME);
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
        let elapsed = active_started_at.elapsed();
        let timeout = cfg.max_age.saturating_sub(elapsed).max(MIN_RECV_TIMEOUT);

        match rx.recv_timeout(timeout) {
            Ok(line) => {
                let f = match active.as_mut() {
                    Some(f) => f,
                    None => {
                        stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                if let Err(e) = f.write_line(&line) {
                    eprintln!("[spool] write failed, dropping event: {}", e);
                    stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats.events_written.fetch_add(1, Ordering::Relaxed);

                if f.bytes_written() >= cfg.max_bytes_per_file {
                    rotate(&mut active, &cfg, &stats, &active_path);
                    active_started_at = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // Skip rotation when the active file is empty — sealing
                // an empty batch wastes both the rotation cost and the
                // shipper's bandwidth.
                if let Some(f) = active.as_ref() {
                    if f.bytes_written() > 0 {
                        rotate(&mut active, &cfg, &stats, &active_path);
                    }
                }
                active_started_at = Instant::now();
            }
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(f) = active.take() {
                    if f.bytes_written() > 0 {
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

fn rotate(
    active: &mut Option<ActiveFile>,
    cfg: &SpoolConfig,
    stats: &SpoolStats,
    active_path: &Path,
) {
    if let Some(f) = active.take() {
        if let Err(e) = seal_active_file(f, cfg, stats, active_path) {
            eprintln!("[spool] failed to seal batch: {}", e);
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

/// Seal the active file: rename → compress → unlink staging.
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

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seq = stats.batches_sealed.fetch_add(1, Ordering::Relaxed);
    let staging = cfg.dir.join(format!("batch-{}-{}.ndjson", ts, seq));
    let final_path = cfg.dir.join(format!("batch-{}-{}.zst", ts, seq));

    fs::rename(active_path, &staging)?;

    let input = fs::File::open(&staging)?;
    let output = fs::File::create(&final_path)?;
    let mut encoder = zstd::stream::Encoder::new(output, cfg.zstd_level)?;
    let mut reader = std::io::BufReader::new(input);
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    let _ = fs::remove_file(&staging);

    enforce_total_size_cap(cfg, stats);
    Ok(())
}

/// Delete oldest `batch-*.zst` files until total size is under budget.
///
/// "Oldest" = smallest `(timestamp, seq)` filename pair, which IS the
/// rotation order. Sorting by mtime would be wrong: clock skew or NTP
/// jumps could reorder things relative to the actual sequence.
fn enforce_total_size_cap(cfg: &SpoolConfig, stats: &SpoolStats) {
    let entries = match fs::read_dir(&cfg.dir) {
        Ok(it) => it,
        Err(_) => return,
    };

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
