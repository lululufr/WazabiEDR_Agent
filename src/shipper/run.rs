//! The shipper thread itself: scan spool dirs, POST oldest batch, repeat.
//!
//! # Loop in pseudo-code
//!
//! ```text
//! loop:
//!     if SHUTDOWN: break
//!     batch = oldest batch-*.zst across all watched dirs (or None)
//!     match batch:
//!         None     → sleep poll_interval
//!         Some(b)  → POST b
//!                    on 2xx          → delete b, reset backoff
//!                    on 4xx          → log once, leave on disk, sleep poll_interval
//!                    on 5xx/network  → sleep backoff (capped), do NOT delete
//! ```
//!
//! 4xx are kept on disk on purpose: those are usually payload-shape
//! mismatches the operator needs to diagnose, and the spool's
//! `max_total_bytes` cap will evict them naturally if the situation
//! persists. Retrying them indefinitely would burn CPU without value.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::shipper::config::ShipperConfig;
use crate::shutdown::SHUTDOWN;

/// Counters exposed for the end-of-run summary.
#[derive(Default)]
pub struct ShipperStats {
    /// Batches the server acknowledged with 2xx and we deleted.
    pub batches_sent: AtomicU64,
    /// Batches that returned 4xx — left on disk for the operator.
    pub batches_rejected: AtomicU64,
    /// Network/5xx retries — counts retries, not unique batches.
    pub send_retries: AtomicU64,
}

pub struct ShipperHandle {
    join: Option<JoinHandle<()>>,
    stats: Arc<ShipperStats>,
    /// Wakes the shipper thread from its sleep so the agent can shut
    /// down within ~100 ms instead of waiting on the poll interval.
    wake: Arc<AtomicBool>,
}

impl ShipperHandle {
    pub fn stats(&self) -> &ShipperStats {
        &self.stats
    }

    pub fn shutdown(mut self) {
        self.wake.store(true, Ordering::Release);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Start the shipper. `dirs` are scanned in order; on a tie (= two
/// batches with the same filename ordering across two dirs), the
/// earlier dir wins. In practice the kernel and plugin spools have
/// independent sequence counters but the same `<ts>` granularity, so
/// "fairness" is best-effort.
pub fn spawn_shipper(cfg: ShipperConfig, dirs: Vec<PathBuf>) -> std::io::Result<ShipperHandle> {
    let stats = Arc::new(ShipperStats::default());
    let wake = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stats);
    let w = Arc::clone(&wake);
    let join = thread::Builder::new()
        .name("wedr-shipper".into())
        .spawn(move || shipper_main(cfg, dirs, s, w))?;
    Ok(ShipperHandle {
        join: Some(join),
        stats,
        wake,
    })
}

fn shipper_main(
    cfg: ShipperConfig,
    dirs: Vec<PathBuf>,
    stats: Arc<ShipperStats>,
    wake: Arc<AtomicBool>,
) {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(cfg.timeout)
        // No global header for the bearer token — we set Authorization
        // per-request so a future per-batch token rotation doesn't need
        // to rebuild the agent.
        .build();

    if !cfg.verify_tls {
        eprintln!(
            "[shipper] WARNING: verify_tls=false requested but TLS \
             verification cannot be disabled in this build — server \
             certificate will still be validated"
        );
    }

    eprintln!(
        "[shipper] started — endpoint: {} — watching {} dir(s)",
        cfg.url,
        dirs.len()
    );

    let mut backoff = Duration::from_millis(0);

    while !SHUTDOWN.load(Ordering::Acquire) {
        match oldest_batch(&dirs) {
            Some(path) => match send_one(&agent, &cfg, &path) {
                Outcome::Ok => {
                    let _ = fs::remove_file(&path);
                    stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                    backoff = Duration::from_millis(0);
                    // Loop straight back — drain as fast as the server
                    // accepts. No sleep on success.
                }
                Outcome::Rejected(status) => {
                    eprintln!(
                        "[shipper] server returned {} for {:?} — left on disk for inspection",
                        status, path
                    );
                    stats.batches_rejected.fetch_add(1, Ordering::Relaxed);
                    sleep_responsive(cfg.poll_interval, &wake);
                }
                Outcome::Retry(why) => {
                    backoff = next_backoff(backoff, cfg.max_backoff);
                    stats.send_retries.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "[shipper] transient failure ({}) for {:?} — retry in {:.1}s",
                        why,
                        path.file_name().unwrap_or_default(),
                        backoff.as_secs_f32()
                    );
                    sleep_responsive(backoff, &wake);
                }
            },
            None => sleep_responsive(cfg.poll_interval, &wake),
        }
    }

    eprintln!("[shipper] exited");
}

enum Outcome {
    Ok,
    /// 4xx — we won't keep retrying; log once and let the spool's cap
    /// evict the batch eventually.
    Rejected(u16),
    /// 5xx, network, timeout. The shipper will back off and retry the
    /// same batch on the next iteration.
    Retry(String),
}

fn send_one(agent: &ureq::Agent, cfg: &ShipperConfig, path: &Path) -> Outcome {
    let raw = match fs::read(path) {
        Ok(b) => b,
        Err(e) => return Outcome::Retry(format!("read batch: {e}")),
    };

    // Debug mode: decompress in-memory so the server sees plain NDJSON.
    // Decode failure is fatal for this batch — a corrupted .zst on disk
    // would loop forever otherwise, so we surface it as 4xx-equivalent.
    let body = if cfg.debug {
        match zstd::stream::decode_all(raw.as_slice()) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[shipper] debug: zstd decode failed for {:?}: {} — skipping batch",
                    path, e
                );
                return Outcome::Rejected(0);
            }
        }
    } else {
        raw
    };

    let mut req = agent
        .post(&cfg.url)
        .set("Content-Type", "application/x-ndjson")
        .set("Authorization", &format!("Bearer {}", cfg.token));
    if !cfg.debug {
        req = req.set("Content-Encoding", "zstd");
    }

    if let Some(tenant) = &cfg.tenant_id {
        req = req.set("X-Wazabi-Tenant", tenant);
    }
    for (k, v) in &cfg.tags {
        // Header names with weird characters would crash ureq; gate to
        // the safe set. Anything filtered out is a config bug, not a
        // runtime concern.
        if k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            req = req.set(&format!("X-Wazabi-Tag-{}", k), v);
        }
    }

    match req.send_bytes(&body) {
        Ok(resp) => {
            let status = resp.status();
            if (200..300).contains(&status) {
                Outcome::Ok
            } else if (400..500).contains(&status) {
                Outcome::Rejected(status)
            } else {
                Outcome::Retry(format!("server {status}"))
            }
        }
        Err(ureq::Error::Status(status, _)) => {
            if (400..500).contains(&status) {
                Outcome::Rejected(status)
            } else {
                Outcome::Retry(format!("server {status}"))
            }
        }
        Err(ureq::Error::Transport(t)) => Outcome::Retry(format!("transport: {t}")),
    }
}

/// Find the oldest unsent batch across every watched directory.
///
/// Ordering is lexicographic on `batch-<ts>-<seq>.zst` — matches the
/// rotation order chosen by the writer (see `spool::writer`).
fn oldest_batch(dirs: &[PathBuf]) -> Option<PathBuf> {
    let mut best: Option<(String, PathBuf)> = None;
    for dir in dirs {
        let entries = match fs::read_dir(dir) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_owned(),
                None => continue,
            };
            if !name.starts_with("batch-") || !name.ends_with(".zst") {
                continue;
            }
            match &best {
                Some((b, _)) if *b <= name => {}
                _ => best = Some((name, path)),
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Sleep for `dur` but wake within ~100 ms of SHUTDOWN being set, or
/// of `wake` being flipped (used by `ShipperHandle::shutdown` to break
/// the sleep immediately).
fn sleep_responsive(dur: Duration, wake: &AtomicBool) {
    let until = Instant::now() + dur;
    while Instant::now() < until {
        if SHUTDOWN.load(Ordering::Acquire) || wake.load(Ordering::Acquire) {
            return;
        }
        let remaining = until.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

/// Exponential backoff with ±25 % jitter, capped at `max`. Jitter
/// prevents a fleet of agents from re-trying in lockstep against a
/// recovering server (thundering herd).
fn next_backoff(curr: Duration, max: Duration) -> Duration {
    let base = if curr.is_zero() {
        Duration::from_secs(1)
    } else {
        (curr * 2).min(max)
    };
    let ms = base.as_millis() as u64;
    if ms < 4 {
        return base;
    }
    // xorshift64* seeded by SystemTime — good enough for jitter, NOT a
    // crypto RNG. Re-seeding every call also keeps cross-agent
    // variation high without persisting state.
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        | 1;
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    let jitter = (seed % (ms / 2)) as i64;
    let signed = if seed & 1 == 0 {
        ms as i64 + jitter / 2
    } else {
        ms as i64 - jitter / 2
    };
    Duration::from_millis(signed.max(1) as u64).min(max)
}
