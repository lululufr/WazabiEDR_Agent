//! Plugin supervisor: spawns auto-launch plugins at agent startup and
//! restarts them on crash with exponential backoff.
//!
//! ## What gets launched
//!
//! Every manifest in the manifest store with `auto_launch: true` and
//! `revoked: false`. Other plugins (operator-managed services, on-demand
//! tools) are unaffected — they keep connecting on their own. The flag
//! is purely opt-in.
//!
//! ## Lifecycle
//!
//! ```text
//!     supervisor thread per plugin
//!         │
//!         ▼
//!     spawn `expected_path` with WEDR_PLUGIN_ID=<uuid>
//!         │
//!         ▼
//!     poll child every 250 ms (try_wait + SHUTDOWN check)
//!         │
//!     ┌───┴────────────────────────────────────────────────┐
//!     │ SHUTDOWN set                       │ child exited  │
//!     ▼                                    ▼               │
//!  wait ≤ 5 s for graceful exit       compute backoff      │
//!  (children share our console, so    (1s → 2s → 4s …      │
//!  Ctrl+C is broadcast and they       cap 60s; reset to 1s │
//!  should exit on their own)          if alive ≥ 5 min)    │
//!     │                                    │               │
//!     ▼                                    └──────► loop ──┘
//!  if still alive: TerminateProcess
//! ```
//!
//! ## Privilege note
//!
//! Children inherit the agent's token. Today the agent typically runs
//! as Administrator (driver access + manifest dir read), so plugins
//! also run elevated. That's a privilege concern documented in
//! `WazabiEDR_Doc/architecture/plugin-supervisor.md`. Future:
//! per-plugin restricted token / specific user.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use crate::plugin::manifest::{ManifestStore, PluginManifest};
use crate::shutdown::SHUTDOWN;

/// Maximum delay between restart attempts. Prevents a permanently
/// broken plugin from spamming Spawn / log lines forever — once the
/// backoff hits this, retries happen at most once a minute.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Initial delay for the first restart attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// "The plugin lasted long enough to count as healthy" threshold. If
/// a child stays alive for at least this long, the next crash starts
/// the backoff from scratch instead of continuing the exponential
/// sequence — gives transient failures (a bad downstream, a one-off
/// network blip) room to recover without permanently penalising the
/// plugin's restart cadence.
const STABLE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Grace period given to children to react to a Ctrl+C that the
/// console layer broadcast to the process group. Past this, we
/// `TerminateProcess` so a misbehaving plugin cannot stall agent
/// shutdown indefinitely.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Returned to the caller. Holds the supervisor threads so shutdown
/// can join them — losing this handle (drop-without-join) leaks the
/// threads but doesn't crash anything; the OS reaps them at process
/// exit.
pub struct SupervisorHandle {
    threads: Vec<thread::JoinHandle<()>>,
    spawned_count: usize,
}

impl SupervisorHandle {
    /// Number of plugins the supervisor decided to spawn at startup.
    /// Useful for the agent's startup banner.
    pub fn spawned_count(&self) -> usize {
        self.spawned_count
    }

    /// Wait for every supervisor thread to exit. Each thread observes
    /// `SHUTDOWN` and stops on its own; this just blocks until they're
    /// all gone. Safe to call without `SHUTDOWN` being set, in which
    /// case it blocks forever — only call after the shutdown signal
    /// has been posted.
    pub fn shutdown(self) {
        for h in self.threads {
            let _ = h.join();
        }
    }
}

/// Read the manifest dir, find every `auto_launch: true` plugin, and
/// spawn one supervisor thread per match.
///
/// Failure to load the manifest dir doesn't fail-fast — same policy as
/// the rest of the plugin subsystem. We log + return an empty handle.
pub fn spawn_supervisor(manifest_dir: PathBuf) -> SupervisorHandle {
    let store = match ManifestStore::load_dir(&manifest_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[supervisor] cannot read manifest dir {:?}: {} — \
                 no plugins will be auto-launched this run",
                manifest_dir, e
            );
            return SupervisorHandle {
                threads: Vec::new(),
                spawned_count: 0,
            };
        }
    };

    let candidates: Vec<PluginManifest> = store
        .iter()
        .filter(|m| m.auto_launch && !m.revoked)
        .cloned()
        .collect();

    if candidates.is_empty() {
        return SupervisorHandle {
            threads: Vec::new(),
            spawned_count: 0,
        };
    }

    let mut threads = Vec::with_capacity(candidates.len());
    for manifest in &candidates {
        // One thread per plugin so a slow/blocked respawn on one
        // plugin doesn't delay the others. Threads are cheap; we cap
        // implicitly because the manifest store is small (operators
        // don't enrol thousands of plugins).
        let thread_name = format!("wedr-supervisor-{}", short_id(&manifest.plugin_id));
        let m = manifest.clone();
        let h = thread::Builder::new()
            .name(thread_name)
            .spawn(move || supervise_one(m))
            .expect("OS refused to spawn supervisor thread");
        threads.push(h);
    }

    eprintln!("[supervisor] auto-launched {} plugin(s)", candidates.len());
    SupervisorHandle {
        threads,
        spawned_count: candidates.len(),
    }
}

/// Single-plugin supervisor loop: spawn → wait → backoff → repeat,
/// until `SHUTDOWN` flips.
fn supervise_one(manifest: PluginManifest) {
    let label = format!("{} ({})", manifest.name, short_id(&manifest.plugin_id));
    let mut backoff = INITIAL_BACKOFF;

    while !SHUTDOWN.load(Ordering::Acquire) {
        // ---- spawn ----
        let mut child = match Command::new(&manifest.expected_path)
            .env("WEDR_PLUGIN_ID", &manifest.plugin_id)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[supervisor] {} — spawn failed: {} — retrying in {:?}",
                    label, e, backoff
                );
                if !sleep_with_shutdown(backoff) {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };

        let pid = child.id();
        let started = Instant::now();
        eprintln!("[supervisor] {} — launched pid={}", label, pid);

        // ---- wait ----
        let exit_status = wait_for_exit(&mut child);

        let alive = started.elapsed();
        eprintln!(
            "[supervisor] {} — pid={} exited after {:.1}s, status={:?}",
            label,
            pid,
            alive.as_secs_f32(),
            exit_status,
        );

        // Shutdown observed during wait → no restart, just stop.
        if SHUTDOWN.load(Ordering::Acquire) {
            return;
        }

        // Healthy run resets the backoff so a one-off crash years
        // into the agent's lifetime doesn't get penalised by a stale
        // exponential.
        if alive >= STABLE_THRESHOLD {
            backoff = INITIAL_BACKOFF;
        }

        eprintln!("[supervisor] {} — restarting in {:?}", label, backoff);
        if !sleep_with_shutdown(backoff) {
            return;
        }
        backoff = next_backoff(backoff);
    }
}

/// Block until either the child exits, or `SHUTDOWN` flips. On
/// shutdown, give the child a grace period to exit on its own (the
/// console-control event broadcast already told it to), then
/// `TerminateProcess` if it hasn't.
fn wait_for_exit(child: &mut Child) -> Option<std::process::ExitStatus> {
    let poll = Duration::from_millis(250);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(e) => {
                eprintln!("[supervisor] try_wait failed: {} — abandoning child", e);
                return None;
            }
        }

        if SHUTDOWN.load(Ordering::Acquire) {
            // Shared console means Ctrl+C already reached the child;
            // give it 5 s to clean up before forcing.
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline {
                if let Ok(Some(s)) = child.try_wait() {
                    return Some(s);
                }
                thread::sleep(poll);
            }
            // Past grace: force. `kill` swallows ESRCH-like errors
            // (already exited), so the worst case is a redundant call.
            let _ = child.kill();
            return child.wait().ok();
        }

        thread::sleep(poll);
    }
}

/// Sleep `dur`, slicing on `SHUTDOWN` so backoffs don't keep an
/// agent alive for up to 60 s after Ctrl+C. Returns `false` if
/// shutdown fired during the sleep — caller should bail out.
fn sleep_with_shutdown(dur: Duration) -> bool {
    let slice = Duration::from_millis(250);
    let mut left = dur;
    while left > Duration::ZERO {
        if SHUTDOWN.load(Ordering::Acquire) {
            return false;
        }
        let chunk = std::cmp::min(slice, left);
        thread::sleep(chunk);
        left = left.saturating_sub(chunk);
    }
    !SHUTDOWN.load(Ordering::Acquire)
}

/// `1s → 2s → 4s → 8s → 16s → 32s → 60s (cap)`.
fn next_backoff(prev: Duration) -> Duration {
    let next = prev.saturating_mul(2);
    if next > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        next
    }
}

/// First 8 hex chars of the plugin_id — keeps log lines readable while
/// staying disambiguated for any realistic enrollment.
fn short_id(id: &str) -> &str {
    if id.len() > 8 { &id[..8] } else { id }
}
