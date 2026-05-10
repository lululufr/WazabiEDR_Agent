//! WazabiEDR userland agent.
//!
//! Connects to the kernel driver and:
//! 1. prints incoming events to stdout (interactive use), and
//! 2. persists them to a local on-disk spool (`./spool/` by default) as
//!    length-prefixed records, sealed periodically into zstd-compressed
//!    batches ready to be uploaded by a future control-plane component.
//!
//! # Architecture
//!
//! ```text
//!   driver ─IOCTL──> pump thread (main) ─┬─> stdout (parse_and_print)
//!                                        └─> spool::SpoolHandle (channel)
//!                                                    │
//!                                                    ▼
//!                                            wedr-spool thread
//!                                                    │
//!                                                    ▼
//!                                  active.bin  →  batch-<ts>-<seq>.zst
//! ```
//!
//! The spool channel is bounded; if disk I/O can't keep up the pump
//! drops the event rather than blocking. Both kinds of drops (kernel
//! ring full vs. agent channel full) are visible separately so we can
//! tell who is the bottleneck.
//!
//! # Module map
//!
//! - [`config`]   — env + CLI parsing into [`config::AgentConfig`]
//! - [`ipc`]      — wire format, device open/close, pump loop, parser
//! - [`plugin`]   — plugin telemetry server (named pipe, manifest, identity)
//! - [`shutdown`] — Ctrl+C flag and handler
//! - [`spool`]    — on-disk write-ahead log of raw events
//! - [`util`]     — UTF-16 conversion + FILETIME formatting

mod config;
mod ipc;
mod plugin;
mod shutdown;
mod spool;
mod util;

use std::io::{self, Write};
use std::sync::atomic::Ordering;

use crate::config::AgentConfig;
use crate::ipc::device::{close_device, open_device, run_pump_loop};
use crate::spool::{SpoolConfig, spawn_writer};

fn main() -> io::Result<()> {
    shutdown::install();

    // Resolve config first so a `--help` / unknown-flag / bad-env case
    // exits before we touch the driver.
    let cfg = match AgentConfig::from_env_and_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[agent] config error: {e}");
            std::process::exit(2);
        }
    };

    let handle = open_device()?;

    // Spin up the spool writer first so the pump can start submitting
    // immediately. Setup failures *inside* the thread (cannot create
    // the dir, etc.) are reported via `SpoolHandle::is_alive()` — we
    // don't fail-fast here, the agent stays useful for stdout.
    let spool_cfg = SpoolConfig {
        dir: cfg.spool_dir.clone(),
        max_bytes_per_file: cfg.max_bytes_per_file,
        max_age: cfg.max_age,
        max_total_bytes: cfg.max_total_bytes,
        channel_capacity: cfg.channel_capacity,
        zstd_level: cfg.zstd_level,
    };
    let spool = match spawn_writer(spool_cfg) {
        Ok(s) => s,
        Err(e) => {
            // OS refused to spawn the writer thread (basically OOM).
            // Close the device so we don't leak the handle and return.
            eprintln!("[agent] cannot spawn spool writer: {e}");
            close_device(handle);
            return Err(e);
        }
    };

    // Spin up the plugin server. Failure to bind the pipe is logged
    // but doesn't fail-fast: kernel-event ingest is the agent's primary
    // job and we want it running even if plugin telemetry is broken.
    let plugin_dir = plugin::manifest::default_dir();
    let plugin_server = match plugin::spawn_server(plugin_dir.clone()) {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!(
                "[agent] plugin server failed to start: {} — \
                 plugin telemetry disabled this run",
                e
            );
            None
        }
    };

    // Auto-launch any plugin whose manifest opted in via `auto_launch:
    // true`. Spawned only AFTER the server above so the named pipe
    // exists by the time the children try to connect — they'd backoff
    // and retry anyway, but skipping the first failure makes startup
    // logs cleaner. If the plugin server failed to start, we skip the
    // supervisor entirely (children would just connect-loop forever).
    let plugin_supervisor = if plugin_server.is_some() {
        Some(plugin::spawn_supervisor(plugin_dir.clone()))
    } else {
        None
    };

    println!(
        "[agent] connected to \\\\.\\WazabiEDR (Ctrl+C to stop) — spool dir: {} — \
         plugins dir: {}",
        cfg.spool_dir.display(),
        plugin_dir.display()
    );
    io::stdout().flush().ok();

    run_pump_loop(handle, Some(&spool));

    close_device(handle);

    // Children opted into auto-launch are still running; the
    // supervisor's per-plugin threads notice SHUTDOWN, give children a
    // 5 s grace period to react to the broadcast Ctrl+C, and force-kill
    // anything still alive. Joining here blocks main() until every
    // supervisor thread has exited, so the agent process doesn't leave
    // stale plugin processes behind.
    if let Some(s) = plugin_supervisor {
        let count = s.spawned_count();
        s.shutdown();
        if count > 0 {
            println!("[agent] supervisor stopped — {} auto-launched plugin(s) joined", count);
        }
    }

    if let Some(p) = plugin_server {
        let ps = p.stats();
        let accepted = ps.sessions_accepted.load(Ordering::Relaxed);
        let rejected = ps.sessions_rejected.load(Ordering::Relaxed);
        let received = ps.events_received.load(Ordering::Relaxed);
        let invalid = ps.events_invalid.load(Ordering::Relaxed);
        let reloads = ps.manifest_reloads.load(Ordering::Relaxed);
        let active = p.active_sessions();
        p.shutdown();
        println!(
            "[agent] plugin server stats — accepted: {}, rejected: {}, \
             events: {} ({} invalid), reloads: {}, still-active: {}",
            accepted, rejected, received, invalid, reloads, active
        );
    }

    // Read the counters BEFORE shutdown so we don't move-or-borrow
    // dance with the handle. They're behind Arcs anyway.
    let s = spool.stats();
    let written = s.events_written.load(Ordering::Relaxed);
    let dropped = s.events_dropped.load(Ordering::Relaxed);
    let sealed = s.batches_sealed.load(Ordering::Relaxed);
    let evicted = s.batches_evicted.load(Ordering::Relaxed);

    spool.shutdown();
    println!(
        "[agent] disconnected — spool: {} events written, {} dropped, \
         {} batches sealed, {} evicted",
        written, dropped, sealed, evicted
    );
    Ok(())
}
