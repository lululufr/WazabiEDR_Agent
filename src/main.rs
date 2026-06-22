//! WazabiEDR userland agent.
//!
//! Connects to the kernel driver and:
//! 1. optionally prints incoming events to stdout (`agent.console_output`),
//! 2. persists them as NDJSON to a local on-disk spool (`<spool_dir>/`
//!    for kernel events, `<spool_dir>/plugins/` for plugin events), and
//! 3. uploads sealed batches to a remote log server when the
//!    `shipper` section of `agent.json` is configured.
//!
//! All tunables live in `%ProgramData%\WazabiEDR\agent.json` —
//! see [`config`].
//!
//! # Architecture
//!
//! ```text
//!   driver ─IOCTL──> pump thread (main) ─┬─> stdout (parse_and_print)  ◀ console_output
//!                                        └─> ipc::json → SpoolHandle (kernel)
//!                                                          │
//!   plugin pipe ──> per-session workers  ─┬─> stdout       │  ◀ console_output
//!                                         └─> SpoolHandle (plugins)
//!                                                          │
//!                                                          ▼
//!                                            active.ndjson → batch-*.zst
//!                                                          │
//!                                                          ▼
//!                                            wedr-shipper thread
//!                                                          │
//!                                                          ▼
//!                                            HTTPS POST → log server
//! ```

mod config;
mod detection;
mod filter;
mod ipc;
mod plugin;
mod shipper;
mod shutdown;
mod spool;
mod util;

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::config::{AppConfig, print_help_and_exit};
use crate::ipc::device::{close_device, open_device, run_pump_loop};
use crate::shipper::spawn_shipper;
use crate::spool::{SpoolConfig, spawn_writer};

/// Subdirectory under the spool root where plugin-event batches live.
/// Kept distinct from kernel batches so an operator inspecting the
/// directory immediately sees which source produced what.
const PLUGIN_SPOOL_SUBDIR: &str = "plugins";

fn main() -> io::Result<()> {
    shutdown::install();

    // The agent takes no CLI flags. Any argument is treated as a
    // request for the help message — typing `--help`, `-h`, or just
    // bumping into the binary with `WazabiEDR_Agent foo` all point
    // the operator at the config file. Refusing-with-help is friendlier
    // than refusing-silently.
    if std::env::args().nth(1).is_some() {
        print_help_and_exit();
    }

    let cfg = match AppConfig::load(&config::default_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[agent] config error: {e}");
            std::process::exit(2);
        }
    };

    // Init du filtre AVANT toute consommation d'events : OnceLock global
    // → toujours initialisé quand le pump thread démarre.
    filter::init(cfg.filter.clone());

    let handle = open_device()?;

    let console_output = cfg.agent.console_output;

    // Waza detection layer. Opt-in via the `detection` config section.
    // A load failure (bad rules file) disables detection but is NOT fatal
    // — the agent keeps ingesting/shipping exactly as before. When loaded,
    // a background thread hot-reloads the rules file on change.
    let (detection, detection_reload) = match cfg.detection.as_ref() {
        Some(d) => match detection::DetectionEngine::load(
            &d.rules_path,
            d.schema_path.as_deref(),
            d.default_window,
        ) {
            Ok(engine) => {
                let engine = Arc::new(engine);
                let reload = detection::spawn_reload(Arc::clone(&engine), d.reload_interval);
                (Some(engine), reload)
            }
            Err(e) => {
                eprintln!("[waza] detection disabled — failed to load rules: {e}");
                (None, None)
            }
        },
        None => {
            eprintln!("[waza] detection disabled (no [detection] config section)");
            (None, None)
        }
    };

    // Kernel-event spool. Spawned first so the pump can start
    // submitting immediately.
    let spool_cfg = SpoolConfig {
        dir: cfg.agent.spool_dir.clone(),
        max_bytes_per_file: cfg.agent.max_bytes_per_file,
        max_age: cfg.agent.max_age,
        max_total_bytes: cfg.agent.max_total_bytes,
        channel_capacity: cfg.agent.channel_capacity,
        zstd_level: cfg.agent.zstd_level,
    };
    let kernel_spool = match spawn_writer(spool_cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[agent] cannot spawn kernel spool writer: {e}");
            close_device(handle);
            return Err(e);
        }
    };

    // Plugin-event spool. Same tunables as the kernel spool for v1:
    // operators that want them tuned independently can split the knobs
    // later. Failures here are non-fatal — kernel ingest is the more
    // valuable path, plugin telemetry can run with stdout-only fallback.
    let plugin_spool_dir = cfg.agent.spool_dir.join(PLUGIN_SPOOL_SUBDIR);
    let plugin_spool_cfg = SpoolConfig {
        dir: plugin_spool_dir.clone(),
        max_bytes_per_file: cfg.agent.max_bytes_per_file,
        max_age: cfg.agent.max_age,
        max_total_bytes: cfg.agent.max_total_bytes,
        channel_capacity: cfg.agent.channel_capacity,
        zstd_level: cfg.agent.zstd_level,
    };
    let plugin_spool = match spawn_writer(plugin_spool_cfg) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!(
                "[agent] cannot spawn plugin spool writer: {e} — \
                 plugin events will only go to stdout"
            );
            None
        }
    };

    // Plugin server. Hooked into the plugin spool if it came up.
    let plugin_dir = plugin::manifest::default_dir();
    let plugin_submitter = plugin_spool.as_ref().map(|s| s.submitter());
    let plugin_server =
        match plugin::spawn_server(plugin_dir.clone(), plugin_submitter, detection.clone(), console_output) {
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

    let plugin_supervisor = if plugin_server.is_some() {
        Some(plugin::spawn_supervisor(plugin_dir.clone()))
    } else {
        None
    };

    // Shipper. Optional: if `agent.json` has no `shipper` section (or
    // disables it), the agent runs in spool-only mode — operators can
    // pick batches off disk manually.
    let shipper_handle = match cfg.shipper {
        Some(sc) => {
            let dirs = vec![cfg.agent.spool_dir.clone(), plugin_spool_dir.clone()];
            match spawn_shipper(sc, dirs) {
                Ok(h) => Some(h),
                Err(e) => {
                    eprintln!("[agent] shipper failed to spawn: {e}");
                    None
                }
            }
        }
        None => {
            eprintln!("[agent] no shipper configured — events stay on disk only");
            None
        }
    };

    eprintln!(
        "[agent] connected to \\\\.\\WazabiEDR (Ctrl+C to stop) — spool dir: {} — \
         plugins dir: {} — console_output: {}",
        cfg.agent.spool_dir.display(),
        plugin_dir.display(),
        console_output,
    );

    run_pump_loop(
        handle,
        Some(&kernel_spool),
        detection.as_ref(),
        console_output,
    );

    close_device(handle);

    // Stop the rules hot-reload thread early (it observes SHUTDOWN, set by
    // the Ctrl+C handler that also unblocked the pump loop above).
    if let Some(j) = detection_reload {
        let _ = j.join();
    }

    // Tear down in reverse spawn order. The supervisor first so plugin
    // child processes get a chance to flush their last events through
    // the still-open pipe → spool → shipper chain.
    if let Some(s) = plugin_supervisor {
        let count = s.spawned_count();
        s.shutdown();
        if count > 0 {
            eprintln!(
                "[agent] supervisor stopped — {} auto-launched plugin(s) joined",
                count
            );
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
        eprintln!(
            "[agent] plugin server stats — accepted: {}, rejected: {}, \
             events: {} ({} invalid), reloads: {}, still-active: {}",
            accepted, rejected, received, invalid, reloads, active
        );
    }

    let ks = kernel_spool.stats();
    let k_written = ks.events_written.load(Ordering::Relaxed);
    let k_dropped = ks.events_dropped.load(Ordering::Relaxed);
    let k_sealed = ks.batches_sealed.load(Ordering::Relaxed);
    let k_evicted = ks.batches_evicted.load(Ordering::Relaxed);
    kernel_spool.shutdown();

    let plugin_summary = if let Some(ps) = plugin_spool {
        let s = ps.stats();
        let w = s.events_written.load(Ordering::Relaxed);
        let d = s.events_dropped.load(Ordering::Relaxed);
        let b = s.batches_sealed.load(Ordering::Relaxed);
        let e = s.batches_evicted.load(Ordering::Relaxed);
        ps.shutdown();
        Some((w, d, b, e))
    } else {
        None
    };

    eprintln!(
        "[agent] disconnected — kernel spool: {} events written, {} dropped, \
         {} batches sealed, {} evicted",
        k_written, k_dropped, k_sealed, k_evicted
    );
    if let Some((w, d, b, e)) = plugin_summary {
        eprintln!(
            "[agent] plugin spool: {} events written, {} dropped, \
             {} batches sealed, {} evicted",
            w, d, b, e
        );
    }

    if let Some(sh) = shipper_handle {
        let ss = sh.stats();
        let sent = ss.batches_sent.load(Ordering::Relaxed);
        let rejected = ss.batches_rejected.load(Ordering::Relaxed);
        let retries = ss.send_retries.load(Ordering::Relaxed);
        sh.shutdown();
        eprintln!(
            "[agent] shipper: {} batches sent, {} rejected, {} retries",
            sent, rejected, retries
        );
    }

    // Make sure stderr is flushed before exit so the operator sees the
    // shutdown stats even if the process is being killed by a service
    // manager. stdout doesn't matter here — every event line was
    // flushed at write time when console_output was on.
    let _ = io::stderr().flush();

    Ok(())
}
