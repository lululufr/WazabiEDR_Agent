//! Control plane: the agent's "life" against Wazabi Server.
//!
//! While [`crate::shipper`] drains *telemetry* batches to `/logs`, this
//! module owns the **management** conversation described by the Wazabi
//! diagrams:
//!
//! - a periodic **heartbeat** (`POST /agents/{id}/heartbeat`) that reports
//!   status / profile version / loaded modules and receives the server
//!   clock, the authoritative profile version, and any pending commands;
//! - **profile synchronisation** (`GET …/profile` + `…/template`) when the
//!   server's profile version moves ahead of the agent's (transport only —
//!   see [`sync`]);
//! - **command** receipt + acknowledgement (`POST …/commands/{id}/ack`);
//! - **alert** forwarding (`POST …/alerts`) for Waza rule matches, pushed
//!   off the detection hot path over a bounded channel (see [`alerts`]).
//!
//! It reuses the same server credentials as the shipper (a single Wazabi
//! Server is the one peer), passed in as [`ServerCreds`]. Two small worker
//! threads are spawned: `wedr-heartbeat` (the heartbeat/command/profile
//! loop) and `wedr-alerts` (drains and POSTs alerts promptly — the
//! diagram's "priority path"). Both observe the global `SHUTDOWN` flag.
//!
//! Networking mirrors `shipper`/`enroll`: `ureq`, manual serde, no async.

pub mod alerts;
pub mod client;
pub mod heartbeat;
pub mod sync;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::detection::AgentAlert;
use crate::shutdown::SHUTDOWN;
use client::ModuleRef;

/// Server credentials shared with the shipper (one Wazabi Server peer).
/// Built from the resolved `ShipperConfig` in `main`.
#[derive(Clone, Debug)]
pub struct ServerCreds {
    /// Base URL, no trailing slash (e.g. `https://wazabi.example.com`).
    pub server_url: String,
    /// The enrolled agent UUID. MUST be the server-assigned id — the
    /// server enforces `{agent_id}` in the path == the Bearer's agent.
    pub agent_id: String,
    /// Bearer token (already decrypted). Never logged.
    pub token: String,
    pub verify_tls: bool,
    pub timeout: Duration,
}

/// Runtime configuration for the control plane.
pub struct ControlConfig {
    pub creds: ServerCreds,
    /// Fallback heartbeat cadence. The server's `next_checkin_seconds`
    /// overrides this at runtime when present.
    pub heartbeat_interval: Duration,
    /// Forward Waza alerts to `/alerts`. When false, the `wedr-alerts`
    /// thread isn't spawned and the detection engine gets no sink.
    pub send_alerts: bool,
    /// Where `profile.json` / `profile_template.json` are persisted.
    pub state_dir: PathBuf,
}

/// In-memory profile state reported in every heartbeat, kept in sync by
/// [`sync::pull`] and seeded from disk at startup by [`sync::load_persisted`].
#[derive(Debug, Default, Clone)]
pub struct ProfileState {
    pub version: i64,
    pub modules_loaded: Vec<ModuleRef>,
}

/// Counters for the end-of-run summary.
#[derive(Default)]
pub struct ControlStats {
    pub heartbeats_ok: AtomicU64,
    pub heartbeats_failed: AtomicU64,
    pub commands_acked: AtomicU64,
    pub profile_syncs: AtomicU64,
    pub alerts_sent: AtomicU64,
    pub alerts_dropped: AtomicU64,
}

impl ControlStats {
    pub fn bump_heartbeat_ok(&self) {
        self.heartbeats_ok.fetch_add(1, Ordering::Relaxed);
    }
    pub fn bump_heartbeat_failed(&self) {
        self.heartbeats_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn bump_command_acked(&self) {
        self.commands_acked.fetch_add(1, Ordering::Relaxed);
    }
    pub fn bump_profile_sync(&self) {
        self.profile_syncs.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_alerts_sent(&self, n: u64) {
        self.alerts_sent.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_alerts_dropped(&self, n: u64) {
        self.alerts_dropped.fetch_add(n, Ordering::Relaxed);
    }
}

/// Handle to the spawned control-plane threads.
pub struct ControlHandle {
    heartbeat_join: Option<JoinHandle<()>>,
    alerts_join: Option<JoinHandle<()>>,
    stats: Arc<ControlStats>,
}

impl ControlHandle {
    pub fn stats(&self) -> &ControlStats {
        &self.stats
    }

    /// Join the worker threads. They observe the global `SHUTDOWN` flag
    /// (set by the Ctrl+C handler) and exit within ~250 ms.
    pub fn shutdown(mut self) {
        if let Some(j) = self.heartbeat_join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.alerts_join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the control plane: always the heartbeat thread, plus the alert
/// thread when `send_alerts` is on and an `alert_rx` is provided.
pub fn spawn_control(
    cfg: ControlConfig,
    alert_rx: Option<Receiver<AgentAlert>>,
) -> std::io::Result<ControlHandle> {
    let stats = Arc::new(ControlStats::default());

    // Seed profile state from disk so a restart resumes at the right
    // version instead of forcing a re-pull on the first heartbeat.
    let state = Arc::new(Mutex::new(sync::load_persisted(&cfg.state_dir)));

    let creds = cfg.creds.clone();
    let heartbeat_interval = cfg.heartbeat_interval;
    let state_dir = cfg.state_dir.clone();
    let hb_state = Arc::clone(&state);
    let hb_stats = Arc::clone(&stats);
    let heartbeat_join = thread::Builder::new()
        .name("wedr-heartbeat".into())
        .spawn(move || {
            let client = client::Client::new(creds);
            heartbeat::run(&client, heartbeat_interval, &state_dir, hb_state, &hb_stats);
        })?;

    let alerts_join = match (cfg.send_alerts, alert_rx) {
        (true, Some(rx)) => {
            let creds = cfg.creds.clone();
            let al_stats = Arc::clone(&stats);
            let join = thread::Builder::new()
                .name("wedr-alerts".into())
                .spawn(move || {
                    let client = client::Client::new(creds);
                    alerts::run(&client, rx, &al_stats);
                })?;
            Some(join)
        }
        _ => None,
    };

    Ok(ControlHandle {
        heartbeat_join: Some(heartbeat_join),
        alerts_join,
        stats,
    })
}

/// Sleep up to `dur`, waking within ~250 ms of `SHUTDOWN` being set so the
/// agent stops promptly instead of waiting out a full heartbeat interval.
pub(crate) fn responsive_sleep(dur: Duration) {
    let until = Instant::now() + dur;
    while Instant::now() < until {
        if SHUTDOWN.load(Ordering::Acquire) {
            return;
        }
        let remaining = until.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(250)));
    }
}
