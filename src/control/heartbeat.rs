//! The `wedr-heartbeat` loop: ping the server, ack commands, sync profile.
//!
//! One iteration:
//! 1. Build a [`HeartbeatRequest`] from the shared [`ProfileState`].
//! 2. `POST /agents/{id}/heartbeat`.
//! 3. **Ack** every returned pending command (`status:"completed"` + a
//!    result stamp). Per the agreed scope this mirrors the reference
//!    simulator: the agent does **not** actually execute commands — the
//!    driver is read-only, so kill/isolate aren't possible — it
//!    acknowledges receipt so the server's queue drains.
//! 4. If the server's `current_profile_version` is ahead of ours, pull the
//!    new profile (transport only — see [`sync::pull`]).
//! 5. Sleep `next_checkin_seconds` (server-driven) or the configured
//!    fallback, waking early on shutdown.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::client::{Client, HeartbeatRequest};
use super::{ControlStats, ProfileState, responsive_sleep, sync};
use crate::shutdown::SHUTDOWN;
use crate::util::time::now_iso8601;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run(
    client: &Client,
    fallback_interval: Duration,
    state_dir: &Path,
    state: Arc<Mutex<ProfileState>>,
    stats: &ControlStats,
) {
    eprintln!(
        "[control] heartbeat thread started — interval {}s (server may override)",
        fallback_interval.as_secs()
    );

    let mut interval = fallback_interval;

    while !SHUTDOWN.load(Ordering::Acquire) {
        // Snapshot the profile state for this beat (clone to release the
        // lock before any network I/O).
        let (profile_version, modules_loaded) = {
            let s = match state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            (s.version, s.modules_loaded.clone())
        };

        let req = HeartbeatRequest {
            status: "healthy",
            agent_version: AGENT_VERSION,
            last_rule_version: 0,
            profile_version,
            modules_loaded,
            metrics: None,
        };

        match client.heartbeat(&req) {
            Ok(resp) => {
                stats.bump_heartbeat_ok();
                eprintln!(
                    "[control] heartbeat ok — server_time={} profile_v={} cmds={}",
                    resp.server_time,
                    resp.current_profile_version,
                    resp.pending_commands.len()
                );

                // (3) Acknowledge pending commands (receipt only).
                for cmd in &resp.pending_commands {
                    let result = serde_json::json!({
                        "executed_at": now_iso8601(),
                        "note": "acknowledged by agent (no local execution in this build)",
                    });
                    match client.ack_command(&cmd.id, "completed", result) {
                        Ok(()) => {
                            stats.bump_command_acked();
                            eprintln!("[control] acked command {} ({})", cmd.id, cmd.cmd_type);
                        }
                        Err(e) => {
                            eprintln!("[control] ack command {} failed: {}", cmd.id, e);
                        }
                    }
                }

                // (4) Profile drift → pull + persist (transport only).
                let local = {
                    let s = match state.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    s.version
                };
                if resp.current_profile_version > local {
                    eprintln!(
                        "[control] profile change v{} → v{}, syncing…",
                        local, resp.current_profile_version
                    );
                    if let Err(e) = sync::pull(client, &state, state_dir, stats) {
                        eprintln!("[control] profile sync failed: {}", e);
                    }
                }

                // (5) Honour the server's requested cadence.
                if resp.next_checkin_seconds > 0 {
                    interval = Duration::from_secs(resp.next_checkin_seconds as u64);
                }
            }
            Err(e) => {
                stats.bump_heartbeat_failed();
                eprintln!("[control] heartbeat failed: {}", e);
            }
        }

        responsive_sleep(interval);
    }

    eprintln!("[control] heartbeat thread exited");
}
