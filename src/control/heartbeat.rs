//! The `wedr-heartbeat` loop: ping the server, run + ack commands, sync profile.
//!
//! One iteration:
//! 1. Build a [`HeartbeatRequest`] from the shared [`ProfileState`].
//! 2. `POST /agents/{id}/heartbeat`.
//! 3. For every returned pending command: hand it to
//!    [`super::executor::execute`] (which may actually perform an action,
//!    e.g. `TerminateProcess` for `kill_process`, or stay no-op for types
//!    we can't fulfill in this build), then `POST .../commands/{id}/ack`
//!    with the resulting status + result. The server's queue drains
//!    either way; status discriminates "actually ran" vs "ack only".
//! 4. If the server's `current_profile_version` is ahead of ours, pull the
//!    new profile (transport only — see [`sync::pull`]).
//! 5. Sleep `next_checkin_seconds` (server-driven) or the configured
//!    fallback, waking early on shutdown.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::client::{Client, HeartbeatRequest};
use super::{ControlStats, ProfileState, executor, responsive_sleep, sync};
use crate::shutdown::SHUTDOWN;

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

                // (3) Run + ack pending commands. The executor either
                // performs a real action (kill_process today) or returns
                // "completed/no-op" with a clear note — either way the
                // server's PENDING queue drains.
                // `update_rules` is special: the executor itself is a
                // no-op (no payload to apply), but seeing one in the
                // pending list means the admin clicked "Re-pull profil"
                // and we want to force a sync this iteration even if the
                // server-side version hasn't moved.
                let mut force_profile_pull = false;
                for cmd in &resp.pending_commands {
                    if cmd.cmd_type == "update_rules" {
                        force_profile_pull = true;
                    }
                    let outcome = executor::execute(cmd);
                    let final_status = outcome.status;
                    match client.ack_command(&cmd.id, final_status, outcome.result) {
                        Ok(()) => {
                            stats.bump_command_acked();
                            eprintln!(
                                "[control] command {} ({}) → ack status={}",
                                cmd.id, cmd.cmd_type, final_status,
                            );
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
                if resp.current_profile_version > local || force_profile_pull {
                    eprintln!(
                        "[control] profile {} v{} → v{}, syncing…",
                        if force_profile_pull { "re-pull forced" } else { "change" },
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
