//! The `wedr-alerts` loop: drain Waza matches and POST them to `/alerts`.
//!
//! This is the diagram's "priority path" — alerts go out promptly, not
//! batched with telemetry. The detection engine hands [`AgentAlert`]s over
//! a bounded channel; this thread blocks on it (with a short timeout so it
//! still notices `SHUTDOWN`), coalesces whatever is immediately available
//! into one batch, maps each to the server's `AlertIn` shape, and POSTs.
//!
//! Mapping is necessarily lossy: local `.waza` rules carry no server rule
//! UUID / severity / MITRE mapping, so `rule_id` falls back to the rule
//! name, `severity` defaults to `medium`, and the event's scalar fields go
//! in `evidence`. `module` is sanitised to a valid server `AgentModule`
//! value (anything not from a known native module is reported as `plugin`).

use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use super::ControlStats;
use super::client::{AlertOut, Client};
use crate::detection::AgentAlert;
use crate::shutdown::SHUTDOWN;

/// Max alerts coalesced into a single POST. A burst beyond this just
/// rolls into the next iteration — keeps any one request bounded.
const MAX_BATCH: usize = 64;

/// Server `AgentModule` enum values the agent can legitimately emit.
const NATIVE_MODULES: [&str; 5] = ["kernel_callback", "minifilter", "network", "hooking", "web"];

/// Map an event module onto a valid server `AgentModule`. Native module
/// names pass through; anything else (e.g. an out-of-process plugin's
/// label) is reported as `plugin`, which the server accepts.
fn server_module(module: &str) -> &str {
    if NATIVE_MODULES.contains(&module) || module == "plugin" {
        module
    } else {
        "plugin"
    }
}

pub fn run(client: &Client, rx: Receiver<AgentAlert>, stats: &ControlStats) {
    eprintln!("[control] alerts thread started");

    while !SHUTDOWN.load(Ordering::Acquire) {
        // Block until an alert arrives or the timeout lets us re-check
        // SHUTDOWN. Coalesce any others already queued into one batch.
        let first = match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(a) => a,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(a) => batch.push(a),
                Err(_) => break,
            }
        }

        post_batch(client, &batch, stats);
    }

    // Best-effort final drain so alerts emitted just before shutdown still
    // go out (the channel may still hold a few).
    let mut tail: Vec<AgentAlert> = Vec::new();
    while let Ok(a) = rx.try_recv() {
        tail.push(a);
        if tail.len() >= MAX_BATCH {
            post_batch(client, &tail, stats);
            tail.clear();
        }
    }
    if !tail.is_empty() {
        post_batch(client, &tail, stats);
    }

    eprintln!("[control] alerts thread exited");
}

/// Map a batch to `AlertOut` and POST it. Counts sent vs dropped.
fn post_batch(client: &Client, batch: &[AgentAlert], stats: &ControlStats) {
    let payload: Vec<AlertOut<'_>> = batch
        .iter()
        .map(|a| AlertOut {
            ts: &a.ts,
            rule_id: &a.rule_name,
            rule_name: &a.rule_name,
            severity: "medium",
            module: server_module(&a.module),
            action_taken: a.action_taken,
            evidence: &a.evidence,
        })
        .collect();

    match client.post_alerts(&payload) {
        Ok(received) => {
            stats.add_alerts_sent(received as u64);
            eprintln!("[control] {} alert(s) sent", received);
        }
        Err(e) => {
            stats.add_alerts_dropped(batch.len() as u64);
            eprintln!(
                "[control] {} alert(s) dropped — POST /alerts failed: {}",
                batch.len(),
                e
            );
        }
    }
}
