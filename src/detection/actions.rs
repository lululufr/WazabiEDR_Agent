//! Action execution on a rule match.
//!
//! Actions run on the calling thread (the kernel pump or a plugin
//! worker), so they must stay light — see `CLAUDE.md` §10: never block
//! the read loop. `Log`/`Alert` are cheap `eprintln!`s. `KillProcess` is
//! a logged stub for now: the driver is opened read-only and exposes no
//! command channel, so there is nothing to send a kill order to yet.

use crate::detection::event::{FieldValue, LogEvent};
use crate::detection::waza::ast::Action;

/// Execute one action for a matched rule. `event` is the event that
/// triggered evaluation — used to enrich the log line (e.g. the pid for
/// a `KillProcess` stub).
pub fn execute(rule_name: &str, action: &Action, event: &LogEvent) {
    match action {
        Action::Log => {
            eprintln!(
                "[waza] MATCH rule='{}' -> LOG ({}.{})",
                rule_name, event.module, event.event_type
            );
        }
        Action::Alert(msg) => {
            eprintln!(
                "[waza] ALERT rule='{}' msg='{}' ({}.{})",
                rule_name, msg, event.module, event.event_type
            );
        }
        Action::KillProcess => {
            // TODO: wire to a real kill once the driver exposes a command
            // channel (it's opened GENERIC_READ today). Until then we log
            // the intent with whatever pid the event carries.
            let pid = event
                .get_field("pid")
                .or_else(|| event.get_field("target_pid"))
                .and_then(|v| match v {
                    FieldValue::Int(i) => Some(*i),
                    _ => None,
                });
            match pid {
                Some(p) => eprintln!(
                    "[waza] KILL_PROCESS (stub) rule='{}' pid={} — not yet wired to driver",
                    rule_name, p
                ),
                None => eprintln!(
                    "[waza] KILL_PROCESS (stub) rule='{}' — no pid in event, not yet wired to driver",
                    rule_name
                ),
            }
        }
    }
}
