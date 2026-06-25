//! JSON envelope for persistence (services / scheduled tasks) events.
//!
//! Same shape as the kernel `KernelEnvelope` and the ETW one so the
//! server's `EventIn` accepts all three sources uniformly. Differences:
//!
//! - `module` = `"persistence"`
//! - `source` = `"polling"`
//! - `event_type` is one of `service_*` / `scheduled_task_*` (see server
//!   `EventType` enum)
//!
//! There is no `process` block: persistence events identify an *artefact*
//! (service name, task path), not an acting process. SIEM rules cross-
//! reference with `process_create` events server-side.

use serde::Serialize;

use crate::util::time::now_iso8601;

pub const ET_SERVICE_CREATE: &str = "service_create";
pub const ET_SERVICE_MODIFY: &str = "service_modify";
pub const ET_SERVICE_DELETE: &str = "service_delete";
pub const ET_SERVICE_START: &str = "service_start";
pub const ET_SERVICE_STOP: &str = "service_stop";
pub const ET_TASK_CREATE: &str = "scheduled_task_create";
pub const ET_TASK_MODIFY: &str = "scheduled_task_modify";
pub const ET_TASK_DELETE: &str = "scheduled_task_delete";

#[derive(Serialize)]
struct Envelope<'a> {
    ts: String,
    module: &'static str,
    event_type: &'static str,
    raw: &'a serde_json::Value,
    source: &'static str,
    kind: &'static str,
    event_version: u16,
}

pub struct PersistenceEvent {
    pub event_type: &'static str,
    pub kind: &'static str,
    pub event_version: u16,
    pub payload: serde_json::Value,
}

impl PersistenceEvent {
    /// `None` on serde error — same rationale as `EtwEvent`: never
    /// push an empty/truncated line into the NDJSON spool.
    pub fn into_ndjson_line(self) -> Option<Vec<u8>> {
        let env = Envelope {
            ts: now_iso8601(),
            module: "persistence",
            event_type: self.event_type,
            raw: &self.payload,
            source: "polling",
            kind: self.kind,
            event_version: self.event_version,
        };
        let mut out = Vec::with_capacity(512);
        match serde_json::to_writer(&mut out, &env) {
            Ok(()) => {
                out.push(b'\n');
                Some(out)
            }
            Err(_) => None,
        }
    }
}
