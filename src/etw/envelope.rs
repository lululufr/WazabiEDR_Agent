//! JSON envelope for ETW events.
//!
//! Mirrors the shape produced by `ipc::json::KernelEnvelope` so the
//! server-side `EventIn` schema accepts both kernel-sourced and
//! ETW-sourced events without special-casing. Differences:
//!
//! - `source` = `"etw"` (instead of `"kernel"`)
//! - `module` = `"etw"` (a dedicated AgentModule on the server)
//! - `event_type` = the normalised label picked by the provider handler
//!   (`dns_query`, `network_connect`, `powershell_script`, …)
//! - `event_version` = a per-provider versioned tag — bump when the
//!   raw payload layout changes for that provider.
//!
//! The `process` block follows the server's `ProcessInfo` shape, hoisted
//! out of the per-event payload when the provider supplied a PID.

use serde::Serialize;

use crate::util::time::now_iso8601;

/// Stable label assigned to each ETW provider's normalised event.
/// Must match an entry in the server's `EventType` Pydantic enum or the
/// event is rejected at ingest (422 → skipped + logged).
pub const ET_DNS_QUERY: &str = "dns_query";
pub const ET_NETWORK_CONNECT: &str = "network_connect";
pub const ET_POWERSHELL_SCRIPT: &str = "powershell_script";
pub const ET_WMI_ACTIVITY: &str = "wmi_activity";
pub const ET_TLS_HANDSHAKE: &str = "tls_handshake";
pub const ET_AMSI_SCAN: &str = "amsi_scan";

#[derive(Serialize)]
struct ProcessSlim {
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize)]
struct Envelope<'a> {
    ts: String,
    module: &'static str,
    event_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessSlim>,
    raw: &'a serde_json::Value,
    source: &'static str,
    kind: &'static str,
    event_version: u16,
}

/// What each per-provider handler returns to the dispatch loop. Holds
/// everything needed to serialise a single NDJSON line.
pub struct EtwEvent {
    /// Server-side `EventType` discriminant.
    pub event_type: &'static str,
    /// Free-text label visible in stdout/UI ("DnsQuery", "TcpConnect").
    pub kind: &'static str,
    /// Per-provider schema version. Bump only when the raw payload's
    /// field set changes in a non-additive way for that provider.
    pub event_version: u16,
    /// PID of the process that emitted the event when known. ETW
    /// always exposes the emitting PID (`record.process_id()`).
    pub pid: Option<u32>,
    /// Best-effort process basename, when the provider supplies one
    /// (PowerShell does, DNS doesn't). The shipper will not OpenProcess
    /// to fill this — kept lazy.
    pub process_name: Option<String>,
    /// Free-form payload (provider-specific). Serialised as `raw.*`.
    pub payload: serde_json::Value,
}

impl EtwEvent {
    /// Returns `None` if serde refuses to serialise the payload — that
    /// way the caller skips submit() entirely rather than pushing a
    /// truncated/empty line that would break the server-side NDJSON
    /// parser. Pre-allocate the buffer to roughly the typical envelope
    /// size to avoid `Vec` reallocations on the hot path.
    pub fn into_ndjson_line(self) -> Option<Vec<u8>> {
        let env = Envelope {
            ts: now_iso8601(),
            module: "etw",
            event_type: self.event_type,
            process: self.pid.map(|pid| ProcessSlim {
                pid,
                name: self.process_name,
            }),
            raw: &self.payload,
            source: "etw",
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
