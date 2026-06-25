//! Microsoft-Windows-PowerShell ETW provider — script-block logging.
//!
//! Provider GUID: `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}`.
//!
//! EventID 4104 = ScriptBlockLogging. Carries the **fully-decoded**
//! script text after `-EncodedCommand` base64 / `Invoke-Expression`
//! unwrapping — exactly what an offensive operator hopes will stay
//! hidden. The catch: 4104 only fires when group policy
//! `EnableScriptBlockLogging` is on (or per-host via the registry key
//! `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`).
//! The installer needs to set that — see Phase F doc.

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_POWERSHELL_SCRIPT, EtwEvent};

pub const GUID: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";

const EVT_SCRIPT_BLOCK: u16 = 4104;

/// Hard cap on the script body we ship. PowerShell scripts can run into
/// hundreds of KB once decoded; the SIEM index doesn't need the full
/// payload — the signal is in the prefix + opcodes.
const MAX_SCRIPT_BYTES: usize = 16 * 1024;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    if record.event_id() != EVT_SCRIPT_BLOCK {
        return None;
    }

    let script: String = parser.try_parse("ScriptBlockText").unwrap_or_default();
    if script.is_empty() {
        return None;
    }
    let (script, truncated) = if script.len() > MAX_SCRIPT_BYTES {
        (script[..MAX_SCRIPT_BYTES].to_string(), true)
    } else {
        (script, false)
    };
    let script_block_id: String = parser.try_parse("ScriptBlockId").unwrap_or_default();
    let path: String = parser.try_parse("Path").unwrap_or_default();

    let payload = serde_json::json!({
        "pid": record.process_id(),
        "script_block_id": script_block_id,
        "script_block": script,
        "script_truncated": truncated,
        "script_path": path,
    });

    Some(EtwEvent {
        event_type: ET_POWERSHELL_SCRIPT,
        kind: "PowerShellScript",
        event_version: 1,
        pid: Some(record.process_id()),
        // Leave name=None — the host could be pwsh.exe (PowerShell 7),
        // powershell_ise.exe, a custom .NET host embedding the runtime,
        // etc. The server can correlate via pid → process_create events.
        process_name: None,
        payload,
    })
}
