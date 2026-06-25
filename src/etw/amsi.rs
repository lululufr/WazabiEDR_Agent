//! Microsoft-Antimalware-Scan-Interface ETW provider.
//!
//! Provider GUID: `{2a576b87-09a7-520e-c21a-4942f0271d67}`.
//!
//! This is the **passive observer** path for AMSI — much lighter than
//! registering an in-proc COM provider (which would require Authenticode
//! signing, an AV-style ELAM install, and ASR rules to load it). The
//! ETW provider emits one event each time an AMSI consumer (PowerShell,
//! VBScript via WSH, Office macros, .NET, etc.) submits content to be
//! scanned. We get the **fully-decoded** content right before execution.
//!
//! Key events:
//! - 1101 = `AmsiContent` (the buffer about to be scanned)
//!
//! Caveats:
//! - The ETW provider is only emitted by Microsoft Defender. Third-party
//!   AVs that hook AMSI via COM bypass this. For a complete-coverage
//!   AMSI integration the right path is the COM provider — out of scope.

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_AMSI_SCAN, EtwEvent};

pub const GUID: &str = "2a576b87-09a7-520e-c21a-4942f0271d67";

const EVT_CONTENT: u16 = 1101;

const MAX_CONTENT_BYTES: usize = 16 * 1024;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    if record.event_id() != EVT_CONTENT {
        return None;
    }

    let content_name: String = parser.try_parse("ContentName").unwrap_or_default();
    let content: String = parser.try_parse("Content").unwrap_or_default();
    let app_name: String = parser.try_parse("AppName").unwrap_or_default();
    let result: u32 = parser.try_parse("ScanResult").unwrap_or(0);

    if content.is_empty() && content_name.is_empty() {
        return None;
    }

    let (content, truncated) = if content.len() > MAX_CONTENT_BYTES {
        (content[..MAX_CONTENT_BYTES].to_string(), true)
    } else {
        (content, false)
    };

    let payload = serde_json::json!({
        "pid": record.process_id(),
        "content_name": content_name,
        "app_name": app_name,
        "content": content,
        "content_truncated": truncated,
        // AMSI scan result codes (msft docs):
        // 0 = clean, 1..32767 = AMSI_RESULT_DETECTED ranges,
        // 0x8000 = blocked by admin.
        "scan_result": result,
        "is_malicious": result >= 32768 || (1..32767).contains(&result),
    });

    Some(EtwEvent {
        event_type: ET_AMSI_SCAN,
        kind: "AmsiContent",
        event_version: 1,
        pid: Some(record.process_id()),
        process_name: None,
        payload,
    })
}
