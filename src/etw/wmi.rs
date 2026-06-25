//! Microsoft-Windows-WMI-Activity ETW provider.
//!
//! Provider GUID: `{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}`.
//!
//! Surfaces WMI calls system-wide. Two events are most useful for
//! detection of fileless persistence / lateral movement:
//!
//! - 5857 = `Operation_StartedOperational` (WMI method invocation,
//!   includes provider + operation + namespace)
//! - 5861 = `Operation_ESStoBecomePermanent` (a permanent event consumer
//!   was registered — the canonical "WMI persistence" technique)
//!
//! 5858 (errors) is dropped — too noisy.

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_WMI_ACTIVITY, EtwEvent};

pub const GUID: &str = "1418ef04-b0b4-4623-bf7e-d74ab47bbdaa";

const EVT_OP_STARTED: u16 = 5857;
const EVT_PERMANENT_CONSUMER: u16 = 5861;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    let id = record.event_id();
    let kind_label = match id {
        EVT_OP_STARTED => "WmiOperation",
        EVT_PERMANENT_CONSUMER => "WmiPermanentConsumer",
        _ => return None,
    };

    let operation: String = parser.try_parse("Operation").unwrap_or_default();
    let namespace: String = parser.try_parse("NamespaceName").unwrap_or_default();
    let provider_name: String = parser.try_parse("ProviderName").unwrap_or_default();
    let user: String = parser.try_parse("User").unwrap_or_default();
    let process_id_field: u32 = parser.try_parse("ProcessID").unwrap_or(record.process_id());

    // Skip housekeeping operations triggered by the OS itself ("Start
    // IWbemServices::ExecQuery - root\subscription") — they dwarf the
    // signal otherwise. We keep only operations against root\subscription
    // (persistence) or non-root namespaces (lateral move targets).
    if id == EVT_OP_STARTED
        && (operation.is_empty() || namespace.eq_ignore_ascii_case("root\\cimv2"))
    {
        return None;
    }

    let payload = serde_json::json!({
        "pid": process_id_field,
        "operation": operation,
        "namespace": namespace,
        "provider": provider_name,
        "user": user,
        "is_persistence_register": id == EVT_PERMANENT_CONSUMER,
    });

    Some(EtwEvent {
        event_type: ET_WMI_ACTIVITY,
        kind: kind_label,
        event_version: 1,
        pid: Some(process_id_field),
        process_name: None,
        payload,
    })
}
