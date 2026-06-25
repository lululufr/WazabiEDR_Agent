//! Microsoft-Windows-DNS-Client ETW provider.
//!
//! Provider GUID: `{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}`.
//!
//! High-signal events:
//! - 3006 = DNS query started
//! - 3008 = DNS query completed (results in `QueryResults`)
//! - 3009 = DNS query timeout / NXDOMAIN
//!
//! We emit one `dns_query` event per **completion** (3008/3009) — the
//! 3006 "started" carries no answer and would double the volume.

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_DNS_QUERY, EtwEvent};

pub const GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

const EVT_COMPLETED: u16 = 3008;
const EVT_TIMEOUT: u16 = 3009;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    let id = record.event_id();
    if id != EVT_COMPLETED && id != EVT_TIMEOUT {
        return None;
    }

    let query_name: String = parser.try_parse("QueryName").unwrap_or_default();
    if query_name.is_empty() {
        return None;
    }
    let query_type: u32 = parser.try_parse("QueryType").unwrap_or(0);
    let query_status: u32 = parser.try_parse("QueryStatus").unwrap_or(0);
    let query_results: String = parser.try_parse("QueryResults").unwrap_or_default();

    let payload = serde_json::json!({
        "pid": record.process_id(),
        "query_name": query_name,
        "query_type": query_type,
        "query_status": query_status,
        // QueryResults is a `;`-joined list of resolved IPs ("type:addr").
        // We split it lazily so the SIEM can match on `dns.answer:1.2.3.4`.
        "answers": query_results
            .split(';')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        "timed_out": id == EVT_TIMEOUT,
    });

    Some(EtwEvent {
        event_type: ET_DNS_QUERY,
        kind: "DnsQuery",
        event_version: 1,
        pid: Some(record.process_id()),
        process_name: None,
        payload,
    })
}
