//! Microsoft-Windows-Schannel-Events ETW provider — TLS handshake.
//!
//! Provider GUID: `{91cc1150-71aa-47e2-a679-fbedaccda1a3}`.
//!
//! Captures TLS handshakes initiated locally. The SNI extension carries
//! the **target hostname** unencrypted, so we get the equivalent of DNS
//! events for traffic that doesn't go through the OS resolver (DoH,
//! hardcoded IP + Host header, etc.). Cross-correlation with
//! `network_connect` exposes the full L7 conversation.
//!
//! Key event:
//! - 36880 = `EVENT_SCHANNEL_TLS_HANDSHAKE_END` (handshake completed,
//!   includes negotiated cipher / TLS version / SNI).

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_TLS_HANDSHAKE, EtwEvent};

pub const GUID: &str = "91cc1150-71aa-47e2-a679-fbedaccda1a3";

const EVT_HANDSHAKE_END: u16 = 36880;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    if record.event_id() != EVT_HANDSHAKE_END {
        return None;
    }

    let target_name: String = parser.try_parse("TargetName").unwrap_or_default();
    let protocol_version: u32 = parser.try_parse("ProtocolVersion").unwrap_or(0);
    let cipher_suite: u32 = parser.try_parse("CipherSuite").unwrap_or(0);

    if target_name.is_empty() && protocol_version == 0 {
        return None;
    }

    let payload = serde_json::json!({
        "pid": record.process_id(),
        "sni": target_name,
        "protocol_version": protocol_version,
        "protocol_label": tls_label(protocol_version),
        "cipher_suite": cipher_suite,
    });

    Some(EtwEvent {
        event_type: ET_TLS_HANDSHAKE,
        kind: "TlsHandshake",
        event_version: 1,
        pid: Some(record.process_id()),
        process_name: None,
        payload,
    })
}

/// SChannel's `ProtocolVersion` field is the raw TLS protocol number
/// (0x0303 = TLS 1.2). We expose a human label alongside so the SIEM
/// can query "tls.protocol_label:TLS1.0" without computing it inline.
fn tls_label(v: u32) -> &'static str {
    match v {
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",
        0x0002 => "SSL2.0",
        0x0300 => "SSL3.0",
        _ => "unknown",
    }
}
