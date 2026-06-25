//! Microsoft-Windows-Kernel-Network ETW provider.
//!
//! Provider GUID: `{7dd42a49-5329-4832-8dfd-43d979153a88}`.
//!
//! Captures TCP/UDP socket events with the emitting PID. We focus on
//! outbound connect attempts — the high-signal subset:
//!
//! - 12 = `KERNEL_NETWORK_TASK_TCPIP / TcpIpConnect` (IPv4 SYN)
//! - 28 = same, IPv6
//! - 42 = UDP send (IPv4)
//! - 58 = UDP send (IPv6)
//!
//! Inbound accepts (13/29) and incoming UDP (43/59) are noisier and
//! less useful for EDR detection; we skip them at this layer (the
//! correlation pid-process happens server-side on `event.pid`).

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;

use super::envelope::{ET_NETWORK_CONNECT, EtwEvent};

pub const GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

const TCP_CONNECT_V4: u16 = 12;
const TCP_CONNECT_V6: u16 = 28;
const UDP_SEND_V4: u16 = 42;
const UDP_SEND_V6: u16 = 58;

pub fn handle(record: &EventRecord, parser: &Parser) -> Option<EtwEvent> {
    let id = record.event_id();
    let (proto, is_v6) = match id {
        TCP_CONNECT_V4 => ("tcp", false),
        TCP_CONNECT_V6 => ("tcp", true),
        UDP_SEND_V4 => ("udp", false),
        UDP_SEND_V6 => ("udp", true),
        _ => return None,
    };

    // The schema uses `daddr` / `saddr` / `dport` / `sport`. ferrisetw
    // turns Win32 IP addresses into `IpAddr` when the field is typed as
    // such in the manifest; we render them as strings for JSON.
    let daddr: String = parser
        .try_parse::<std::net::IpAddr>("daddr")
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let saddr: String = parser
        .try_parse::<std::net::IpAddr>("saddr")
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let dport: u16 = parser.try_parse("dport").unwrap_or(0);
    let sport: u16 = parser.try_parse("sport").unwrap_or(0);
    // Kernel-Network's manifest names the field `ProcessId`. Older
    // builds or alternate schemas sometimes use `PID` — try both,
    // fall back to the ETW record-level PID (the consumer-side
    // PsGetCurrentProcessId at emission time).
    let pid_from_record: u32 = parser
        .try_parse("ProcessId")
        .or_else(|_| parser.try_parse("PID"))
        .unwrap_or(record.process_id());

    // Skip events where the kernel didn't actually fill destination
    // (loopback / partial). They generate noise without forensic value.
    if daddr.is_empty() && saddr.is_empty() {
        return None;
    }

    let payload = serde_json::json!({
        "pid": pid_from_record,
        "protocol": proto,
        "ip_version": if is_v6 { 6 } else { 4 },
        "dst_ip": daddr,
        "dst_port": dport,
        "src_ip": saddr,
        "src_port": sport,
        "direction": "outbound",
    });

    Some(EtwEvent {
        event_type: ET_NETWORK_CONNECT,
        kind: if proto == "tcp" { "TcpConnect" } else { "UdpSend" },
        event_version: 1,
        pid: Some(pid_from_record),
        process_name: None,
        payload,
    })
}
