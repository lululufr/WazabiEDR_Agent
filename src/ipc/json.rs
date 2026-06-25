//! Convert raw kernel-event bytes to a JSON line for the spool / shipper.
//!
//! The driver↔agent wire format is intentionally binary (packed, byte-
//! identical with the driver). The on-disk spool and the network shipper
//! both want JSON — this module is the single conversion point.
//!
//! # Why duplicate the parsing logic from `parser.rs`?
//!
//! `parser.rs` exists to feed stdout for human consumption: it formats
//! `"[ts] ProcessCreate pid=… path=…"` lines and stays the canonical
//! "what just happened" surface. JSON encoding has different concerns
//! (stable field names, no padding, escaping). Sharing one giant
//! intermediate enum across both would lock the two outputs into the
//! same schema forever; keeping them separate lets us evolve the JSON
//! shape without churning the human pretty-printer.
//!
//! The unsafe `read_unaligned` patterns are the same as `parser.rs` —
//! same packed structs, same `ptr::addr_of!` discipline. Touch one,
//! audit the other.

use std::mem::size_of;
use std::ptr;
use std::time::Instant;

use serde::Serialize;

use crate::detection::event::LogEvent;
use crate::detection::flatten_fields;
use crate::ipc::events::{
    EVENT_TYPE_IMAGE_LOAD, EVENT_TYPE_PROCESS_CREATE, EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_PROCESS_HANDLE_ACCESS, EVENT_TYPE_REGISTRY_MODIFY, EVENT_TYPE_THREAD_CREATE,
    EVENT_TYPE_THREAD_EXIT, EVENT_VERSION, EventHeader, HANDLE_ACCESS_OP_CREATE,
    HANDLE_ACCESS_OP_DUPLICATE, IMAGE_PATH_MAX, ImageLoadEvent, ProcessCreateEvent,
    ProcessExitEvent, ProcessHandleAccessEvent, REGISTRY_DATA_PREVIEW_MAX, REGISTRY_KEY_PATH_MAX,
    REGISTRY_OP_CREATE_KEY, REGISTRY_OP_DELETE_KEY, REGISTRY_OP_DELETE_VALUE,
    REGISTRY_OP_RENAME_KEY, REGISTRY_OP_SET_VALUE, REGISTRY_VALUE_NAME_MAX, RegistryEvent,
    ThreadCreateEvent, ThreadExitEvent,
};
use crate::util::time::format_timestamp;

/// Shape produced by [`encode_kernel_event`]. Aligned with the Wazabi
/// Server `EventIn` Pydantic schema (`WazabiEDR_Server/app/schemas/event.py`)
/// so each NDJSON line POSTed to `/api/v1/agents/{agent_id}/logs` parses
/// without validation errors and is indexed into OpenSearch
/// `wazabi-events`.
///
/// Required-by-server fields: `ts`, `module`, `event_type`. The server
/// also recognises a top-level `process` (`ProcessInfo`) which we hoist
/// out of the kernel payload when relevant. Everything else lives in
/// `raw` — Pydantic is configured with `extra="allow"` so the server
/// also keeps the verbatim agent-side fields (`ts_ft_100ns`, `source`,
/// `kind`, `event_version`, `drop_count`, `trunc_count`) for forensics.
///
/// `source` is always `"kernel"` here. The plugin-side encoder produces
/// the same envelope with `source: "plugin"` and its own
/// `module`/`event_type` mapping (see `plugin/server.rs`).
#[derive(Serialize)]
struct KernelEnvelope<'a> {
    /// ISO-8601 UTC, derived from the kernel FILETIME in the header.
    ts: String,
    /// Maps to the server's `AgentModule` enum — always
    /// `"kernel_callback"` for events sourced from the driver.
    module: &'static str,
    /// Maps to the server's `EventType` enum (snake_case). Built from
    /// the kernel event type code.
    event_type: &'static str,
    /// Process context hoisted out of the kernel payload when the event
    /// has one. Matches the server's `ProcessInfo` shape (`pid`, `ppid`,
    /// `path`). Skipped entirely for events without a process scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<ProcessSlim>,
    /// All other kernel-specific fields (registry op, image base,
    /// handle access, …). The server stores it as-is in OpenSearch.
    raw: &'a serde_json::Value,
    /// Kept verbatim so reorder under clock skew is debuggable.
    ts_ft_100ns: i64,
    source: &'static str,
    kind: &'static str,
    event_version: u16,
    /// Events dropped by the kernel ring between the previous delivered
    /// event and this one. Zero on the happy path; non-zero = surface it
    /// to the log backend so operators know about gaps.
    #[serde(skip_serializing_if = "is_zero_u32")]
    drop_count: u32,
    /// Path/value-name/data-preview fields the driver had to truncate
    /// since the previous delivered event. Same skip-zero treatment.
    #[serde(skip_serializing_if = "is_zero_u32")]
    trunc_count: u32,
}

/// Server-shaped subset of `ProcessInfo` that the kernel actually knows
/// about. Filled by [`extract_process`] from the per-event payloads.
///
/// `name` is derived from the basename of `path` — kept cheap because
/// `kernel_callback` events are high-volume. The SIEM heavily relies on
/// `process.name` (the keyword field) for Lucene queries like
/// `process.name:"powershell.exe"`, so providing it here is a big UX win
/// without going to OpenProcess/PEB territory (which would require a
/// user-mode handle to the target and synchronous I/O on the hot path).
#[derive(Serialize)]
struct ProcessSlim {
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

/// Extract a process executable name from a kernel path. Handles both NT
/// (`\Device\HarddiskVolume3\Windows\System32\notepad.exe`) and DOS
/// (`C:\Windows\System32\notepad.exe`) variants — the driver may emit
/// either depending on the callback.
fn basename(path: &str) -> Option<String> {
    let idx = path.rfind(|c| c == '\\' || c == '/')?;
    let name = &path[idx + 1..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Pull a server-compatible `process` block out of the kernel payload
/// when it carries one. Kernel callbacks always identify a process (or
/// a thread inside one) by `pid`, sometimes with `parent_pid` and
/// `image_path` — that's all the server's `ProcessInfo` can absorb at
/// this layer. PID 0 is the System Idle process / kernel scope, not a
/// real target — skip it so the server-side `ProcessInfo.pid` stays
/// meaningful for actual user-mode processes.
fn extract_process(payload: &serde_json::Value) -> Option<ProcessSlim> {
    let pid = payload.get("pid").and_then(|v| v.as_u64())? as u32;
    if pid == 0 {
        return None;
    }
    let ppid = payload
        .get("parent_pid")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let path = payload
        .get("image_path")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    let name = path.as_deref().and_then(basename);
    Some(ProcessSlim {
        pid,
        ppid,
        name,
        path,
    })
}

/// Decoded form of a kernel event: the server-shaped `event_type` plus
/// the `raw` payload and the header metadata. Produced once by
/// [`decode_kernel_event`] and consumed both by the NDJSON encoder and
/// the detection `LogEvent` builder so a single parse serves both.
struct DecodedKernel {
    kind: &'static str,
    event_type: &'static str,
    payload: serde_json::Value,
    ts: String,
    ts_ft_100ns: i64,
    version: u16,
    drop_count: u32,
    trunc_count: u32,
}

/// Parse the header + per-type payload of a raw kernel event exactly
/// once. Shared by [`encode_kernel_event`] and
/// [`encode_kernel_event_and_log`].
fn decode_kernel_event(buf: &[u8]) -> Result<DecodedKernel, String> {
    if buf.len() < size_of::<EventHeader>() {
        return Err(format!(
            "event too short: {} bytes, expected at least {}",
            buf.len(),
            size_of::<EventHeader>()
        ));
    }

    // SAFETY: bounds checked above; struct layout is `repr(C, packed)`.
    let header = unsafe { ptr::read_unaligned(buf.as_ptr() as *const EventHeader) };
    let h_version = header.version;
    let h_type = header.type_;
    let h_timestamp = header.timestamp;
    let h_size = header.size;
    let h_drop = header.drop_count;
    let h_trunc = header.trunc_count;

    if h_version != EVENT_VERSION {
        return Err(format!("unknown event version {}", h_version));
    }
    if (h_size as usize) > buf.len() {
        return Err(format!(
            "header.size={} exceeds delivered {}",
            h_size,
            buf.len()
        ));
    }

    let (kind, event_type, payload) = match h_type {
        EVENT_TYPE_PROCESS_CREATE => (
            "ProcessCreate",
            "process_create",
            encode_process_create(buf, h_size)?,
        ),
        EVENT_TYPE_PROCESS_EXIT => (
            "ProcessExit",
            "process_terminate",
            encode_process_exit(buf, h_size)?,
        ),
        EVENT_TYPE_IMAGE_LOAD => ("ImageLoad", "module_load", encode_image_load(buf, h_size)?),
        EVENT_TYPE_REGISTRY_MODIFY => (
            "RegistryModify",
            "registry_write",
            encode_registry(buf, h_size)?,
        ),
        EVENT_TYPE_THREAD_CREATE => (
            "ThreadCreate",
            "thread_create",
            encode_thread_create(buf, h_size)?,
        ),
        EVENT_TYPE_THREAD_EXIT => ("ThreadExit", "thread_exit", encode_thread_exit(buf, h_size)?),
        EVENT_TYPE_PROCESS_HANDLE_ACCESS => (
            "ProcessHandleAccess",
            "process_handle_access",
            encode_handle_access(buf, h_size)?,
        ),
        other => (
            "Unknown",
            "process_create",
            serde_json::json!({ "type": other, "size": h_size }),
        ),
    };

    Ok(DecodedKernel {
        kind,
        event_type,
        payload,
        ts: format_timestamp(h_timestamp),
        ts_ft_100ns: h_timestamp,
        version: h_version,
        drop_count: h_drop,
        trunc_count: h_trunc,
    })
}

/// Serialise a [`DecodedKernel`] into the NDJSON envelope (`{...}\n`).
fn encode_decoded(d: &DecodedKernel) -> Result<Vec<u8>, String> {
    let process = extract_process(&d.payload);
    let env = KernelEnvelope {
        ts: d.ts.clone(),
        module: "kernel_callback",
        event_type: d.event_type,
        process,
        raw: &d.payload,
        ts_ft_100ns: d.ts_ft_100ns,
        source: "kernel",
        kind: d.kind,
        event_version: d.version,
        drop_count: d.drop_count,
        trunc_count: d.trunc_count,
    };
    let mut out = serde_json::to_vec(&env).map_err(|e| format!("serialize: {e}"))?;
    out.push(b'\n');
    Ok(out)
}

/// Build a detection [`LogEvent`] from a decoded kernel event. Fields are
/// the flattened scalar entries of the `raw` payload (`pid`, `image_path`,
/// `op`, `remote_injection`, …) — exactly the names a `.waza` rule
/// references as `kernel_callback.<event_type>.<field>`.
fn decoded_to_log_event(d: &DecodedKernel) -> LogEvent {
    let fields = match d.payload.as_object() {
        Some(obj) => flatten_fields(obj),
        None => std::collections::HashMap::new(),
    };
    LogEvent {
        module: "kernel_callback".to_string(),
        event_type: d.event_type.to_string(),
        fields,
        timestamp: Instant::now(),
    }
}

/// Encode one raw kernel event into a single-line JSON document.
///
/// Returns `Ok(Some(bytes))` for events the agent's allow-list keeps,
/// `Ok(None)` when the event was filtered out (skip without alloc),
/// `Err(msg)` only on malformed input. Returned bytes are exactly
/// `{...}\n` — ready to append to an NDJSON stream without an extra
/// allocation at the call site.
pub fn encode_kernel_event(buf: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let d = decode_kernel_event(buf)?;
    // Allow-list applied after decode (we need the resolved event_type)
    // but before serialising the full envelope — filtered events are
    // never spooled/shipped. Detection (see encode_kernel_event_and_log)
    // bypasses this on purpose: the filter only gates emission.
    if !crate::filter::allows("kernel_callback", d.event_type) {
        return Ok(None);
    }
    Ok(Some(encode_decoded(&d)?))
}

/// Like [`encode_kernel_event`] but also returns the detection
/// [`LogEvent`] built from the same single parse. Used on the pump
/// thread when the Waza detection layer is enabled, so the hot path
/// parses the packed event only once for both the spool and the engine.
pub fn encode_kernel_event_and_log(buf: &[u8]) -> Result<(Vec<u8>, LogEvent), String> {
    let d = decode_kernel_event(buf)?;
    let line = encode_decoded(&d)?;
    let log = decoded_to_log_event(&d);
    Ok((line, log))
}

unsafe fn read_packed<T: Copy>(buf: &[u8], header_size: u32, name: &str) -> Result<T, String> {
    if (header_size as usize) < size_of::<T>() {
        return Err(format!(
            "{} too small: size={}, expected {}",
            name,
            header_size,
            size_of::<T>()
        ));
    }
    // SAFETY: bounds checked above; layout is `repr(C, packed)`.
    Ok(unsafe { ptr::read_unaligned(buf.as_ptr() as *const T) })
}

unsafe fn decode_path<const N: usize>(arr_ptr: *const [u16; N], len: usize) -> String {
    if len == 0 || len > N {
        return String::new();
    }
    let arr: [u16; N] = unsafe { ptr::read_unaligned(arr_ptr) };
    String::from_utf16_lossy(&arr[..len])
}

fn encode_process_create(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ProcessCreateEvent = unsafe { read_packed(buf, size, "ProcessCreate")? };
    let pid = evt.process_id;
    let ppid = evt.parent_process_id;
    let cpid = evt.creating_process_id;
    let len = evt.image_path_len as usize;
    let image_path = unsafe { decode_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.image_path), len) };
    Ok(serde_json::json!({
        "pid": pid,
        "parent_pid": ppid,
        "creating_pid": cpid,
        "image_path": image_path,
    }))
}

fn encode_process_exit(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ProcessExitEvent = unsafe { read_packed(buf, size, "ProcessExit")? };
    let pid = evt.process_id;
    Ok(serde_json::json!({ "pid": pid }))
}

fn encode_image_load(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ImageLoadEvent = unsafe { read_packed(buf, size, "ImageLoad")? };
    let pid = evt.process_id;
    let base = evt.image_base;
    let img_size = evt.image_size;
    let len = evt.image_path_len as usize;
    let image_path = unsafe { decode_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.image_path), len) };
    // pid==0 marks a kernel-mode image — surface it as an explicit field
    // rather than expecting the consumer to special-case 0.
    let scope = if pid == 0 { "kernel" } else { "user" };
    Ok(serde_json::json!({
        "pid": pid,
        "scope": scope,
        "image_base": base,
        "image_size": img_size,
        "image_path": image_path,
    }))
}

fn registry_op_name(op: u16) -> &'static str {
    match op {
        REGISTRY_OP_SET_VALUE => "SetValue",
        REGISTRY_OP_DELETE_VALUE => "DeleteValue",
        REGISTRY_OP_DELETE_KEY => "DeleteKey",
        REGISTRY_OP_RENAME_KEY => "RenameKey",
        REGISTRY_OP_CREATE_KEY => "CreateKey",
        _ => "Unknown",
    }
}

fn encode_registry(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: RegistryEvent = unsafe { read_packed(buf, size, "RegistryModify")? };
    let pid = evt.process_id;
    let op = evt.operation;
    let value_type = evt.value_type;
    let data_size = evt.data_size;
    let key_len = evt.key_path_len as usize;
    let val_len = evt.value_name_len as usize;
    let prev_len = evt.data_preview_len as usize;

    let key_path =
        unsafe { decode_path::<REGISTRY_KEY_PATH_MAX>(ptr::addr_of!(evt.key_path), key_len) };
    let value_name = if val_len == 0 {
        String::new()
    } else {
        unsafe { decode_path::<REGISTRY_VALUE_NAME_MAX>(ptr::addr_of!(evt.value_name), val_len) }
    };

    // For SetValue, encode the preview as hex — JSON has no native
    // binary type and embedding raw bytes as a UTF-8 string would lose
    // data on non-textual values (REG_BINARY, REG_DWORD, …). Consumers
    // that want to decode a known REG_SZ can hex-decode + utf16-decode.
    let mut payload = serde_json::json!({
        "pid": pid,
        "op": registry_op_name(op),
        "op_code": op,
        "key_path": key_path,
    });
    let obj = payload.as_object_mut().expect("just built as object");
    if !value_name.is_empty() {
        obj.insert("value_name".into(), value_name.into());
    }
    if op == REGISTRY_OP_SET_VALUE {
        let preview_arr: [u8; REGISTRY_DATA_PREVIEW_MAX] =
            unsafe { ptr::read_unaligned(ptr::addr_of!(evt.data_preview)) };
        let take = prev_len.min(REGISTRY_DATA_PREVIEW_MAX);
        let mut hex = String::with_capacity(take * 2);
        for b in &preview_arr[..take] {
            hex.push_str(&format!("{:02x}", b));
        }
        obj.insert("value_type".into(), value_type.into());
        obj.insert("data_size".into(), data_size.into());
        obj.insert("data_preview_hex".into(), hex.into());
        obj.insert(
            "data_truncated".into(),
            (data_size as usize > prev_len).into(),
        );
    }
    Ok(payload)
}

fn encode_thread_create(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ThreadCreateEvent = unsafe { read_packed(buf, size, "ThreadCreate")? };
    let pid = evt.process_id;
    let tid = evt.thread_id;
    let creator = evt.creating_process_id;
    // Tag remote-thread injections explicitly so a SIEM rule can match
    // on a boolean rather than re-deriving the comparison.
    let remote = creator != pid && creator != 0;
    Ok(serde_json::json!({
        "pid": pid,
        "tid": tid,
        "creating_pid": creator,
        "remote_injection": remote,
    }))
}

fn encode_thread_exit(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ThreadExitEvent = unsafe { read_packed(buf, size, "ThreadExit")? };
    let pid = evt.process_id;
    let tid = evt.thread_id;
    Ok(serde_json::json!({
        "pid": pid,
        "tid": tid,
    }))
}

fn encode_handle_access(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ProcessHandleAccessEvent = unsafe { read_packed(buf, size, "ProcessHandleAccess")? };
    let src = evt.source_process_id;
    let dst = evt.target_process_id;
    let desired = evt.desired_access;
    let original = evt.original_desired_access;
    let op = evt.operation;
    let op_name = match op {
        HANDLE_ACCESS_OP_CREATE => "Open",
        HANDLE_ACCESS_OP_DUPLICATE => "Duplicate",
        _ => "Unknown",
    };
    // Pour le SIEM, `process.*` représente toujours l'acteur de l'event.
    // Sur un handle access, l'acteur c'est le SOURCE qui ouvre/duplique
    // un handle vers la cible — c'est ce qu'on veut détecter (ex: un
    // process random qui OpenProcess(lsass) = potentiel credential theft).
    // On duplique src dans `pid` pour que `extract_process` populer
    // automatiquement le bloc top-level `process` ; `source_pid` reste
    // dans `raw` pour les requêtes natives.
    Ok(serde_json::json!({
        "pid": src,
        "source_pid": src,
        "target_pid": dst,
        "desired_access": desired,
        "original_desired_access": original,
        "op": op_name,
        "op_code": op,
    }))
}
