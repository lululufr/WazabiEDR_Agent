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
    COMMAND_LINE_MAX, EVENT_TYPE_IMAGE_LOAD, EVENT_TYPE_PROCESS_CREATE, EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_PROCESS_HANDLE_ACCESS, EVENT_TYPE_REGISTRY_MODIFY, EVENT_TYPE_THREAD_CREATE,
    EVENT_TYPE_THREAD_EXIT, EVENT_VERSION, EventHeader, HANDLE_ACCESS_OP_CREATE,
    HANDLE_ACCESS_OP_DUPLICATE, IMAGE_PATH_MAX, ImageLoadEvent, ProcessCreateEvent,
    ProcessExitEvent, ProcessHandleAccessEvent, REGISTRY_DATA_PREVIEW_MAX, REGISTRY_KEY_PATH_MAX,
    REGISTRY_OP_CREATE_KEY, REGISTRY_OP_DELETE_KEY, REGISTRY_OP_DELETE_VALUE,
    REGISTRY_OP_RENAME_KEY, REGISTRY_OP_SET_VALUE, REGISTRY_VALUE_NAME_MAX, RegistryEvent,
    ThreadCreateEvent, ThreadExitEvent, USER_SID_MAX,
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
    /// Server's `ProcessInfo.command_line`. Populated for `process_create`
    /// events (the kernel ships it via `PS_CREATE_NOTIFY_INFO`); skipped
    /// for events that don't carry one.
    #[serde(skip_serializing_if = "Option::is_none")]
    command_line: Option<String>,
    /// Server's `ProcessInfo.user`. We ship the **SDDL SID** (e.g.
    /// `S-1-5-21-…-1001`) rather than `DOMAIN\user` because resolving in
    /// the kernel callback would require either an LSA lookup (paged,
    /// can recurse into network for domain SIDs) or a user-mode cache
    /// (extra dependency on each event). The server / SIEM is the right
    /// place to do that resolution lazily.
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
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
    let command_line = payload
        .get("command_line")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    let user = payload
        .get("user_sid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned());
    Some(ProcessSlim {
        pid,
        ppid,
        name,
        path,
        command_line,
        user,
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
    let path_len = evt.image_path_len as usize;
    let cmd_len = evt.command_line_len as usize;
    let parent_len = evt.parent_image_path_len as usize;
    let sid_len = evt.user_sid_len as usize;

    let image_path =
        unsafe { decode_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.image_path), path_len) };
    let command_line =
        unsafe { decode_path::<COMMAND_LINE_MAX>(ptr::addr_of!(evt.command_line), cmd_len) };
    let parent_image_path = unsafe {
        decode_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.parent_image_path), parent_len)
    };
    let user_sid = unsafe { decode_path::<USER_SID_MAX>(ptr::addr_of!(evt.user_sid), sid_len) };

    // Pre-compute the parent's basename so detection rules can match on
    // `kernel_callback.process_create.parent_name` without having to
    // re-derive it from the path on every event.
    let parent_image_name = if parent_image_path.is_empty() {
        String::new()
    } else {
        basename(&parent_image_path).unwrap_or_default()
    };

    let mut payload = serde_json::json!({
        "pid": pid,
        "parent_pid": ppid,
        "creating_pid": cpid,
        "image_path": image_path,
    });
    let obj = payload.as_object_mut().expect("just built as object");
    // Each enrichment is skipped when empty — keeps the OpenSearch index
    // mapping stable and avoids storing useless `""` for fields the
    // kernel couldn't resolve.
    if !command_line.is_empty() {
        obj.insert("command_line".into(), command_line.into());
    }
    if !parent_image_path.is_empty() {
        obj.insert("parent_image_path".into(), parent_image_path.into());
    }
    if !parent_image_name.is_empty() {
        obj.insert("parent_image_name".into(), parent_image_name.into());
    }
    if !user_sid.is_empty() {
        obj.insert("user_sid".into(), user_sid.into());
    }
    // Integrity level: skip the 0xFFFFFFFF sentinel so the field isn't
    // indexed for events where the kernel couldn't resolve it. Otherwise
    // expose BOTH the raw RID (machine-friendly, filterable) and the
    // human label (SIEM-friendly, "il:high" queries).
    let il = evt.integrity_level;
    if il != 0xFFFF_FFFF {
        obj.insert("integrity_level".into(), il.into());
        obj.insert(
            "integrity_label".into(),
            integrity_label_str(il).into(),
        );
    }
    Ok(payload)
}

fn integrity_label_str(rid: u32) -> &'static str {
    match rid {
        0x0000 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x2100 => "medium_plus",
        0x3000 => "high",
        0x4000 => "system",
        0x5000 => "protected",
        _ => "unknown",
    }
}

fn encode_process_exit(buf: &[u8], size: u32) -> Result<serde_json::Value, String> {
    let evt: ProcessExitEvent = unsafe { read_packed(buf, size, "ProcessExit")? };
    let pid = evt.process_id;
    let exit_code = evt.exit_code;
    Ok(serde_json::json!({
        "pid": pid,
        "exit_code": exit_code,
        // Convenience flag for SIEM rules: non-zero is either explicit
        // exit code or TerminateProcess from another process.
        "clean_exit": exit_code == 0,
    }))
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

#[cfg(test)]
mod tests {
    //! Wire-format → JSON round-trip tests.
    //!
    //! These exercise `encode_kernel_event` on a hand-built packed buffer
    //! that mimics what the driver actually ships, then asserts the JSON
    //! envelope contains the enrichments the server-side `EventIn` schema
    //! expects (see `WazabiEDR_Server/app/schemas/event.py` +
    //! `_common.py::ProcessInfo`).
    //!
    //! Catching a wire / serializer drift here is way cheaper than
    //! discovering it via `validation skipped, …` lines in production
    //! agent logs.

    use super::*;
    use crate::ipc::events::{
        COMMAND_LINE_MAX, EVENT_TYPE_PROCESS_CREATE, EVENT_TYPE_PROCESS_EXIT, EVENT_VERSION,
        EventHeader, IMAGE_PATH_MAX, ProcessCreateEvent, ProcessExitEvent, USER_SID_MAX,
    };
    use std::mem::size_of;

    /// Write a UTF-16 string into a packed-struct array field via raw
    /// pointers (`&mut field` on a packed struct is UB) and return the
    /// number of u16 units written. Mirrors what the driver does.
    unsafe fn fill_packed_u16<const N: usize>(
        arr_ptr: *mut [u16; N],
        s: &str,
    ) -> u16 {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let n = utf16.len().min(N - 1);
        unsafe {
            let dst = arr_ptr as *mut u16;
            ptr::copy_nonoverlapping(utf16.as_ptr(), dst, n);
        }
        n as u16
    }

    fn fake_process_create_buffer() -> Vec<u8> {
        // Allocate the byte buffer first, then write each packed field
        // through raw pointers — same pattern as the kernel callback
        // (which can't form &mut on packed-struct fields either).
        let size = size_of::<ProcessCreateEvent>();
        let mut bytes = vec![0u8; size];
        let evt = bytes.as_mut_ptr() as *mut ProcessCreateEvent;
        unsafe {
            // Header
            ptr::write_unaligned(
                ptr::addr_of_mut!((*evt).header),
                EventHeader {
                    version: EVENT_VERSION,
                    type_: EVENT_TYPE_PROCESS_CREATE,
                    timestamp: 133_634_820_000_000_000,
                    size: size as u32,
                    drop_count: 0,
                    trunc_count: 0,
                },
            );
            // Numeric tail
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).process_id), 4823u32);
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).parent_process_id), 824u32);
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).creating_process_id), 824u32);
            // String tails
            let img_len = fill_packed_u16::<IMAGE_PATH_MAX>(
                ptr::addr_of_mut!((*evt).image_path),
                r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            );
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).image_path_len), img_len);
            let cmd_len = fill_packed_u16::<COMMAND_LINE_MAX>(
                ptr::addr_of_mut!((*evt).command_line),
                "powershell.exe -EncodedCommand SQBFAFgA",
            );
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).command_line_len), cmd_len);
            let parent_len = fill_packed_u16::<IMAGE_PATH_MAX>(
                ptr::addr_of_mut!((*evt).parent_image_path),
                r"\Device\HarddiskVolume3\Windows\explorer.exe",
            );
            ptr::write_unaligned(
                ptr::addr_of_mut!((*evt).parent_image_path_len),
                parent_len,
            );
            let sid_len = fill_packed_u16::<USER_SID_MAX>(
                ptr::addr_of_mut!((*evt).user_sid),
                "S-1-5-21-1004336348-1177238915-682003330-1001",
            );
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).user_sid_len), sid_len);
            // High integrity (elevated admin) — typical for a powershell.exe
            // launched from an admin desktop session.
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).integrity_level), 0x3000u32);
        }
        bytes
    }

    fn fake_process_exit_buffer(exit_code: i32) -> Vec<u8> {
        let size = size_of::<ProcessExitEvent>();
        let mut bytes = vec![0u8; size];
        let evt = bytes.as_mut_ptr() as *mut ProcessExitEvent;
        unsafe {
            ptr::write_unaligned(
                ptr::addr_of_mut!((*evt).header),
                EventHeader {
                    version: EVENT_VERSION,
                    type_: EVENT_TYPE_PROCESS_EXIT,
                    timestamp: 133_634_820_000_000_001,
                    size: size as u32,
                    drop_count: 0,
                    trunc_count: 0,
                },
            );
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).process_id), 4823u32);
            ptr::write_unaligned(ptr::addr_of_mut!((*evt).exit_code), exit_code);
        }
        bytes
    }

    #[test]
    fn process_create_v6_envelope_matches_server_schema() {
        let buf = fake_process_create_buffer();
        let bytes = encode_kernel_event(&buf)
            .expect("encode should succeed")
            .expect("filter should not drop process_create by default");
        // Strip the trailing newline so serde_json doesn't trip on it.
        let text = std::str::from_utf8(&bytes).expect("UTF-8 NDJSON");
        let text = text.trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");

        // Top-level envelope (mirrors KernelEnvelope → EventIn).
        assert_eq!(v["module"], "kernel_callback");
        assert_eq!(v["event_type"], "process_create");
        assert_eq!(v["source"], "kernel");
        assert_eq!(v["event_version"], EVENT_VERSION);

        // Server-validated `process` block — every field here must exist
        // in `ProcessInfo` or Pydantic will silently drop it.
        let proc = &v["process"];
        assert_eq!(proc["pid"], 4823);
        assert_eq!(proc["ppid"], 824);
        assert_eq!(proc["name"], "powershell.exe");
        assert!(
            proc["path"].as_str().unwrap().ends_with("powershell.exe"),
            "path: {:?}",
            proc["path"],
        );
        assert!(
            proc["command_line"]
                .as_str()
                .unwrap()
                .starts_with("powershell.exe"),
            "command_line: {:?}",
            proc["command_line"],
        );
        assert_eq!(
            proc["user"],
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        );

        // `raw` is the server's free-form bag — everything kernel-specific
        // lives here for SIEM queries (no schema constraint).
        let raw = &v["raw"];
        assert_eq!(raw["pid"], 4823);
        assert_eq!(raw["parent_pid"], 824);
        assert_eq!(raw["creating_pid"], 824);
        assert!(raw["image_path"].as_str().unwrap().contains("powershell"));
        assert!(raw["command_line"].as_str().unwrap().contains("EncodedCommand"));
        assert!(
            raw["parent_image_path"]
                .as_str()
                .unwrap()
                .ends_with("explorer.exe"),
        );
        assert_eq!(raw["parent_image_name"], "explorer.exe");
        assert_eq!(
            raw["user_sid"],
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        );
        // v6 enrichment: integrity_level (raw RID + human label).
        assert_eq!(raw["integrity_level"], 0x3000);
        assert_eq!(raw["integrity_label"], "high");
    }

    #[test]
    fn process_exit_v6_envelope_carries_exit_code() {
        // Non-zero exit — typical of TerminateProcess(STATUS_ACCESS_VIOLATION).
        let buf = fake_process_exit_buffer(0xC000_0005u32 as i32);
        let bytes = encode_kernel_event(&buf)
            .expect("encode should succeed")
            .expect("filter should not drop process_terminate by default");
        let text = std::str::from_utf8(&bytes).unwrap().trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["event_type"], "process_terminate");
        assert_eq!(v["event_version"], EVENT_VERSION);
        // exit_code is i32; the JSON number encodes the signed value.
        assert_eq!(v["raw"]["exit_code"].as_i64().unwrap(), 0xC000_0005u32 as i32 as i64);
        assert_eq!(v["raw"]["clean_exit"], false);

        // Clean exit case.
        let buf = fake_process_exit_buffer(0);
        let bytes = encode_kernel_event(&buf).unwrap().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap().trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["raw"]["exit_code"], 0);
        assert_eq!(v["raw"]["clean_exit"], true);
    }

    #[test]
    fn process_create_rejects_old_version() {
        let mut buf = fake_process_create_buffer();
        // Stamp version 5 (previous schema). Parser must refuse it
        // rather than misinterpret the bytes.
        buf[0..2].copy_from_slice(&5u16.to_le_bytes());
        let err = encode_kernel_event(&buf).expect_err("v5 must be rejected");
        assert!(err.contains("unknown event version"), "got: {err}");
    }
}

