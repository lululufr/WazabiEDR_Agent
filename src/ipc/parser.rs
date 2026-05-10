//! Parse raw IOCTL output bytes into human-readable lines on stdout.
//!
//! The on-the-wire structs are `repr(C, packed)`, so every read goes
//! through `ptr::read_unaligned`. Taking ordinary `&` references to fields
//! of a packed struct is undefined behavior in Rust — even for primitives.

use std::mem::size_of;
use std::ptr;

use crate::ipc::events::{
    EVENT_TYPE_IMAGE_LOAD, EVENT_TYPE_PROCESS_CREATE, EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_PROCESS_HANDLE_ACCESS, EVENT_TYPE_REGISTRY_MODIFY, EVENT_TYPE_THREAD_CREATE,
    EVENT_TYPE_THREAD_EXIT, EVENT_VERSION, EventHeader, HANDLE_ACCESS_OP_CREATE,
    HANDLE_ACCESS_OP_DUPLICATE, IMAGE_PATH_MAX, ImageLoadEvent, ProcessCreateEvent,
    ProcessExitEvent, ProcessHandleAccessEvent, REGISTRY_DATA_PREVIEW_MAX,
    REGISTRY_KEY_PATH_MAX, REGISTRY_OP_CREATE_KEY, REGISTRY_OP_DELETE_KEY,
    REGISTRY_OP_DELETE_VALUE, REGISTRY_OP_RENAME_KEY, REGISTRY_OP_SET_VALUE,
    REGISTRY_VALUE_NAME_MAX, RegistryEvent, ThreadCreateEvent, ThreadExitEvent,
};
use crate::util::time::format_timestamp;

/// Per-event context carried through every printer.
///
/// Keeps the printer signatures short and lets us add new fields (an
/// optional event sequence, hostname, …) without touching every site.
struct EventCtx<'a> {
    timestamp: i64,
    /// Already-formatted "(DROPPED N events …)" suffix, empty when the
    /// driver reported zero drops since the last delivered event.
    drop_marker: &'a str,
    /// Same idea for `trunc_count` — formatted once, appended to each
    /// printed line, empty when zero.
    trunc_marker: &'a str,
}

/// Helper around the "size-check + `read_unaligned`" pattern repeated by
/// every printer.
///
/// Returns the parsed event or an error string mentioning `name`. The
/// caller has already validated `header.size <= buf.len()`, so this
/// function only checks against `size_of::<T>()` (i.e. that the driver
/// actually sent at least one full struct).
unsafe fn read_packed_event<T: Copy>(buf: &[u8], header_size: u32, name: &str) -> Result<T, String> {
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

/// Decode a fixed-size UTF-16 path field embedded in a packed struct.
///
/// Returns `<unknown>` for the empty / overlong cases so a missing path
/// is visible in the log without crashing the printer.
unsafe fn decode_packed_path<const N: usize>(arr_ptr: *const [u16; N], len: usize) -> String {
    if len == 0 || len > N {
        return String::from("<unknown>");
    }
    // The array lives inside a packed struct — copy through a raw
    // pointer to avoid forming a misaligned reference, then decode.
    let arr: [u16; N] = unsafe { ptr::read_unaligned(arr_ptr) };
    String::from_utf16_lossy(&arr[..len])
}

/// Parse one event from `buf` and print it to stdout.
///
/// Returns `Err` on schema mismatch (unknown version, truncated buffer,
/// inconsistent `header.size`). The pump loop logs these and keeps going.
pub fn parse_and_print(buf: &[u8]) -> Result<(), String> {
    if buf.len() < size_of::<EventHeader>() {
        return Err(format!(
            "event too short: {} bytes, expected ≥ {}",
            buf.len(),
            size_of::<EventHeader>()
        ));
    }

    // SAFETY: bounds checked above; struct layout is `repr(C, packed)`.
    let header = unsafe { ptr::read_unaligned(buf.as_ptr() as *const EventHeader) };
    // Copy fields into locals — references to packed-struct fields are UB.
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

    // Surface gaps + truncations inline rather than swallowing them: a
    // drop_count > 0 means the kernel ring overflowed, a trunc_count > 0
    // means a path / value name / data-preview was clipped to fit a
    // fixed-size buffer.
    let drop_marker = if h_drop > 0 {
        format!(" (DROPPED {} events since last)", h_drop)
    } else {
        String::new()
    };
    let trunc_marker = if h_trunc > 0 {
        format!(" (TRUNCATED {} fields since last)", h_trunc)
    } else {
        String::new()
    };
    let ctx = EventCtx {
        timestamp: h_timestamp,
        drop_marker: &drop_marker,
        trunc_marker: &trunc_marker,
    };

    match h_type {
        EVENT_TYPE_PROCESS_CREATE => print_process_create(buf, h_size, &ctx)?,
        EVENT_TYPE_PROCESS_EXIT => print_process_exit(buf, h_size, &ctx)?,
        EVENT_TYPE_IMAGE_LOAD => print_image_load(buf, h_size, &ctx)?,
        EVENT_TYPE_REGISTRY_MODIFY => print_registry_modify(buf, h_size, &ctx)?,
        EVENT_TYPE_THREAD_CREATE => print_thread_create(buf, h_size, &ctx)?,
        EVENT_TYPE_THREAD_EXIT => print_thread_exit(buf, h_size, &ctx)?,
        EVENT_TYPE_PROCESS_HANDLE_ACCESS => print_process_handle_access(buf, h_size, &ctx)?,
        other => {
            // Unknown event type: header is already validated, so it is
            // safe to print at least the metadata. Future-proofing for
            // when the driver gains new event types.
            println!(
                "[{}] event type={} size={}{}{}",
                format_timestamp(ctx.timestamp),
                other,
                h_size,
                ctx.drop_marker,
                ctx.trunc_marker
            );
        }
    }

    Ok(())
}

fn print_process_create(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: ProcessCreateEvent =
        unsafe { read_packed_event(buf, size, "ProcessCreate")? };
    let pid = evt.process_id;
    let ppid = evt.parent_process_id;
    let cpid = evt.creating_process_id;
    let path_len = evt.image_path_len as usize;

    let image_path =
        unsafe { decode_packed_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.image_path), path_len) };

    println!(
        "[{}] ProcessCreate pid={} ppid={} creator={} path=\"{}\"{}{}",
        format_timestamp(ctx.timestamp),
        pid,
        ppid,
        cpid,
        image_path,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}

fn print_process_exit(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: ProcessExitEvent = unsafe { read_packed_event(buf, size, "ProcessExit")? };
    let pid = evt.process_id;
    println!(
        "[{}] ProcessExit  pid={}{}{}",
        format_timestamp(ctx.timestamp),
        pid,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}

fn print_image_load(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: ImageLoadEvent = unsafe { read_packed_event(buf, size, "ImageLoad")? };
    let pid = evt.process_id;
    let base = evt.image_base;
    let img_size = evt.image_size;
    let path_len = evt.image_path_len as usize;

    let image_path =
        unsafe { decode_packed_path::<IMAGE_PATH_MAX>(ptr::addr_of!(evt.image_path), path_len) };

    // pid==0 marks a kernel-mode image (driver). Highlight it so it
    // stands out from the user-mode DLL noise.
    let scope = if pid == 0 { "kernel" } else { "user" };

    println!(
        "[{}] ImageLoad    pid={} ({}) base=0x{:x} size=0x{:x} path=\"{}\"{}{}",
        format_timestamp(ctx.timestamp),
        pid,
        scope,
        base,
        img_size,
        image_path,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}

/// Translate a registry-operation discriminant into a short label.
///
/// Unknown values fall back to `"Op?"` rather than panicking — we want
/// future driver versions that add new ops to remain partially readable.
fn registry_op_label(op: u16) -> &'static str {
    match op {
        REGISTRY_OP_SET_VALUE => "SetValue   ",
        REGISTRY_OP_DELETE_VALUE => "DeleteValue",
        REGISTRY_OP_DELETE_KEY => "DeleteKey  ",
        REGISTRY_OP_RENAME_KEY => "RenameKey  ",
        REGISTRY_OP_CREATE_KEY => "CreateKey  ",
        _ => "Op?        ",
    }
}

/// Best-effort human-readable rendering of a `SetValue` payload preview.
///
/// We don't have full `REG_*` type constants here on purpose — only the
/// common ones are decoded; the rest fall back to a hex dump. The agent
/// never *interprets* the value, it just helps a human eyeball it.
fn render_data_preview(value_type: u32, preview: &[u8]) -> String {
    // Windows REG_* constants. Repeated here verbatim to avoid pulling in
    // a Win32 dependency just for the symbolic names.
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    const REG_MULTI_SZ: u32 = 7;
    const REG_QWORD: u32 = 11;

    match value_type {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            // UTF-16 string. Trim a trailing NUL pair (or a tail of NULs)
            // so the rendered output doesn't include them.
            if preview.len() < 2 {
                return String::from("\"\"");
            }
            let units: Vec<u16> = preview
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Strip trailing NUL UTF-16 units.
            let trimmed_end = units
                .iter()
                .rposition(|&u| u != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            let s = String::from_utf16_lossy(&units[..trimmed_end]);
            // For MULTI_SZ, embedded NULs separate strings — surface them
            // as `|` so a single line stays readable.
            let s = s.replace('\0', "|");
            format!("\"{}\"", s)
        }
        REG_DWORD if preview.len() >= 4 => {
            let v = u32::from_le_bytes([preview[0], preview[1], preview[2], preview[3]]);
            format!("0x{:08x} ({})", v, v)
        }
        REG_QWORD if preview.len() >= 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&preview[..8]);
            let v = u64::from_le_bytes(a);
            format!("0x{:016x} ({})", v, v)
        }
        REG_BINARY | _ => {
            // Hex dump. Truncated at 32 bytes to keep stdout lines sane —
            // the full size is already shown next to it via `data_size`.
            const HEX_LIMIT: usize = 32;
            let take = preview.len().min(HEX_LIMIT);
            // 3 chars per byte ("xx ") + maybe a trailing " …" — a 4×
            // capacity avoids any reallocation under the limit.
            let mut out = String::with_capacity(take * 4);
            for (i, b) in preview[..take].iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(&format!("{:02x}", b));
            }
            if preview.len() > HEX_LIMIT {
                out.push_str(" …");
            }
            out
        }
    }
}

fn print_registry_modify(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: RegistryEvent = unsafe { read_packed_event(buf, size, "RegistryModify")? };
    let pid = evt.process_id;
    let op = evt.operation;
    let value_type = evt.value_type;
    let data_size = evt.data_size;
    let key_len = evt.key_path_len as usize;
    let val_len = evt.value_name_len as usize;
    let prev_len = evt.data_preview_len as usize;

    let key_path =
        unsafe { decode_packed_path::<REGISTRY_KEY_PATH_MAX>(ptr::addr_of!(evt.key_path), key_len) };

    // Empty / default value name renders as "(default)" — that is the
    // convention `regedit` uses for the unnamed value of a key.
    let value_name = if val_len == 0 {
        String::from("(default)")
    } else {
        unsafe {
            decode_packed_path::<REGISTRY_VALUE_NAME_MAX>(
                ptr::addr_of!(evt.value_name),
                val_len,
            )
        }
    };

    let label = registry_op_label(op);

    // SetValue is the only op with payload data; everything else just
    // logs key (+ optionally value name).
    if op == REGISTRY_OP_SET_VALUE {
        let preview_arr: [u8; REGISTRY_DATA_PREVIEW_MAX] =
            unsafe { ptr::read_unaligned(ptr::addr_of!(evt.data_preview)) };
        let preview_slice = &preview_arr[..prev_len.min(REGISTRY_DATA_PREVIEW_MAX)];
        let rendered = render_data_preview(value_type, preview_slice);
        // `truncated` is shown only when the preview window was smaller
        // than the actual payload — useful to spot e.g. multi-MiB blobs.
        let truncated = if (data_size as usize) > prev_len {
            format!(" (truncated, real size={} bytes)", data_size)
        } else {
            String::new()
        };
        println!(
            "[{}] Registry {} pid={} key=\"{}\" value=\"{}\" type={} data={}{}{}{}",
            format_timestamp(ctx.timestamp),
            label,
            pid,
            key_path,
            value_name,
            value_type,
            rendered,
            truncated,
            ctx.drop_marker,
            ctx.trunc_marker
        );
    } else if op == REGISTRY_OP_DELETE_VALUE {
        println!(
            "[{}] Registry {} pid={} key=\"{}\" value=\"{}\"{}{}",
            format_timestamp(ctx.timestamp),
            label,
            pid,
            key_path,
            value_name,
            ctx.drop_marker,
            ctx.trunc_marker
        );
    } else {
        // DeleteKey / RenameKey / CreateKey — value-less.
        println!(
            "[{}] Registry {} pid={} key=\"{}\"{}{}",
            format_timestamp(ctx.timestamp),
            label,
            pid,
            key_path,
            ctx.drop_marker,
            ctx.trunc_marker
        );
    }

    Ok(())
}

fn print_thread_create(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: ThreadCreateEvent = unsafe { read_packed_event(buf, size, "ThreadCreate")? };
    let pid = evt.process_id;
    let tid = evt.thread_id;
    let creator = evt.creating_process_id;

    // The signal an EDR cares about: a process spawning a thread inside a
    // *different* process. Highlight it inline so a human eyeballing the
    // feed can spot injection attempts without grepping.
    let injection_marker = if creator != pid && creator != 0 {
        format!(" [REMOTE INJECTION from pid={}]", creator)
    } else {
        String::new()
    };

    println!(
        "[{}] ThreadCreate pid={} tid={} creator={}{}{}{}",
        format_timestamp(ctx.timestamp),
        pid,
        tid,
        creator,
        injection_marker,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}

fn print_thread_exit(buf: &[u8], size: u32, ctx: &EventCtx<'_>) -> Result<(), String> {
    let evt: ThreadExitEvent = unsafe { read_packed_event(buf, size, "ThreadExit")? };
    let pid = evt.process_id;
    let tid = evt.thread_id;
    println!(
        "[{}] ThreadExit   pid={} tid={}{}{}",
        format_timestamp(ctx.timestamp),
        pid,
        tid,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}

/// Decode a Windows `PROCESS_*` access mask into a `|`-separated string of
/// the bits we care about.
///
/// Unknown bits at the top end (the rare `PROCESS_SET_*`, vendor flags,
/// …) are folded into a trailing `0xNNNN` so nothing is silently lost.
fn decode_process_access(mask: u32) -> String {
    // Win32 process-access constants, repeated locally — same rationale
    // as in the driver: avoids a Win32 dependency just for the names.
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_DUP_HANDLE: u32 = 0x0040;
    const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    let known: &[(u32, &str)] = &[
        (PROCESS_TERMINATE, "TERMINATE"),
        (PROCESS_CREATE_THREAD, "CREATE_THREAD"),
        (PROCESS_VM_OPERATION, "VM_OPERATION"),
        (PROCESS_VM_READ, "VM_READ"),
        (PROCESS_VM_WRITE, "VM_WRITE"),
        (PROCESS_DUP_HANDLE, "DUP_HANDLE"),
        (PROCESS_CREATE_PROCESS, "CREATE_PROCESS"),
        (PROCESS_QUERY_INFORMATION, "QUERY_INFORMATION"),
        (PROCESS_SUSPEND_RESUME, "SUSPEND_RESUME"),
        (PROCESS_QUERY_LIMITED_INFORMATION, "QUERY_LIMITED_INFORMATION"),
        (SYNCHRONIZE, "SYNCHRONIZE"),
    ];

    let mut parts: Vec<&str> = Vec::new();
    let mut leftover = mask;
    for &(bit, name) in known {
        if mask & bit != 0 {
            parts.push(name);
            leftover &= !bit;
        }
    }
    if leftover != 0 {
        // Stitch the unknown remainder back at the end as a hex literal
        // so nothing is silently lost.
        let extra = format!("0x{:x}", leftover);
        let mut out = parts.join("|");
        if !out.is_empty() {
            out.push('|');
        }
        out.push_str(&extra);
        out
    } else if parts.is_empty() {
        String::from("0")
    } else {
        parts.join("|")
    }
}

fn print_process_handle_access(
    buf: &[u8],
    size: u32,
    ctx: &EventCtx<'_>,
) -> Result<(), String> {
    let evt: ProcessHandleAccessEvent =
        unsafe { read_packed_event(buf, size, "ProcessHandleAccess")? };
    let src = evt.source_process_id;
    let dst = evt.target_process_id;
    let desired = evt.desired_access;
    let original = evt.original_desired_access;
    let op = evt.operation;

    let label = match op {
        HANDLE_ACCESS_OP_CREATE => "Open ",
        HANDLE_ACCESS_OP_DUPLICATE => "Dup  ",
        _ => "Op?  ",
    };
    let access = decode_process_access(original);

    // Only show the post-filter mask when it differs from the original —
    // that's the case where another callback has already stripped rights.
    let stripped = if desired != original {
        format!(" granted={}", decode_process_access(desired))
    } else {
        String::new()
    };

    println!(
        "[{}] ProcAccess  {} src_pid={} target_pid={} access={}{}{}{}",
        format_timestamp(ctx.timestamp),
        label,
        src,
        dst,
        access,
        stripped,
        ctx.drop_marker,
        ctx.trunc_marker
    );
    Ok(())
}
