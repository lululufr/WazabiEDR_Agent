//! Parse raw IOCTL output bytes into human-readable lines on stdout.
//!
//! The on-the-wire structs are `repr(C, packed)`, so every read goes
//! through `ptr::read_unaligned`. Taking ordinary `&` references to fields
//! of a packed struct is undefined behavior in Rust — even for primitives.

use std::mem::size_of;
use std::ptr;

use crate::ipc::events::{
    EVENT_TYPE_IMAGE_LOAD, EVENT_TYPE_PROCESS_CREATE, EVENT_TYPE_PROCESS_EXIT, EVENT_VERSION,
    EventHeader, IMAGE_PATH_MAX, ImageLoadEvent, ProcessCreateEvent, ProcessExitEvent,
};
use crate::util::time::format_timestamp;

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

    // If the driver had to drop events between this one and the previous
    // delivered event, surface that gap inline rather than swallowing it.
    let drop_marker = if h_drop > 0 {
        format!(" (DROPPED {} events since last)", h_drop)
    } else {
        String::new()
    };

    match h_type {
        EVENT_TYPE_PROCESS_CREATE => {
            print_process_create(buf, h_timestamp, h_size, &drop_marker)?;
        }
        EVENT_TYPE_PROCESS_EXIT => {
            print_process_exit(buf, h_timestamp, h_size, &drop_marker)?;
        }
        EVENT_TYPE_IMAGE_LOAD => {
            print_image_load(buf, h_timestamp, h_size, &drop_marker)?;
        }
        other => {
            // Unknown event type: header is already validated, so it is
            // safe to print at least the metadata. Future-proofing for
            // when the driver gains new event types.
            println!(
                "[{}] event type={} size={}{}",
                format_timestamp(h_timestamp),
                other,
                h_size,
                drop_marker
            );
        }
    }

    Ok(())
}

fn print_process_create(
    buf: &[u8],
    timestamp: i64,
    size: u32,
    drop_marker: &str,
) -> Result<(), String> {
    if (size as usize) < size_of::<ProcessCreateEvent>() {
        return Err(format!(
            "ProcessCreate too small: size={}, expected {}",
            size,
            size_of::<ProcessCreateEvent>()
        ));
    }

    // SAFETY: size validated above; layout is `repr(C, packed)`.
    let evt = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ProcessCreateEvent) };
    let pid = evt.process_id;
    let ppid = evt.parent_process_id;
    let cpid = evt.creating_process_id;
    let path_len = evt.image_path_len as usize;

    let image_path = if path_len > 0 && path_len <= IMAGE_PATH_MAX {
        // `image_path` lives inside a packed struct — go through a raw
        // pointer to avoid forming a misaligned reference, then decode.
        let path_arr: [u16; IMAGE_PATH_MAX] =
            unsafe { ptr::read_unaligned(ptr::addr_of!(evt.image_path)) };
        String::from_utf16_lossy(&path_arr[..path_len])
    } else {
        String::from("<unknown>")
    };

    println!(
        "[{}] ProcessCreate pid={} ppid={} creator={} path=\"{}\"{}",
        format_timestamp(timestamp),
        pid,
        ppid,
        cpid,
        image_path,
        drop_marker
    );
    Ok(())
}

fn print_process_exit(
    buf: &[u8],
    timestamp: i64,
    size: u32,
    drop_marker: &str,
) -> Result<(), String> {
    if (size as usize) < size_of::<ProcessExitEvent>() {
        return Err(format!(
            "ProcessExit too small: size={}, expected {}",
            size,
            size_of::<ProcessExitEvent>()
        ));
    }
    let evt = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ProcessExitEvent) };
    let pid = evt.process_id;
    println!(
        "[{}] ProcessExit  pid={}{}",
        format_timestamp(timestamp),
        pid,
        drop_marker
    );
    Ok(())
}

fn print_image_load(
    buf: &[u8],
    timestamp: i64,
    size: u32,
    drop_marker: &str,
) -> Result<(), String> {
    if (size as usize) < size_of::<ImageLoadEvent>() {
        return Err(format!(
            "ImageLoad too small: size={}, expected {}",
            size,
            size_of::<ImageLoadEvent>()
        ));
    }

    // SAFETY: size validated above; layout is `repr(C, packed)`.
    let evt = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ImageLoadEvent) };
    let pid = evt.process_id;
    let base = evt.image_base;
    let img_size = evt.image_size;
    let path_len = evt.image_path_len as usize;

    let image_path = if path_len > 0 && path_len <= IMAGE_PATH_MAX {
        // Same packed-struct gymnastics as print_process_create: copy via
        // raw pointer to avoid forming a misaligned reference.
        let path_arr: [u16; IMAGE_PATH_MAX] =
            unsafe { ptr::read_unaligned(ptr::addr_of!(evt.image_path)) };
        String::from_utf16_lossy(&path_arr[..path_len])
    } else {
        String::from("<unknown>")
    };

    // pid==0 marks a kernel-mode image (driver). Highlight it so it
    // stands out from the user-mode DLL noise.
    let scope = if pid == 0 { "kernel" } else { "user" };

    println!(
        "[{}] ImageLoad    pid={} ({}) base=0x{:x} size=0x{:x} path=\"{}\"{}",
        format_timestamp(timestamp),
        pid,
        scope,
        base,
        img_size,
        image_path,
        drop_marker
    );
    Ok(())
}
