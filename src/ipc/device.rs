//! Driver device: open `\\.\WazabiEDR` and pump events from it.

use std::io::{self, Write};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, GENERIC_READ, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::ipc::parser::parse_and_print;
use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolHandle;
use crate::util::strings::to_wide_nul;

/// IOCTL code — must match the driver. See
/// `WazabiEDR_Driver::ipc::IOCTL_WEDR_GET_EVENT`.
const IOCTL_WEDR_GET_EVENT: u32 = 0x0022_6000;

/// Initial buffer size. Grown automatically on `STATUS_BUFFER_TOO_SMALL`.
///
/// 4 KiB comfortably fits any current event (`ProcessCreateEvent` is the
/// largest, ~1 KiB).
const INITIAL_BUF: usize = 4096;

/// Open the driver's control device.
///
/// Captures `GetLastError` immediately on failure (so a follow-up Win32
/// call from the caller can't clobber it) and returns it as an
/// `io::Error`. The success path returns the raw `HANDLE` for the
/// caller to use with `DeviceIoControl` etc.
pub fn open_device() -> io::Result<HANDLE> {
    let path = to_wide_nul(r"\\.\WazabiEDR");
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // Read GetLastError BEFORE doing anything else — a single
        // intervening Win32 call (allocation, formatting, …) can
        // overwrite it.
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(handle)
}

/// Pump loop: blocking IOCTL → spool + parse → print, until `SHUTDOWN`
/// is set or a fatal error is returned by the driver.
///
/// `spool` is optional so the agent still works (printing only) if the
/// spool subsystem failed to initialise. When provided, every received
/// event is forwarded to the writer thread *before* parsing — that way
/// a parse error (unknown event type, schema mismatch) doesn't cost us
/// the persisted copy of the raw bytes.
pub fn run_pump_loop(handle: HANDLE, spool: Option<&SpoolHandle>) {
    let mut buf = vec![0u8; INITIAL_BUF];
    // One-shot guard so we only complain about a dead writer thread the
    // first time we notice — repeating the warning every iteration would
    // just spam stderr.
    let writer_warning_emitted = AtomicBool::new(false);

    while !SHUTDOWN.load(Ordering::Acquire) {
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_WEDR_GET_EVENT,
                ptr::null(),
                0,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };

        if ok == FALSE as i32 {
            let err = unsafe { GetLastError() };

            // The driver sets `Information` = required size when our buffer
            // is too small; we receive that value via `returned`. Grow and
            // retry without dropping the (still queued) event.
            if err == ERROR_INSUFFICIENT_BUFFER {
                let needed = returned.max(buf.len() as u32 * 2) as usize;
                eprintln!(
                    "[agent] buffer too small, growing {} → {}",
                    buf.len(),
                    needed
                );
                buf.resize(needed, 0);
                continue;
            }

            // ERROR_OPERATION_ABORTED (995) means our handle was cancelled
            // — usually because we are shutting down or the driver was
            // unloaded. Anything else is a genuine failure.
            eprintln!("[agent] DeviceIoControl failed: error {}", err);
            break;
        }

        let payload = &buf[..returned as usize];

        // Persist BEFORE parsing: if `parse_and_print` rejects the event
        // (unknown version, etc.) we still want the raw bytes preserved
        // for offline analysis. The submission is non-blocking — full
        // channel = drop, accounted in the spool stats.
        //
        // We hand off ownership via `Arc<[u8]>` so the writer thread
        // doesn't need its own copy of the payload bytes.
        if let Some(spool) = spool {
            if !spool.is_alive() && !writer_warning_emitted.swap(true, Ordering::AcqRel) {
                eprintln!(
                    "[agent] spool writer thread is no longer running — \
                     events will accumulate in the kernel ring and \
                     eventually be dropped"
                );
            }
            let shared: Arc<[u8]> = Arc::from(payload);
            let _ = spool.try_submit(shared);
        }

        if let Err(e) = parse_and_print(payload) {
            eprintln!("[agent] parse error: {}", e);
        }
        io::stdout().flush().ok();
    }
}

/// Close the device handle. Idempotent enough for end-of-program.
pub fn close_device(handle: HANDLE) {
    unsafe { CloseHandle(handle) };
}
