//! Ctrl+C / Ctrl+Break handling.
//!
//! The OS calls our `ctrl_handler` on a dedicated thread. We:
//!   1. flip `SHUTDOWN` so every polling site sees the request,
//!   2. if a device handle was registered, cancel any in-flight
//!      synchronous I/O against it via `CancelIoEx`. Without (2) the
//!      pump thread stays parked inside `DeviceIoControl` waiting for
//!      a kernel event that never comes (which happens when the driver
//!      is loaded but its event version mismatches the agent's --
//!      every event is rejected silently and the pump never iterates
//!      to re-check SHUTDOWN, so Ctrl+C appears unresponsive).

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use windows_sys::Win32::Foundation::{BOOL, HANDLE};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::Win32::System::IO::CancelIoEx;

/// Set when the user hits Ctrl+C (or Ctrl+Break). The pump loop polls
/// this each iteration to exit cleanly.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Optional device handle to cancel on shutdown. Stored as `isize`
/// because `HANDLE` (a raw pointer) is not `Sync`. `0` means "no
/// handle registered" -- `CancelIoEx(NULL)` is a no-op so a missing
/// registration is harmless.
static DEVICE_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// Register the Ctrl+C handler. Call once at startup.
pub fn install() {
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
}

/// Hand the driver device handle to the shutdown machinery. The
/// Ctrl+C handler will `CancelIoEx` on it to unstick the pump thread
/// when it's blocked in `DeviceIoControl`. Safe to call before / after
/// the handle exists; passing `INVALID_HANDLE_VALUE` (cast to isize)
/// also works, `CancelIoEx` just fails harmlessly.
pub fn register_pump_handle(handle: HANDLE) {
    DEVICE_HANDLE.store(handle as isize, Ordering::Release);
}

unsafe extern "system" fn ctrl_handler(ctrl: u32) -> BOOL {
    if ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT {
        SHUTDOWN.store(true, Ordering::Release);
        // Wake any thread stuck in a synchronous I/O on the pump
        // handle (typically DeviceIoControl(IOCTL_WEDR_GET_EVENT)).
        let raw = DEVICE_HANDLE.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: FFI. CancelIoEx with overlapped=NULL cancels all
            // pending I/O for the handle from any thread. Ignoring the
            // BOOL return: failure (e.g. nothing to cancel) is benign.
            unsafe { CancelIoEx(raw as HANDLE, core::ptr::null()) };
        }
        // Returning TRUE tells the OS we handled the signal -- without
        // it, the default handler would terminate us before we get a
        // chance to close the device cleanly.
        1
    } else {
        0
    }
}
