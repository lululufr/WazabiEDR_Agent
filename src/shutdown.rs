//! Ctrl+C / Ctrl+Break handling.
//!
//! The OS calls our `ctrl_handler` on a dedicated thread; we just flip a
//! flag and let the main pump loop notice it on its next iteration. That
//! way we don't have to worry about cancelling an in-flight IOCTL from a
//! signal context.

use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};

/// Set when the user hits Ctrl+C (or Ctrl+Break). The pump loop polls
/// this each iteration to exit cleanly.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Register the Ctrl+C handler. Call once at startup.
pub fn install() {
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
}

unsafe extern "system" fn ctrl_handler(ctrl: u32) -> BOOL {
    if ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT {
        SHUTDOWN.store(true, Ordering::Release);
        // Returning TRUE tells the OS we handled the signal — without it,
        // the default handler would terminate us before we get a chance to
        // close the device cleanly.
        1
    } else {
        0
    }
}
