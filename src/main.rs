//! WazabiEDR userland agent.
//!
//! Connects to the kernel driver and prints incoming events to stdout.
//!
//! # Architecture
//!
//! 1. Install a Ctrl+C handler that flips `shutdown::SHUTDOWN`.
//! 2. Open `\\.\WazabiEDR` (the symlink the driver creates).
//! 3. Loop: blocking `DeviceIoControl(IOCTL_WEDR_GET_EVENT)` → parse → print.
//! 4. On Ctrl+C or fatal error, close the handle and exit.
//!
//! # Module map
//!
//! - [`ipc`]      — wire format, device open/close, pump loop, parser
//! - [`shutdown`] — Ctrl+C flag and handler
//! - [`util`]     — UTF-16 conversion + FILETIME formatting

mod ipc;
mod shutdown;
mod util;

use std::io::{self, Write};

use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};

use crate::ipc::device::{close_device, open_device, run_pump_loop};

fn main() -> io::Result<()> {
    shutdown::install();

    let handle = open_device();
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    println!("[agent] connected to \\\\.\\WazabiEDR (Ctrl+C to stop)");
    io::stdout().flush().ok();

    run_pump_loop(handle);

    close_device(handle);
    println!("[agent] disconnected");
    Ok(())
}
