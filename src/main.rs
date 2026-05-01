//! WazabiEDR userland agent — Phase 2.
//!
//! Opens \\.\WazabiEDR and pumps IOCTL_WEDR_GET_EVENT in a loop, printing each
//! event to stdout.

use std::io::{self, Write};
use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, GENERIC_READ, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

// ───────────────────────── IOCTL contract (must match the driver) ─────────────────────────

const IOCTL_WEDR_GET_EVENT: u32 = 0x0022_6000;

const EVENT_VERSION: u16 = 1;

const EVENT_TYPE_PROCESS_CREATE: u16 = 1;
const EVENT_TYPE_PROCESS_EXIT: u16 = 2;

const IMAGE_PATH_MAX: usize = 512;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct EventHeader {
    version: u16,
    type_: u16,
    timestamp: i64,
    size: u32,
    drop_count: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ProcessCreateEvent {
    header: EventHeader,
    process_id: u32,
    parent_process_id: u32,
    creating_process_id: u32,
    image_path: [u16; IMAGE_PATH_MAX],
    image_path_len: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ProcessExitEvent {
    header: EventHeader,
    process_id: u32,
}

// ───────────────────────── Ctrl+C handling ─────────────────────────

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn ctrl_handler(ctrl: u32) -> windows_sys::Win32::Foundation::BOOL {
    if ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT {
        SHUTDOWN.store(true, Ordering::Release);
        1 // TRUE: handled
    } else {
        0
    }
}

// ───────────────────────── Helpers ─────────────────────────

fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn format_timestamp(ft_100ns: i64) -> String {
    // FILETIME = 100ns ticks since 1601-01-01 UTC
    let ft = windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: ft_100ns as u32,
        dwHighDateTime: (ft_100ns >> 32) as u32,
    };
    unsafe {
        let mut st: MaybeUninit<windows_sys::Win32::Foundation::SYSTEMTIME> = MaybeUninit::uninit();
        if FileTimeToSystemTime(&ft, st.as_mut_ptr()) == 0 {
            return format!("ft={}", ft_100ns);
        }
        let st = st.assume_init();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
        )
    }
}

// ───────────────────────── Event parsing ─────────────────────────

fn parse_and_print(buf: &[u8]) -> Result<(), String> {
    if buf.len() < size_of::<EventHeader>() {
        return Err(format!(
            "event too short: {} bytes, expected ≥ {}",
            buf.len(),
            size_of::<EventHeader>()
        ));
    }

    // SAFETY: we just verified the slice covers EventHeader, and the layout is repr(C, packed).
    // Copy fields into locals to avoid creating unaligned references.
    let header = unsafe { ptr::read_unaligned(buf.as_ptr() as *const EventHeader) };
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

    let drop_marker = if h_drop > 0 {
        format!(" (DROPPED {} events since last)", h_drop)
    } else {
        String::new()
    };

    match h_type {
        EVENT_TYPE_PROCESS_CREATE => {
            if (h_size as usize) < size_of::<ProcessCreateEvent>() {
                return Err(format!(
                    "ProcessCreate too small: size={}, expected {}",
                    h_size,
                    size_of::<ProcessCreateEvent>()
                ));
            }
            let evt = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ProcessCreateEvent) };
            let pid = evt.process_id;
            let ppid = evt.parent_process_id;
            let cpid = evt.creating_process_id;
            let path_len = evt.image_path_len as usize;
            // image_path is inside a packed struct → copy out via raw pointer to avoid misaligned ref.
            let image_path = if path_len > 0 && path_len <= IMAGE_PATH_MAX {
                let path_arr: [u16; IMAGE_PATH_MAX] =
                    unsafe { ptr::read_unaligned(ptr::addr_of!(evt.image_path)) };
                String::from_utf16_lossy(&path_arr[..path_len])
            } else {
                String::from("<unknown>")
            };
            println!(
                "[{}] ProcessCreate pid={} ppid={} creator={} path=\"{}\"{}",
                format_timestamp(h_timestamp),
                pid,
                ppid,
                cpid,
                image_path,
                drop_marker
            );
        }
        EVENT_TYPE_PROCESS_EXIT => {
            if (h_size as usize) < size_of::<ProcessExitEvent>() {
                return Err(format!(
                    "ProcessExit too small: size={}, expected {}",
                    h_size,
                    size_of::<ProcessExitEvent>()
                ));
            }
            let evt = unsafe { ptr::read_unaligned(buf.as_ptr() as *const ProcessExitEvent) };
            let pid = evt.process_id;
            println!(
                "[{}] ProcessExit  pid={}{}",
                format_timestamp(h_timestamp),
                pid,
                drop_marker
            );
        }
        other => {
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

// ───────────────────────── Main loop ─────────────────────────

fn main() -> io::Result<()> {
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };

    let path = to_wide_nul(r"\\.\WazabiEDR");

    let handle: HANDLE = unsafe {
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
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    println!("[agent] connected to \\\\.\\WazabiEDR (Ctrl+C to stop)");
    io::stdout().flush().ok();

    let mut buf = vec![0u8; 4096];

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
            // ERROR_OPERATION_ABORTED (995) = handle closed (cleanup) or driver unloaded
            eprintln!("[agent] DeviceIoControl failed: error {}", err);
            break;
        }

        if let Err(e) = parse_and_print(&buf[..returned as usize]) {
            eprintln!("[agent] parse error: {}", e);
        }
        io::stdout().flush().ok();
    }

    unsafe { CloseHandle(handle) };
    println!("[agent] disconnected");
    Ok(())
}
