//! Windows FILETIME formatting.

use std::mem::MaybeUninit;

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::SystemInformation::GetSystemTime;
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

/// Format a kernel-supplied 100ns FILETIME tick value as ISO-8601 UTC.
///
/// Falls back to the raw integer (`ft=…`) if `FileTimeToSystemTime` fails,
/// so a malformed timestamp doesn't silently disappear from the log.
pub fn format_timestamp(ft_100ns: i64) -> String {
    let ft = FILETIME {
        dwLowDateTime: ft_100ns as u32,
        dwHighDateTime: (ft_100ns >> 32) as u32,
    };
    unsafe {
        let mut st: MaybeUninit<SYSTEMTIME> = MaybeUninit::uninit();
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

/// Current wall-clock time as ISO-8601 UTC (`…Z`).
///
/// Used for the `ts` field of alerts sent to the server: a [`LogEvent`]
/// carries a monotonic `Instant` (good for the correlation window, but
/// not a calendar time), so the wall-clock instant is sampled here at the
/// moment the alert is emitted. `GetSystemTime` already returns UTC, so no
/// `FileTimeToSystemTime` round-trip is needed.
///
/// [`LogEvent`]: crate::detection::event::LogEvent
pub fn now_iso8601() -> String {
    unsafe {
        let mut st: MaybeUninit<SYSTEMTIME> = MaybeUninit::uninit();
        GetSystemTime(st.as_mut_ptr());
        let st = st.assume_init();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
        )
    }
}
