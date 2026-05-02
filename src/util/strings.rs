//! UTF-16 string helpers for Win32 API calls.

/// Convert a Rust `&str` into a NUL-terminated UTF-16 vector, suitable for
/// any Win32 `*W` API (`CreateFileW`, `RegOpenKeyW`, …).
pub fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
