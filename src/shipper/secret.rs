//! Token-at-rest protection.
//!
//! The bearer token used by the shipper to authenticate against the
//! log server is sensitive — anyone who reads `agent.json` and can
//! reach the endpoint can impersonate the agent. We store it
//! DPAPI-encrypted under the **LOCAL_MACHINE** scope: any process on
//! the same Windows host can decrypt (so the SYSTEM-running agent can
//! read it back), but the ciphertext is meaningless on a different
//! machine. Combined with the `agent.json` ACL (Administrators only),
//! this matches the threat model: an attacker who already has admin
//! could exfiltrate the token anyway — DPAPI protects against
//! offline-disk-image leakage and against non-admin users on the
//! machine.
//!
//! The base64 routine here is intentionally hand-rolled. Adding the
//! `base64` crate for ~50 lines of code would pull in dependencies for
//! a feature whose entire purpose is to keep the supply-chain footprint
//! small.

use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

/// `CRYPTPROTECT_LOCAL_MACHINE` — encrypt under the machine key rather
/// than the user key. Lets any process on the host (including a
/// service running as SYSTEM) decrypt the blob. Not defined as a
/// constant in windows-sys 0.59, so we inline the documented value.
///
/// The agent only ever **decrypts** — the matching `CryptProtectData`
/// happens in the operator tooling (PowerShell one-liner documented in
/// `WazabiEDR_Doc/usage/configuring-shipper.md`), so we don't expose a
/// `protect` wrapper here.
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

/// Decrypt a DPAPI ciphertext produced under the LOCAL_MACHINE scope.
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("CryptUnprotectData failed: error {err}"));
    }
    let len = out_blob.cbData as usize;
    let bytes = unsafe { std::slice::from_raw_parts(out_blob.pbData, len) }.to_vec();
    unsafe { LocalFree(out_blob.pbData as _) };
    Ok(bytes)
}

pub fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Strip whitespace defensively so a copy-paste with newlines decodes.
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.len() % 4 != 0 {
        return Err("base64: length not a multiple of 4".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks_exact(4) {
        let mut buf = [0u32; 4];
        let mut pad = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = match b {
                b'A'..=b'Z' => (b - b'A') as u32,
                b'a'..=b'z' => (b - b'a' + 26) as u32,
                b'0'..=b'9' => (b - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                _ => return Err("base64: invalid byte".into()),
            };
        }
        let n = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}
