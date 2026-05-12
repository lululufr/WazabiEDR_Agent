//! Verify the identity of a process connected to the plugin pipe.
//!
//! Three layers, in order of strength:
//!
//! 1. **OS-level identity** — we ask the kernel who is on the other end
//!    of the pipe and where its image lives on disk. This is unforgeable
//!    by the plugin process itself; lying about it would require already
//!    having SYSTEM, at which point our threat model is moot.
//!
//! 2. **Binary integrity** (SHA-256) — when the manifest carries an
//!    `expected_sha256`, we hash the binary on disk and compare. Closes
//!    the gap "the path matches but the binary was swapped."
//!
//! 3. **Authenticode** — when the manifest carries an `expected_signer`,
//!    we run `WinVerifyTrust` to confirm the binary is signed and the
//!    chain validates. (Subject-DN comparison is a TODO; see the comment
//!    in [`verify_authenticode`].)
//!
//! Layer 1 is always run. Layers 2 and 3 are conditional — a manifest
//! must declare at least one of them (validated at load time in
//! `manifest::ManifestStore::load_one`).

use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider,
    BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData,
    BCryptOpenAlgorithmProvider,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::util::strings::to_wide_nul;

/// Win32 GUID for `WINTRUST_ACTION_GENERIC_VERIFY_V2`. The crate's
/// constant lives behind feature gates that vary release-to-release, so
/// we just hard-code the well-known value to avoid breakage.
///
/// Source: `wintrust.h`.
const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

/// What we discovered about the connected plugin's process.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub pid: u32,
    pub image_path: PathBuf,
}

#[derive(Debug)]
pub enum IdentityError {
    /// Could not even ask Windows who is on the other end of the pipe.
    /// Either the OS API failed or the client disconnected before we
    /// could query — either way, drop them.
    QueryFailed(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueryFailed(s) => write!(f, "{s}"),
        }
    }
}

/// Resolve the connected client's PID + image path from a connected
/// pipe handle. Called as the very first step of every handshake.
pub fn identify_client(pipe: HANDLE) -> Result<ClientIdentity, IdentityError> {
    let mut pid: u32 = 0;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(IdentityError::QueryFailed(format!(
            "GetNamedPipeClientProcessId failed: error {err}"
        )));
    }

    // PROCESS_QUERY_LIMITED_INFORMATION is the minimum right we need
    // and is granted across security boundaries that the heavier
    // PROCESS_QUERY_INFORMATION wouldn't be — important if the plugin
    // runs as a different user.
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc_handle.is_null() {
        let err = unsafe { GetLastError() };
        return Err(IdentityError::QueryFailed(format!(
            "OpenProcess(pid={pid}) failed: error {err}"
        )));
    }

    let mut buf = [0u16; 32 * 1024];
    let mut size: u32 = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(proc_handle) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(IdentityError::QueryFailed(format!(
            "QueryFullProcessImageNameW(pid={pid}) failed: error {err}"
        )));
    }

    let image_path = PathBuf::from(String::from_utf16_lossy(&buf[..size as usize]));
    Ok(ClientIdentity { pid, image_path })
}

// =====================================================================
// SHA-256 over a file (BCrypt / CNG)
// =====================================================================

/// Compute SHA-256 of the file at `path` and return it lowercase-hex.
///
/// Uses BCrypt directly so we don't pull in a `sha2` crate just for
/// this. 64 KiB chunks balance syscall overhead against memory use.
pub fn sha256_file_hex(path: &std::path::Path) -> std::io::Result<String> {
    let wide = to_wide_nul(&path.to_string_lossy());
    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }

    let result = (|| -> std::io::Result<String> {
        let mut alg: BCRYPT_ALG_HANDLE = ptr::null_mut();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
        };
        if status != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptOpenAlgorithmProvider failed: 0x{:x}",
                status as u32
            )));
        }

        let mut hash: BCRYPT_HASH_HANDLE = ptr::null_mut();
        let status =
            unsafe { BCryptCreateHash(alg, &mut hash, ptr::null_mut(), 0, ptr::null(), 0, 0) };
        if status != 0 {
            unsafe { BCryptCloseAlgorithmProvider(alg, 0) };
            return Err(std::io::Error::other(format!(
                "BCryptCreateHash failed: 0x{:x}",
                status as u32
            )));
        }

        let mut buf = [0u8; 64 * 1024];
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    BCryptDestroyHash(hash);
                    BCryptCloseAlgorithmProvider(alg, 0);
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
            if read == 0 {
                break;
            }
            let status = unsafe { BCryptHashData(hash, buf.as_ptr(), read, 0) };
            if status != 0 {
                unsafe {
                    BCryptDestroyHash(hash);
                    BCryptCloseAlgorithmProvider(alg, 0);
                }
                return Err(std::io::Error::other(format!(
                    "BCryptHashData failed: 0x{:x}",
                    status as u32
                )));
            }
        }

        let mut digest = [0u8; 32];
        let status = unsafe { BCryptFinishHash(hash, digest.as_mut_ptr(), digest.len() as u32, 0) };
        unsafe {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        if status != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptFinishHash failed: 0x{:x}",
                status as u32
            )));
        }

        let mut hex = String::with_capacity(64);
        for b in digest {
            hex.push_str(&format!("{:02x}", b));
        }
        Ok(hex)
    })();

    unsafe { CloseHandle(h) };
    result
}

// =====================================================================
// Authenticode
// =====================================================================

/// Verify Authenticode signature on a file using the embedded signature
/// (no catalog support yet). Returns `Ok(())` only if WinVerifyTrust
/// reports success.
///
/// **Subject-DN matching is not yet implemented.** Extracting the
/// signer's certificate subject from a PE on Windows requires walking
/// `CryptQueryObject` → `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` →
/// `CertFindCertificateInStore` → `CertGetNameStringW` and is roughly
/// 200 lines of unsafe FFI. For v1 we treat `expected_signer` as a
/// "signature must validate" gate; the subject string is only stored
/// for human attribution. A future revision should compare the actual
/// subject DN of the embedded signer cert against `expected_signer`.
pub fn verify_authenticode(path: &std::path::Path) -> Result<(), String> {
    let wide = to_wide_nul(&path.to_string_lossy());

    let file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.Anonymous = WINTRUST_DATA_0 {
        pFile: &file_info as *const _ as *mut _,
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status =
        unsafe { WinVerifyTrust(ptr::null_mut(), &mut action, &mut data as *mut _ as *mut _) };

    // Always close the trust state, even on failure — leaking it would
    // pin native handles for the lifetime of the process.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(ptr::null_mut(), &mut action, &mut data as *mut _ as *mut _) };

    if status == 0 {
        Ok(())
    } else {
        Err(format!("WinVerifyTrust failed: 0x{:x}", status as u32))
    }
}
