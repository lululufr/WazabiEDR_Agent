//! Enrichissement user-mode des events kernel.
//!
//! Le driver emet des donnees brutes (SID en SDDL, PID, paths NT). Cote
//! kernel on ne peut pas faire d appels paged depuis un notify callback,
//! donc tout ce qui demande Open*/Lookup* est fait ici, dans l agent.
//!
//! Tous les helpers sont best-effort : un echec retombe sur "champ
//! absent du JSON", l event part quand meme. Caches LRU naifs (clear
//! quand on depasse la borne) pour eviter d ajouter une dependance
//! supplementaire ; le set de SIDs sur une machine est petit et stable,
//! le hit-rate est tres bon.

use std::collections::HashMap;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation, TokenSessionId,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const USER_CACHE_MAX: usize = 4096;

#[derive(Clone)]
struct CachedUser {
    account: String,
    domain: String,
}

fn user_cache() -> &'static Mutex<HashMap<String, Option<CachedUser>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<CachedUser>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resout un SID en (account, domain). `None` si le SID est introuvable
/// (compte supprime, SID local d un autre forest, etc.) — c est OK :
/// l event part avec user_sid brut, sans le nom lisible.
pub fn resolve_user(sid_str: &str) -> Option<(String, String)> {
    if sid_str.is_empty() {
        return None;
    }
    {
        let cache = user_cache().lock().ok()?;
        if let Some(slot) = cache.get(sid_str) {
            return slot.clone().map(|u| (u.account, u.domain));
        }
    }

    let result = lookup_sid(sid_str);

    if let Ok(mut cache) = user_cache().lock() {
        // Eviction grossiere : on vide tout quand on depasse la borne.
        // Pas LRU mais le set de SIDs reels est petit (< 50 sur une
        // machine typique), on remplit puis on hit. Mieux qu un crate.
        if cache.len() > USER_CACHE_MAX {
            cache.clear();
        }
        let cached = result
            .clone()
            .map(|(a, d)| CachedUser { account: a, domain: d });
        cache.insert(sid_str.to_string(), cached);
    }

    result
}

fn lookup_sid(sid_str: &str) -> Option<(String, String)> {
    // ConvertStringSidToSidW veut une chaine UTF-16 NUL-terminated.
    let sid_wide: Vec<u16> = sid_str.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid: *mut core::ffi::c_void = ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut psid) };
    if ok == 0 || psid.is_null() {
        return None;
    }

    let mut name_buf = [0u16; 256];
    let mut domain_buf = [0u16; 256];
    let mut name_len = name_buf.len() as u32;
    let mut domain_len = domain_buf.len() as u32;
    let mut sid_use: SID_NAME_USE = 0;

    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            psid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };

    unsafe {
        LocalFree(psid as _);
    }

    if ok == 0 {
        return None;
    }

    let account = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);
    Some((account, domain))
}

/// Session Windows du process : 0 = Service / Console, >=1 = sessions
/// interactives (Console = souvent 1, RDP = 2+). Distingue immediatement
/// "PowerShell lance depuis RDP" vs "PowerShell lance par un service".
pub fn session_id_for_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }
    let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h_proc.is_null() {
        return None;
    }
    let result = unsafe { query_session_id(h_proc) };
    unsafe {
        CloseHandle(h_proc);
    }
    result
}

unsafe fn query_session_id(h_proc: HANDLE) -> Option<u32> {
    let mut h_tok: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(h_proc, TOKEN_QUERY, &mut h_tok) } == 0 {
        return None;
    }
    let mut session_id: u32 = 0;
    let mut ret_len: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            h_tok,
            TokenSessionId,
            &mut session_id as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        )
    };
    unsafe {
        CloseHandle(h_tok);
    }
    if ok != 0 { Some(session_id) } else { None }
}

/// `true` si le process tourne avec un token eleve (UAC consent passe ou
/// session admin sans UAC). Cruciale en triage : un cmd.exe lance par
/// un user standard vs un cmd.exe eleve, ce sont deux mondes en termes
/// de risque.
pub fn is_elevated_for_pid(pid: u32) -> Option<bool> {
    if pid == 0 {
        return None;
    }
    let h_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h_proc.is_null() {
        return None;
    }
    let result = unsafe { query_elevation(h_proc) };
    unsafe {
        CloseHandle(h_proc);
    }
    result
}

unsafe fn query_elevation(h_proc: HANDLE) -> Option<bool> {
    let mut h_tok: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(h_proc, TOKEN_QUERY, &mut h_tok) } == 0 {
        return None;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len: u32 = 0;
    let ok = unsafe {
        GetTokenInformation(
            h_tok,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    unsafe {
        CloseHandle(h_tok);
    }
    if ok != 0 {
        Some(elevation.TokenIsElevated != 0)
    } else {
        None
    }
}
