//! Service Control Manager polling.
//!
//! Walks all services via `EnumServicesStatusExW`, queries config via
//! `QueryServiceConfigW`, and diffs against the previous snapshot to
//! emit:
//!
//! - `service_create` — name not seen before
//! - `service_delete` — name vanished
//! - `service_modify` — `BinaryPathName`, `StartType`, `ServiceType`,
//!   or `ServiceAccount` changed
//! - `service_start` / `service_stop` — `RUNNING ↔ STOPPED` transition
//!
//! We deliberately skip transient state transitions (`START_PENDING`,
//! `STOP_PENDING`) so a single restart doesn't generate 4 events.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, GetLastError};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL,
    SERVICE_WIN32,
};

use super::envelope::{
    ET_SERVICE_CREATE, ET_SERVICE_DELETE, ET_SERVICE_MODIFY, ET_SERVICE_START, ET_SERVICE_STOP,
    PersistenceEvent,
};
use super::responsive_sleep;
use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolSubmitter;

/// Minimal subset of service metadata we diff between snapshots.
/// Adding fields here is the only place to extend coverage.
#[derive(Clone, PartialEq, Eq)]
struct ServiceSnapshot {
    display_name: String,
    binary_path: String,
    start_type: u32,
    service_type: u32,
    account: String,
    running: bool,
}

pub fn run(
    submitter: SpoolSubmitter,
    counter: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    interval: Duration,
    silent_first: bool,
) {
    eprintln!(
        "[polling] services thread started — interval {}s",
        interval.as_secs()
    );

    let mut prev: HashMap<String, ServiceSnapshot> = HashMap::new();
    let mut first = true;
    // Forced full re-config every Nth cycle: a service whose
    // BinaryPath / StartType / Account changed without an associated
    // state transition would otherwise stay undetected forever.
    // 10 × 30s = full re-scan every 5 minutes.
    const FULL_RESCAN_EVERY: u32 = 10;
    let mut cycles_since_full = 0u32;

    while !SHUTDOWN.load(Ordering::Acquire) {
        let full_rescan = cycles_since_full >= FULL_RESCAN_EVERY;
        let snapshot = match enumerate_services(&prev, full_rescan) {
            Some(s) => s,
            None => {
                eprintln!(
                    "[polling] services snapshot failed (last_error={}); skipping cycle",
                    unsafe { GetLastError() }
                );
                responsive_sleep(interval);
                continue;
            }
        };
        if full_rescan {
            cycles_since_full = 0;
        } else {
            cycles_since_full += 1;
        }

        if first && silent_first {
            prev = snapshot;
            first = false;
            responsive_sleep(interval);
            continue;
        }

        diff_and_emit(&prev, &snapshot, &submitter, &counter, &dropped);
        prev = snapshot;
        first = false;
        responsive_sleep(interval);
    }
}

/// One diff outcome — what kind of event to emit for a given service.
/// Splits the pure logic (computing diffs) from the I/O (serialising
/// + submitting), so the diff can be unit-tested without a spool.
#[derive(Debug, PartialEq, Eq, Clone)]
struct DiffEntry {
    event_type: &'static str,
    kind: &'static str,
    name: String,
}

fn compute_diff(
    prev: &HashMap<String, ServiceSnapshot>,
    next: &HashMap<String, ServiceSnapshot>,
) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    // Creates + modifies + state transitions.
    for (name, snap) in next {
        match prev.get(name) {
            None => out.push(DiffEntry {
                event_type: ET_SERVICE_CREATE,
                kind: "ServiceCreate",
                name: name.clone(),
            }),
            Some(old) if old != snap => {
                if old.running != snap.running {
                    out.push(DiffEntry {
                        event_type: if snap.running {
                            ET_SERVICE_START
                        } else {
                            ET_SERVICE_STOP
                        },
                        kind: if snap.running { "ServiceStart" } else { "ServiceStop" },
                        name: name.clone(),
                    });
                }
                if old.binary_path != snap.binary_path
                    || old.start_type != snap.start_type
                    || old.service_type != snap.service_type
                    || old.account != snap.account
                    || old.display_name != snap.display_name
                {
                    out.push(DiffEntry {
                        event_type: ET_SERVICE_MODIFY,
                        kind: "ServiceModify",
                        name: name.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    // Deletes — anything in prev that vanished.
    for name in prev.keys() {
        if !next.contains_key(name) {
            out.push(DiffEntry {
                event_type: ET_SERVICE_DELETE,
                kind: "ServiceDelete",
                name: name.clone(),
            });
        }
    }
    out
}

fn diff_and_emit(
    prev: &HashMap<String, ServiceSnapshot>,
    next: &HashMap<String, ServiceSnapshot>,
    submitter: &SpoolSubmitter,
    counter: &AtomicU64,
    dropped: &AtomicU64,
) {
    for entry in compute_diff(prev, next) {
        let snap_for_payload = next.get(&entry.name).or_else(|| prev.get(&entry.name));
        let prev_snap = if entry.event_type == ET_SERVICE_DELETE {
            None
        } else {
            prev.get(&entry.name)
        };
        if let Some(snap) = snap_for_payload {
            emit(
                entry.event_type,
                entry.kind,
                build_payload(&entry.name, snap, prev_snap),
                submitter,
                counter,
                dropped,
            );
        }
    }
}

fn build_payload(name: &str, snap: &ServiceSnapshot, prev: Option<&ServiceSnapshot>) -> serde_json::Value {
    let mut v = serde_json::json!({
        "name": name,
        "display_name": snap.display_name,
        "binary_path": snap.binary_path,
        "start_type": snap.start_type,
        "start_type_label": start_type_label(snap.start_type),
        "service_type": snap.service_type,
        "account": snap.account,
        "running": snap.running,
    });
    if let Some(p) = prev {
        let obj = v.as_object_mut().unwrap();
        obj.insert(
            "previous".into(),
            serde_json::json!({
                "binary_path": p.binary_path,
                "start_type": p.start_type,
                "service_type": p.service_type,
                "account": p.account,
                "running": p.running,
            }),
        );
    }
    v
}

fn start_type_label(t: u32) -> &'static str {
    match t {
        0 => "boot",
        1 => "system",
        2 => "auto",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

fn emit(
    event_type: &'static str,
    kind: &'static str,
    payload: serde_json::Value,
    submitter: &SpoolSubmitter,
    counter: &AtomicU64,
    dropped: &AtomicU64,
) {
    let evt = PersistenceEvent {
        event_type,
        kind,
        event_version: 1,
        payload,
    };
    if let Some(line) = evt.into_ndjson_line() {
        counter.fetch_add(1, Ordering::Relaxed);
        let bytes: Arc<[u8]> = Arc::from(line);
        if !submitter.try_submit(bytes) {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Take a snapshot of every Win32 service known to the SCM.
///
/// Performance: `QueryServiceConfigW` is an RPC call to SCM — on a host
/// with 300+ services it dominates the syscall cost of a poll cycle.
/// To keep the steady-state cycle cheap, we reuse the config from `prev`
/// whenever a service exists in both snapshots AND the new `running`
/// state matches the old one (i.e. nothing observable changed at this
/// layer). `full_rescan=true` forces re-querying every service — call it
/// periodically (~ every 5 min) to catch silent config edits that
/// don't flip running state.
///
/// Implementation note: the SCM enumeration is racy by design — services
/// can come/go between the size-probing call and the actual fill. We
/// retry up to 3× with a growing buffer when the second call returns
/// `ERROR_MORE_DATA`; beyond that we accept the partial snapshot rather
/// than spinning indefinitely.
fn enumerate_services(
    prev: &HashMap<String, ServiceSnapshot>,
    full_rescan: bool,
) -> Option<HashMap<String, ServiceSnapshot>> {
    const MAX_RETRIES: usize = 3;

    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return None;
        }
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;
        // First call: probe the required buffer size.
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            ptr::null(),
        );
        if bytes_needed == 0 {
            CloseServiceHandle(scm);
            return Some(HashMap::new());
        }

        // Retry loop: grow the buffer until the call succeeds or we
        // exhaust retries. `services_returned` is ONLY trusted on a
        // successful (ok != 0) call — never read from a partial fill.
        let mut buf_size = bytes_needed as usize;
        let mut buf: Vec<u8> = Vec::new();
        let mut ok = 0i32;
        for _ in 0..MAX_RETRIES {
            buf.resize(buf_size, 0u8);
            services_returned = 0;
            resume_handle = 0;
            ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_needed,
                &mut services_returned,
                &mut resume_handle,
                ptr::null(),
            );
            if ok != 0 {
                break;
            }
            if GetLastError() != ERROR_MORE_DATA {
                CloseServiceHandle(scm);
                return None;
            }
            // Grow by at least the kernel's hint, with a 25% headroom
            // so we don't hot-loop on a quick churn.
            buf_size = (bytes_needed as usize).max(buf_size + buf_size / 4);
        }
        if ok == 0 {
            // 3 retries failed — accept defeat, no snapshot this cycle.
            CloseServiceHandle(scm);
            return None;
        }

        let mut map: HashMap<String, ServiceSnapshot> =
            HashMap::with_capacity(services_returned as usize);
        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );
        for entry in entries {
            let name = wide_to_string(entry.lpServiceName);
            if name.is_empty() {
                continue;
            }
            let display_name = wide_to_string(entry.lpDisplayName);
            // SERVICE_RUNNING is the only state we treat as "up". Pending
            // states (start_pending / stop_pending / pause_pending /
            // continue_pending) flip back and forth on a single restart;
            // counting them as "running" would create thrashing events.
            let running = entry.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING;

            // Reuse the previous snapshot's config when the service is
            // already known AND running state is unchanged (and we're
            // not in a forced full-rescan cycle). Saves one SCM RPC
            // per untouched service per cycle.
            let (binary_path, start_type, service_type, account) =
                if !full_rescan
                    && prev
                        .get(&name)
                        .is_some_and(|p| p.running == running && !p.binary_path.is_empty())
                {
                    let p = &prev[&name];
                    (
                        p.binary_path.clone(),
                        p.start_type,
                        p.service_type,
                        p.account.clone(),
                    )
                } else {
                    query_service_config(scm, &name).unwrap_or_default()
                };

            map.insert(
                name.clone(),
                ServiceSnapshot {
                    display_name,
                    binary_path,
                    start_type,
                    service_type,
                    account,
                    running,
                },
            );
        }
        CloseServiceHandle(scm);
        Some(map)
    }
}

/// Open a service by name and fetch its `QUERY_SERVICE_CONFIGW`. Returns
/// `(binary_path, start_type, service_type, account)`. All-empty on
/// failure — we don't want one inaccessible service to abort the snapshot.
///
/// SC_HANDLE cleanup is centralised in a single `cleanup` closure so
/// every early-return path goes through `CloseServiceHandle`. A
/// previous version leaked the handle when `QueryServiceConfigW` failed
/// (rare, but in a long-running agent it would eventually exhaust the
/// SCM's per-process handle pool).
unsafe fn query_service_config(
    scm: windows_sys::Win32::System::Services::SC_HANDLE,
    name: &str,
) -> Option<(String, u32, u32, String)> {
    unsafe {
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let svc = OpenServiceW(scm, wide_name.as_ptr(), SERVICE_QUERY_CONFIG);
        if svc.is_null() {
            return None;
        }
        // From here on, every exit path must Close the handle. A small
        // guard struct gives us RAII without pulling a third-party crate.
        struct CloseOnDrop(windows_sys::Win32::System::Services::SC_HANDLE);
        impl Drop for CloseOnDrop {
            fn drop(&mut self) {
                unsafe { CloseServiceHandle(self.0) };
            }
        }
        let _svc_guard = CloseOnDrop(svc);

        let mut bytes_needed = 0u32;
        let _ = QueryServiceConfigW(svc, ptr::null_mut(), 0, &mut bytes_needed);
        if bytes_needed == 0 {
            return None;
        }
        let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
        let ok = QueryServiceConfigW(
            svc,
            buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW,
            buf.len() as u32,
            &mut bytes_needed,
        );
        if ok == 0 {
            return None;
        }
        let cfg = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
        Some((
            wide_to_string(cfg.lpBinaryPathName),
            cfg.dwStartType,
            cfg.dwServiceType,
            wide_to_string(cfg.lpServiceStartName),
        ))
    }
}

/// Convert a Windows wide-string pointer (UTF-16, NUL-terminated) to a
/// Rust `String`. Returns an empty string for null inputs.
///
/// Hard-caps the scan at 4096 wide-chars (8 KB) — way past anything
/// realistic for a service name / display name / binary path /
/// account name (Windows itself caps these at MAX_PATH variants).
/// Without the cap a corrupted SCM record could send us walking
/// arbitrary memory.
unsafe fn wide_to_string(p: *const u16) -> String {
    const MAX_WIDE_CHARS: usize = 4096;
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len >= MAX_WIDE_CHARS {
                break;
            }
        }
        let slice = std::slice::from_raw_parts(p, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    //! Diff-logic tests. We can't unit-test `enumerate_services`
    //! (needs a real SCM) but `compute_diff` is pure logic over
    //! HashMaps — we exercise every transition shape without any
    //! Windows API or spool/channel involvement.

    use super::*;

    fn snap(running: bool, bin: &str, start: u32) -> ServiceSnapshot {
        ServiceSnapshot {
            display_name: "Test Service".into(),
            binary_path: bin.into(),
            start_type: start,
            service_type: 16,
            account: "LocalSystem".into(),
            running,
        }
    }

    fn types(diff: Vec<DiffEntry>) -> Vec<&'static str> {
        diff.iter().map(|e| e.event_type).collect()
    }

    #[test]
    fn diff_emits_create_for_new_service() {
        let mut next = HashMap::new();
        next.insert("NewSvc".to_string(), snap(true, "C:\\new.exe", 2));
        assert_eq!(types(compute_diff(&HashMap::new(), &next)), vec!["service_create"]);
    }

    #[test]
    fn diff_emits_delete_for_vanished_service() {
        let mut prev = HashMap::new();
        prev.insert("OldSvc".to_string(), snap(true, "C:\\old.exe", 2));
        assert_eq!(types(compute_diff(&prev, &HashMap::new())), vec!["service_delete"]);
    }

    #[test]
    fn diff_emits_start_on_state_transition() {
        let mut prev = HashMap::new();
        prev.insert("Svc".into(), snap(false, "C:\\x.exe", 2));
        let mut next = HashMap::new();
        next.insert("Svc".into(), snap(true, "C:\\x.exe", 2));
        assert_eq!(types(compute_diff(&prev, &next)), vec!["service_start"]);
    }

    #[test]
    fn diff_emits_stop_on_state_transition() {
        let mut prev = HashMap::new();
        prev.insert("Svc".into(), snap(true, "C:\\x.exe", 2));
        let mut next = HashMap::new();
        next.insert("Svc".into(), snap(false, "C:\\x.exe", 2));
        assert_eq!(types(compute_diff(&prev, &next)), vec!["service_stop"]);
    }

    #[test]
    fn diff_emits_modify_on_binary_change() {
        let mut prev = HashMap::new();
        prev.insert("Svc".into(), snap(true, "C:\\old.exe", 2));
        let mut next = HashMap::new();
        next.insert("Svc".into(), snap(true, "C:\\new.exe", 2));
        assert_eq!(types(compute_diff(&prev, &next)), vec!["service_modify"]);
    }

    #[test]
    fn diff_emits_start_and_modify_when_both_change() {
        // Sneaky case: a service goes from "stopped + old binary" to
        // "running + new binary" in one cycle. We expect BOTH events,
        // not just one.
        let mut prev = HashMap::new();
        prev.insert("Svc".into(), snap(false, "C:\\old.exe", 2));
        let mut next = HashMap::new();
        next.insert("Svc".into(), snap(true, "C:\\new.exe", 2));
        let got = types(compute_diff(&prev, &next));
        assert!(
            got.contains(&"service_start") && got.contains(&"service_modify"),
            "got {got:?}",
        );
    }

    #[test]
    fn diff_silent_when_nothing_changed() {
        let mut prev = HashMap::new();
        prev.insert("Svc".into(), snap(true, "C:\\x.exe", 2));
        let next = prev.clone();
        assert!(compute_diff(&prev, &next).is_empty());
    }
}
