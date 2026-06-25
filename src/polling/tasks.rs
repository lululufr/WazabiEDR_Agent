//! Scheduled tasks polling — XML file scan.
//!
//! Windows persists every scheduled task as a single XML file under
//! `C:\Windows\System32\Tasks\<author>\<…>\<TaskName>`. The Task
//! Scheduler service rewrites these files on changes, so file mtime +
//! a content hash give us reliable create/modify/delete signals
//! without taking a `ITaskService` COM dependency.
//!
//! Trade-off: a scheduled task created in-memory only (Run-once dialog
//! that completes before our next poll) can be missed. The COM path
//! would catch it; for an MVP-grade EDR the XML scan is the right
//! cost/benefit point.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::envelope::{
    ET_TASK_CREATE, ET_TASK_DELETE, ET_TASK_MODIFY, PersistenceEvent,
};
use super::responsive_sleep;
use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolSubmitter;

const TASKS_ROOT: &str = r"C:\Windows\System32\Tasks";

/// What we keep between snapshots. Path serves as identity; mtime +
/// digest catch modifications. The XML body itself isn't kept — it
/// would dwarf the agent's RSS on a host with thousands of tasks.
#[derive(Clone, PartialEq, Eq)]
struct TaskSnapshot {
    /// Modification time (epoch seconds). 0 on systems where mtime
    /// isn't available; in that case digest alone disambiguates.
    mtime: u64,
    /// FNV-1a 64-bit of the XML body. Cheap, no crypto needed —
    /// collisions between two different task bodies are vanishingly
    /// rare and would only mask a single modify event.
    digest: u64,
    /// Length in bytes. Logged with the event; helps spot artificially
    /// large XML bodies (malware sometimes embeds payloads here).
    size: u64,
}

pub fn run(
    submitter: SpoolSubmitter,
    counter: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    interval: Duration,
    silent_first: bool,
) {
    eprintln!(
        "[polling] scheduled tasks thread started — root {} interval {}s",
        TASKS_ROOT,
        interval.as_secs()
    );

    let mut prev: HashMap<String, TaskSnapshot> = HashMap::new();
    let mut first = true;

    while !SHUTDOWN.load(Ordering::Acquire) {
        // `scan_tasks` returns None when the root directory itself was
        // not enumerable (permission denied, share offline). We MUST
        // distinguish that from "directory exists but is empty",
        // otherwise a transient permission glitch would surface every
        // task as `_delete` on the next successful scan.
        let snapshot = match scan_tasks(Path::new(TASKS_ROOT)) {
            Some(snap) => snap,
            None => {
                eprintln!(
                    "[polling] tasks scan failed (root unreadable) — keeping previous snapshot"
                );
                responsive_sleep(interval);
                continue;
            }
        };

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

fn diff_and_emit(
    prev: &HashMap<String, TaskSnapshot>,
    next: &HashMap<String, TaskSnapshot>,
    submitter: &SpoolSubmitter,
    counter: &AtomicU64,
    dropped: &AtomicU64,
) {
    for (path, snap) in next {
        match prev.get(path) {
            None => emit(
                ET_TASK_CREATE,
                "ScheduledTaskCreate",
                build_payload(path, snap, None),
                submitter,
                counter,
                dropped,
            ),
            Some(old) if old != snap => emit(
                ET_TASK_MODIFY,
                "ScheduledTaskModify",
                build_payload(path, snap, Some(old)),
                submitter,
                counter,
                dropped,
            ),
            _ => {}
        }
    }
    for (path, old) in prev {
        if !next.contains_key(path) {
            emit(
                ET_TASK_DELETE,
                "ScheduledTaskDelete",
                build_payload(path, old, None),
                submitter,
                counter,
                dropped,
            );
        }
    }
}

fn build_payload(
    path: &str,
    snap: &TaskSnapshot,
    prev: Option<&TaskSnapshot>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "task_path": path,
        "task_name": Path::new(path).file_name().map(|s| s.to_string_lossy().to_string()),
        "mtime": snap.mtime,
        "digest": format!("{:016x}", snap.digest),
        "size": snap.size,
    });
    if let Some(p) = prev {
        let obj = v.as_object_mut().unwrap();
        obj.insert(
            "previous".into(),
            serde_json::json!({
                "mtime": p.mtime,
                "digest": format!("{:016x}", p.digest),
                "size": p.size,
            }),
        );
    }
    v
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

/// Walk every file under `root` recursively, hashing each body.
///
/// Returns `None` when the **root directory itself** is unreadable —
/// the caller then keeps the previous snapshot rather than diffing
/// against an empty map and flagging every existing task as deleted.
///
/// Sub-directory failures (a specific task folder we can't enter due
/// to permissions) are silently skipped: that's an acceptable
/// coverage gap, not a snapshot-wide failure.
fn scan_tasks(root: &Path) -> Option<HashMap<String, TaskSnapshot>> {
    let root_iter = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return None,
    };
    let mut out = HashMap::new();
    let mut stack: Vec<PathBuf> = Vec::new();
    // Drain root level first via the already-opened iterator.
    drain(root_iter, &mut stack, &mut out);
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        drain(entries, &mut stack, &mut out);
    }
    Some(out)
}

fn drain(
    iter: fs::ReadDir,
    stack: &mut Vec<PathBuf>,
    out: &mut HashMap<String, TaskSnapshot>,
) {
    for entry in iter.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            stack.push(path);
        } else if meta.is_file() {
            if let Some(snap) = file_snapshot(&path, &meta) {
                out.insert(path.to_string_lossy().into_owned(), snap);
            }
        }
    }
}

fn file_snapshot(path: &Path, meta: &fs::Metadata) -> Option<TaskSnapshot> {
    let body = fs::read(path).ok()?;
    Some(TaskSnapshot {
        mtime: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
        digest: fnv1a_64(&body),
        size: body.len() as u64,
    })
}

/// FNV-1a 64-bit. Tiny, deterministic, no crypto needed. We use it
/// only to spot "body changed since last poll" — any cryptographic
/// hash would be massive overkill for that.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_known_vector() {
        // Wikipedia reference for FNV-1a 64-bit of "foobar".
        assert_eq!(fnv1a_64(b"foobar"), 0x85944171f73967e8);
    }
}
