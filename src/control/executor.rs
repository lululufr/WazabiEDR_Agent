//! Local executor for server-issued commands.
//!
//! Almost everything stays no-op in this build (the kernel driver is
//! observe-only, no FS mutator, no WFP, etc.) — but `kill_process` is a
//! single `TerminateProcess` syscall and there's no reason to leave it on
//! the table. Implementing it lets the admin console show the full loop
//! green end-to-end: queue a command → agent kills → ack with status
//! `success` → row turns green in the commands history.
//!
//! Adding more executors later: extend the `match` in [`execute`], return
//! an [`ExecutionResult`]. Every other type already gets a sane default
//! "acknowledged only" answer, so no router-side change is needed.

use super::client::CommandOut;
use crate::util::time::now_iso8601;

/// Outcome of running a single command — fed straight to `ack_command`.
pub struct ExecutionResult {
    /// `"success"` (real action ran), `"completed"` (receipt only — no-op
    /// for this command type in this build), or `"failed"`. The server
    /// maps "success"/"completed" → SUCCESS, "failed" → FAILED.
    pub status: &'static str,
    /// Free-form blob persisted server-side for the commands audit row.
    pub result: serde_json::Value,
}

/// Dispatch one command to the right executor.
pub fn execute(cmd: &CommandOut) -> ExecutionResult {
    match cmd.cmd_type.as_str() {
        "kill_process" => execute_kill_process(&cmd.payload),
        // Every other type lands here. We intentionally keep the same
        // "completed" status the old code used so an admin doesn't see a
        // false negative (the queue still drains, audit shows SUCCESS),
        // but the note makes clear no local action was taken.
        other => ExecutionResult {
            status: "completed",
            result: serde_json::json!({
                "executed_at": now_iso8601(),
                "note": "acknowledged by agent (no local executor for this type)",
                "cmd_type": other,
            }),
        },
    }
}

/// Best-effort `TerminateProcess(pid, 1)`. `payload` must contain `pid`
/// (>=1) — anything else fails with a clear reason.
fn execute_kill_process(payload: &serde_json::Value) -> ExecutionResult {
    let pid = match payload.get("pid").and_then(|v| v.as_u64()) {
        Some(p) if p > 0 && p <= u32::MAX as u64 => p as u32,
        _ => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "invalid or missing 'pid' in payload",
                    "got": payload,
                }),
            };
        }
    };

    // PROCESS_TERMINATE is the minimum right for TerminateProcess. We do
    // NOT request PROCESS_ALL_ACCESS to keep the failure modes narrow:
    // either we have the right and it works, or we don't and it doesn't.
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: FFI. The handle is closed unconditionally (no Drop on a raw
    // HANDLE). `OpenProcess` returns null on failure; we check before use.
    let outcome = unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "OpenProcess failed — process may not exist, or insufficient privilege",
                    "pid": pid,
                }),
            };
        }
        let ok = TerminateProcess(h, 1) != 0;
        let _ = CloseHandle(h);
        ok
    };

    if outcome {
        ExecutionResult {
            status: "success",
            result: serde_json::json!({
                "executed_at": now_iso8601(),
                "action": "TerminateProcess",
                "pid": pid,
                "exit_code": 1,
            }),
        }
    } else {
        ExecutionResult {
            status: "failed",
            result: serde_json::json!({
                "error": "TerminateProcess returned 0",
                "pid": pid,
            }),
        }
    }
}
