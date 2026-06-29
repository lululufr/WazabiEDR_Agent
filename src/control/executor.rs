//! Local executor for server-issued commands.
//!
//! The driver is observe-only — actions live in this user-mode executor.
//! By type:
//!
//! - `kill_process`     → real: `TerminateProcess`.
//! - `quarantine_file`  → real: move the file to `%ProgramData%\WazabiEDR\quarantine\`
//!                        with a `.quarantined` suffix; SHA-256 verified
//!                        when provided.
//! - `scan_now`         → best-effort: enumerates files under `target_path`
//!                        (or `%ProgramData%`) and returns counts. No
//!                        signature engine yet.
//! - `run_shell`        → real: `cmd.exe /c <command>`, captured
//!                        stdout/stderr/exit_code, output capped at 64 KB.
//! - `isolate_endpoint` → real: pushes `WazabiEDR-Isolate-*` rules to
//!                        Windows Firewall via `netsh advfirewall`. ALLOW
//!                        rules win over BLOCK so the server stays
//!                        reachable. User-mode only — bypassable by a
//!                        local admin; WFP kernel layer is S6+.
//! - `unisolate_endpoint` → real: removes the `WazabiEDR-Isolate-*` rules.
//! - `update_agent`     → real: downloads `download_url`, verifies the
//!                        optional SHA-256, then launches the InnoSetup
//!                        bundle with `/SILENT /UPGRADE`. The installer
//!                        overwrites the binaries and restarts the
//!                        service without re-enrolling.
//! - `update_rules`     → ack-only here: the actual re-pull is done by
//!                        the heartbeat loop, which sees the pending
//!                        command and forces a `sync::pull()` even if the
//!                        server-side version hasn't moved.
//! - `restart_module`   → no-op: the agent has no dynamic module loader.
//!                        Acks with a clear note so the admin sees it.
//!
//! Every executor returns an [`ExecutionResult`] that the heartbeat loop
//! pushes back via `POST .../commands/{id}/ack`. The `status` field
//! ("success" / "failed" / "completed") drives how the admin console
//! renders the command row.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
        "quarantine_file" => execute_quarantine_file(&cmd.payload),
        "scan_now" => execute_scan_now(&cmd.payload),
        "run_shell" => execute_run_shell(&cmd.payload),
        "isolate_endpoint" => execute_isolate(&cmd.payload),
        "unisolate_endpoint" => execute_unisolate(),
        "update_agent" => execute_update_agent(&cmd.payload),
        "update_rules" => no_op_ack(
            "re-pull triggered by heartbeat loop (sees this pending cmd and forces sync::pull)",
            &cmd.payload,
        ),
        "restart_module" => no_op_ack("no dynamic module loader — restart_module is a stub", &cmd.payload),
        other => ExecutionResult {
            status: "completed",
            result: serde_json::json!({
                "executed_at": now_iso8601(),
                "note": "acknowledged by agent (unknown command type)",
                "cmd_type": other,
            }),
        },
    }
}

/// Acks the command without doing anything, embedding the original
/// payload + a `note` so the admin sees clearly that nothing was done.
fn no_op_ack(note: &'static str, payload: &serde_json::Value) -> ExecutionResult {
    ExecutionResult {
        status: "completed",
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "note": note,
            "echo_payload": payload,
        }),
    }
}

// ===========================================================================
// kill_process
// ===========================================================================

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

// ===========================================================================
// run_shell — cmd.exe /c <command>, capture stdout/stderr/exit_code
// ===========================================================================

/// Hard cap on stdout+stderr we ship back. The audit row sits in Postgres
/// as JSON (`payload.result`) — there's no reason to let a `dir /s C:\`
/// blow up the row. Truncation is signaled in the result object.
const MAX_SHELL_OUTPUT_BYTES: usize = 64 * 1024;

fn execute_run_shell(payload: &serde_json::Value) -> ExecutionResult {
    let command = match payload.get("command").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "missing or empty 'command' in payload",
                    "got": payload,
                }),
            };
        }
    };
    let timeout_secs = payload
        .get("timeout_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(30)
        .clamp(1, 600);
    let working_dir = payload.get("working_dir").and_then(|v| v.as_str());

    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    let started_at = now_iso8601();
    let t0 = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("spawn cmd.exe failed: {e}"),
                    "command": command,
                }),
            };
        }
    };

    let timeout = Duration::from_secs(timeout_secs);
    let mut timed_out = false;
    let exit_code: Option<i32> = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if t0.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return ExecutionResult {
                    status: "failed",
                    result: serde_json::json!({
                        "error": format!("wait failed: {e}"),
                        "command": command,
                    }),
                };
            }
        }
    };

    let (stdout, stdout_truncated) = read_capped(child.stdout.as_mut(), MAX_SHELL_OUTPUT_BYTES);
    let (stderr, stderr_truncated) = read_capped(child.stderr.as_mut(), MAX_SHELL_OUTPUT_BYTES);
    let duration_ms = t0.elapsed().as_millis() as u64;

    let status_str: &'static str = if timed_out {
        "failed"
    } else if exit_code == Some(0) {
        "success"
    } else {
        // Non-zero exit ≠ agent failure: the shell ran, it just returned
        // an error. We still report "success" because the COMMAND ran —
        // the admin reads exit_code in the result to judge the outcome.
        "success"
    };

    ExecutionResult {
        status: status_str,
        result: serde_json::json!({
            "started_at": started_at,
            "duration_ms": duration_ms,
            "command": command,
            "working_dir": working_dir,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "max_output_bytes": MAX_SHELL_OUTPUT_BYTES,
        }),
    }
}

/// Read up to `cap` bytes from a child pipe. Returns the bytes as a
/// String (lossy on invalid UTF-8 — Windows cmd.exe outputs in the
/// console codepage which isn't always UTF-8) + a "truncated" flag.
fn read_capped<R: Read>(reader: Option<&mut R>, cap: usize) -> (String, bool) {
    let Some(reader) = reader else {
        return (String::new(), false);
    };
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > cap {
                    let take = cap - buf.len();
                    buf.extend_from_slice(&chunk[..take]);
                    truncated = true;
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}

// ===========================================================================
// quarantine_file — move into ProgramData\WazabiEDR\quarantine\
// ===========================================================================

fn execute_quarantine_file(payload: &serde_json::Value) -> ExecutionResult {
    let path = match payload.get("path").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "missing or empty 'path' in payload",
                    "got": payload,
                }),
            };
        }
    };
    let expected_sha = payload.get("sha256").and_then(|v| v.as_str());
    let reason = payload.get("reason").and_then(|v| v.as_str());

    let src = PathBuf::from(path);
    if !src.exists() {
        return ExecutionResult {
            status: "failed",
            result: serde_json::json!({
                "error": "source file does not exist",
                "path": path,
            }),
        };
    }
    if !src.is_file() {
        return ExecutionResult {
            status: "failed",
            result: serde_json::json!({
                "error": "path is not a regular file",
                "path": path,
            }),
        };
    }

    // SHA-256 vérification optionnelle. Si fournie et non matchée, on
    // refuse — l'admin a explicitement nommé un fichier précis et on ne
    // veut pas quarantiner un homonyme légitime.
    let actual_sha = match sha256_file(&src) {
        Ok(s) => s,
        Err(e) => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("sha256 failed: {e}"),
                    "path": path,
                }),
            };
        }
    };
    if let Some(want) = expected_sha {
        if !want.eq_ignore_ascii_case(&actual_sha) {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "sha256 mismatch — refusing to quarantine",
                    "path": path,
                    "expected": want,
                    "actual": actual_sha,
                }),
            };
        }
    }

    let quarantine_dir = quarantine_dir();
    if let Err(e) = fs::create_dir_all(&quarantine_dir) {
        return ExecutionResult {
            status: "failed",
            result: serde_json::json!({
                "error": format!("create quarantine dir failed: {e}"),
                "quarantine_dir": quarantine_dir.display().to_string(),
            }),
        };
    }

    let original_name = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    // Préfixe = sha256 court pour éviter les collisions de noms entre
    // quarantines successives du même nom de fichier (download.exe ×3).
    let short_sha = &actual_sha[..16.min(actual_sha.len())];
    let dst_name = format!("{}__{}.quarantined", short_sha, original_name);
    let dst = quarantine_dir.join(&dst_name);

    if let Err(e) = fs::rename(&src, &dst) {
        // Cross-device fallback: copy + delete.
        if let Err(e2) = fs::copy(&src, &dst).and_then(|_| fs::remove_file(&src)) {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("move failed (rename: {e}, copy+rm: {e2})"),
                    "src": path,
                    "dst": dst.display().to_string(),
                }),
            };
        }
    }

    ExecutionResult {
        status: "success",
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "action": "quarantine_file",
            "src": path,
            "dst": dst.display().to_string(),
            "sha256": actual_sha,
            "reason": reason,
        }),
    }
}

fn quarantine_dir() -> PathBuf {
    let pd = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    pd.join("WazabiEDR").join("quarantine")
}

/// SHA-256 d'un fichier. On hash en pure Rust sans dépendance externe
/// (l'agent évite déjà la dépendance crypto pour réduire la supply chain) —
/// implémentation FIPS 180-4 minimale en bas de fichier.
fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

// ===========================================================================
// scan_now — basic FS walk, no signature engine yet
// ===========================================================================

fn execute_scan_now(payload: &serde_json::Value) -> ExecutionResult {
    let target = payload
        .get("target_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
        });

    if !target.exists() {
        return ExecutionResult {
            status: "failed",
            result: serde_json::json!({
                "error": "target_path does not exist",
                "target_path": target.display().to_string(),
            }),
        };
    }

    let t0 = Instant::now();
    // Borne dure pour ne pas bloquer un agent pendant 10 minutes sur un
    // scan_now opportuniste — le mode "full scan" n'est pas le sujet ici.
    let max_files = 100_000usize;
    let max_duration = Duration::from_secs(120);
    let mut files_seen = 0usize;
    let mut dirs_seen = 0usize;
    let mut bytes_seen: u64 = 0;
    let mut errors = 0usize;
    let truncated = walk(&target, &mut files_seen, &mut dirs_seen, &mut bytes_seen, &mut errors, max_files, max_duration, t0);

    ExecutionResult {
        status: "success",
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "note": "FS walk only — no signature engine in this build",
            "target_path": target.display().to_string(),
            "files_seen": files_seen,
            "dirs_seen": dirs_seen,
            "bytes_seen": bytes_seen,
            "errors": errors,
            "duration_ms": t0.elapsed().as_millis() as u64,
            "truncated": truncated,
            "max_files": max_files,
            "max_duration_secs": max_duration.as_secs(),
        }),
    }
}

fn walk(
    root: &Path,
    files: &mut usize,
    dirs: &mut usize,
    bytes: &mut u64,
    errors: &mut usize,
    max_files: usize,
    max_duration: Duration,
    t0: Instant,
) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if *files >= max_files || t0.elapsed() >= max_duration {
            return true;
        }
        *dirs += 1;
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                *errors += 1;
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    *errors += 1;
                    continue;
                }
            };
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    *errors += 1;
                    continue;
                }
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                *files += 1;
                *bytes += meta.len();
                if *files >= max_files || t0.elapsed() >= max_duration {
                    return true;
                }
            }
        }
    }
    false
}

// ===========================================================================
// isolate_endpoint / unisolate_endpoint — Windows Firewall via netsh
// ===========================================================================
//
// Pourquoi pas juste "add rule action=block" :
//
// Windows Firewall a un stock de centaines d'allow rules par defaut (svchost,
// WinHTTP, ICMP, mDNS, etc.). Ajouter quelques block rules NE LES OVERRIDE
// PAS — les allow continuent a laisser passer leur trafic. Et meme avec
// `set firewallpolicy blockoutbound`, la policy DEFAULT ne s'applique
// qu'aux flux qui ne matchent AUCUNE rule existante. Resultat : la machine
// continue de parler a internet via les allow rules built-in.
//
// La seule maniere fiable avec netsh seul (sans WFP kernel) est :
//
//   1. Export l'etat firewall complet vers un .wfw (backup).
//   2. `netsh advfirewall reset` — vide toutes les rules existantes.
//   3. `set allprofiles state on` + `firewallpolicy blockinbound,blockoutbound`
//      — plus aucune allow ne laisse passer, et la policy default block tout.
//   4. Ajouter NOS allow rules : serveur Wazabi + loopback.
//   5. Unisolate = `netsh advfirewall import <backup.wfw>` — restore
//      EXACTEMENT l'etat d'avant (rules, profils, IPSec, tout).

const ISOLATE_RULE_PREFIX: &str = "WazabiEDR-Isolate";

/// Le backup binaire du firewall. Persiste dans %ProgramData% pour
/// survivre a un reboot de l'agent pendant l'isolation. Si le fichier
/// existe deja a l'execution d'isolate, on ne l'ecrase PAS (re-isolate
/// idempotent — l'etat de reference reste celui d'avant la 1ere
/// isolation).
fn isolation_backup_path() -> PathBuf {
    let pd = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    pd.join("WazabiEDR").join("firewall_pre_isolation.wfw")
}

fn execute_isolate(payload: &serde_json::Value) -> ExecutionResult {
    let allowed_hosts: Vec<String> = payload
        .get("allowed_hosts")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Resolution DNS AVANT le reset firewall — sinon plus de DNS apres.
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    for host in &allowed_hosts {
        match resolve_host_to_ipv4(host) {
            Some(ip) => allowed_ips.push(ip),
            None => unresolved.push(host.clone()),
        }
    }

    let mut actions: Vec<serde_json::Value> = Vec::new();

    // 1) Backup. Si deja present, on respecte (re-isolate ne doit pas
    // ecraser le backup de la 1ere isolation).
    let backup_path = isolation_backup_path();
    let backup_str = backup_path.display().to_string();
    if !backup_path.exists() {
        if let Some(parent) = backup_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        actions.push(serde_json::json!({"step": "backup", "path": backup_str}));
        actions.push(netsh_invoke(&["advfirewall", "export", &backup_str]));
    } else {
        actions.push(serde_json::json!({
            "step": "backup_skipped",
            "reason": "backup already present from a previous isolate",
            "path": backup_str,
        }));
    }

    // 2) Reset des rules existantes (les allow built-in disparaissent).
    actions.push(serde_json::json!({"step": "reset"}));
    actions.push(netsh_invoke(&["advfirewall", "reset"]));

    // 3) Firewall ON + policy block in + out par defaut.
    actions.push(serde_json::json!({"step": "enable_firewall"}));
    actions.push(netsh_invoke(&["advfirewall", "set", "allprofiles", "state", "on"]));
    actions.push(serde_json::json!({"step": "set_policy_block_all"}));
    actions.push(netsh_invoke(&[
        "advfirewall", "set", "allprofiles",
        "firewallpolicy", "blockinbound,blockoutbound",
    ]));

    // 4) Allow rules : loopback (ne pas casser les apps locales).
    actions.push(serde_json::json!({"step": "allow_loopback"}));
    actions.push(run_netsh_add_allow("LoopOut", "out", "127.0.0.1,::1"));
    actions.push(run_netsh_add_allow("LoopIn", "in", "127.0.0.1,::1"));

    // 5) Allow rules : serveur Wazabi + autres hosts whitelistes.
    if !allowed_ips.is_empty() {
        let csv = allowed_ips.join(",");
        actions.push(run_netsh_add_allow("ServerOut", "out", &csv));
        actions.push(run_netsh_add_allow("ServerIn", "in", &csv));
    }

    // 6) DHCP/DHCPv6 — sans ca, le bail expire et l'IP change/disparait.
    // Bloquer DHCP isole bien... jusqu'au prochain renew, ou la machine
    // perd son adresse et plus rien ne marche y compris l'unisolate.
    actions.push(serde_json::json!({"step": "allow_dhcp"}));
    actions.push(netsh_invoke(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}-DHCP-Out", ISOLATE_RULE_PREFIX),
        "dir=out", "action=allow", "enable=yes", "profile=any",
        "protocol=udp", "localport=68,546", "remoteport=67,547",
    ]));
    actions.push(netsh_invoke(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}-DHCP-In", ISOLATE_RULE_PREFIX),
        "dir=in", "action=allow", "enable=yes", "profile=any",
        "protocol=udp", "localport=68,546", "remoteport=67,547",
    ]));

    // On considere "success" si TOUTES les commandes netsh ont ok=true.
    // Les marqueurs {step: ...} sans champ `ok` sont ignores (vrais
    // marqueurs de phase, pas des invocations).
    let all_ok = actions.iter().all(|a| {
        // Si pas de champ "ok" → c'est un marqueur de phase, on ignore.
        a.get("ok")
            .and_then(|v| v.as_bool())
            .map(|b| b)
            .unwrap_or(true)
    });

    ExecutionResult {
        status: if all_ok { "success" } else { "failed" },
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "action": "isolate_endpoint",
            "allowed_hosts": allowed_hosts,
            "allowed_ips": allowed_ips,
            "unresolved_hosts": unresolved,
            "backup_path": backup_str,
            "netsh_actions": actions,
            "reason": payload.get("reason"),
        }),
    }
}

fn execute_unisolate() -> ExecutionResult {
    let mut actions: Vec<serde_json::Value> = Vec::new();
    let backup_path = isolation_backup_path();
    let backup_str = backup_path.display().to_string();

    if backup_path.exists() {
        // Cas nominal : restore EXACTEMENT l'etat firewall pre-isolation
        // (rules, profils, IPSec, policy default). `import` ecrase tout.
        actions.push(serde_json::json!({"step": "import_backup", "path": backup_str}));
        actions.push(netsh_invoke(&["advfirewall", "import", &backup_str]));
        // Cleanup du fichier — la prochaine isolation refera un backup
        // a partir de l'etat courant.
        match std::fs::remove_file(&backup_path) {
            Ok(_) => actions.push(serde_json::json!({"step": "backup_removed"})),
            Err(e) => actions.push(serde_json::json!({
                "step": "backup_remove_failed",
                "error": e.to_string(),
            })),
        }
    } else {
        // Mode degrade : pas de backup. Reset les rules existantes (qui
        // incluent peut-etre des WazabiEDR-Isolate-* d'un ancien run) et
        // remet la policy a la valeur Windows par defaut. Mieux que
        // laisser blockoutbound en place.
        actions.push(serde_json::json!({
            "step": "no_backup_fallback_reset",
            "note": "no isolation backup found at {} — performing a firewall reset",
        }));
        actions.push(netsh_invoke(&["advfirewall", "reset"]));
        actions.push(netsh_invoke(&[
            "advfirewall", "set", "allprofiles", "state", "on",
        ]));
        actions.push(netsh_invoke(&[
            "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,allowoutbound",
        ]));
    }

    let all_ok = actions
        .iter()
        .all(|a| a.get("ok").and_then(|v| v.as_bool()).unwrap_or(true));

    ExecutionResult {
        status: if all_ok { "success" } else { "completed" },
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "action": "unisolate_endpoint",
            "backup_path": backup_str,
            "netsh_actions": actions,
        }),
    }
}

fn run_netsh_add_allow(suffix: &str, dir: &str, remote_ip_csv: &str) -> serde_json::Value {
    let name = format!("{}-{}", ISOLATE_RULE_PREFIX, suffix);
    netsh_invoke(&[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={}", name),
        &format!("dir={}", dir),
        "action=allow",
        "enable=yes",
        "profile=any",
        &format!("remoteip={}", remote_ip_csv),
    ])
}

fn netsh_invoke(args: &[&str]) -> serde_json::Value {
    let mut cmd = Command::new("netsh");
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match cmd.output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            let code = out.status.code();
            serde_json::json!({
                "ok": out.status.success(),
                "exit_code": code,
                "args": args,
                "stdout": stdout.trim(),
                "stderr": stderr.trim(),
            })
        }
        Err(e) => serde_json::json!({
            "ok": false,
            "exit_code": serde_json::Value::Null,
            "args": args,
            "error": format!("spawn netsh failed: {e}"),
        }),
    }
}

/// Résolution best-effort host → IPv4. Si `host` est déjà une IP, le
/// renvoie tel quel. Sinon, fait un `ToSocketAddrs` sur (host, 0) et
/// prend la première IPv4. Renvoie None si rien ne résout.
fn resolve_host_to_ipv4(host: &str) -> Option<String> {
    use std::net::{IpAddr, ToSocketAddrs};
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let with_port = format!("{}:0", host);
    let addrs = with_port.to_socket_addrs().ok()?;
    for sa in addrs {
        if let IpAddr::V4(v4) = sa.ip() {
            return Some(v4.to_string());
        }
    }
    None
}

// ===========================================================================
// update_agent — download bundle + verify sha256 + launch InnoSetup /SILENT /UPGRADE
// ===========================================================================

fn execute_update_agent(payload: &serde_json::Value) -> ExecutionResult {
    let download_url = match payload.get("download_url").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "missing 'download_url' — server must inject INSTALLER_URL",
                    "got": payload,
                }),
            };
        }
    };
    let expected_sha = payload.get("sha256").and_then(|v| v.as_str()).map(str::to_string);
    let target_version = payload.get("target_version").and_then(|v| v.as_str()).unwrap_or("");

    // Téléchargement dans %TEMP% — l'installeur InnoSetup s'extrait
    // ailleurs, donc on n'a pas à rester long ici.
    let tmp_dir = std::env::temp_dir();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let installer_path = tmp_dir.join(format!("WazabiEDR_Setup_{}.exe", stamp));

    let download = match download_to_file(&download_url, &installer_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("download failed: {e}"),
                    "url": download_url,
                }),
            };
        }
    };

    // SHA-256 — refus dur si fourni et non-matché. Sans hash, on logue
    // celui calculé pour traçabilité mais on continue.
    let actual_sha = match sha256_file(&installer_path) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_file(&installer_path);
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("sha256 failed: {e}"),
                    "installer_path": installer_path.display().to_string(),
                }),
            };
        }
    };
    if let Some(want) = &expected_sha {
        if !want.eq_ignore_ascii_case(&actual_sha) {
            let _ = fs::remove_file(&installer_path);
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": "sha256 mismatch — refusing to install",
                    "expected": want,
                    "actual": actual_sha,
                    "installer_path": installer_path.display().to_string(),
                }),
            };
        }
    }

    // Lancement détaché : on doit pouvoir ack la commande AVANT que
    // l'installeur stoppe notre service. Donc on ne `wait()` pas — on
    // spawn et on rend la main.
    let spawn_result = Command::new(&installer_path)
        .args(["/SILENT", "/UPGRADE", "/SUPPRESSMSGBOXES"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    let pid = match spawn_result {
        Ok(child) => child.id(),
        Err(e) => {
            return ExecutionResult {
                status: "failed",
                result: serde_json::json!({
                    "error": format!("spawn installer failed: {e}"),
                    "installer_path": installer_path.display().to_string(),
                    "downloaded_bytes": download,
                    "actual_sha256": actual_sha,
                }),
            };
        }
    };

    ExecutionResult {
        status: "success",
        result: serde_json::json!({
            "executed_at": now_iso8601(),
            "action": "update_agent",
            "target_version": target_version,
            "download_url": download_url,
            "downloaded_bytes": download,
            "sha256_verified": expected_sha.is_some(),
            "sha256": actual_sha,
            "installer_path": installer_path.display().to_string(),
            "installer_pid": pid,
            "note": "installer spawned with /SILENT /UPGRADE — service will restart from new binaries",
        }),
    }
}

/// Télécharge un URL HTTPS vers un fichier local via ureq (déjà au
/// classpath du shipper). Renvoie le nombre d'octets écrits.
fn download_to_file(url: &str, dst: &Path) -> Result<u64, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build();
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    if resp.status() / 100 != 2 {
        return Err(format!("HTTP {} {}", resp.status(), resp.status_text()));
    }
    let mut reader = resp.into_reader();
    let mut file = fs::File::create(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    let written = std::io::copy(&mut reader, &mut file).map_err(|e| e.to_string())?;
    Ok(written)
}

// ===========================================================================
// SHA-256 — implémentation minimale (FIPS 180-4) pour éviter une
// dépendance crypto. Utilisée uniquement par quarantine_file.
// ===========================================================================

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut i = 0;
        while i < data.len() {
            let take = (64 - self.buf_len).min(data.len() - i);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let mut h = Sha256::new();
        h.update(b"abc");
        let got = hex(&h.finalize());
        // RFC 6234 test vector.
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty() {
        let h = Sha256::new();
        let got = hex(&h.finalize());
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_multiblock() {
        // 1000 'a' chars — crosses several 64-byte blocks.
        let data = vec![b'a'; 1000];
        let mut h = Sha256::new();
        h.update(&data);
        let got = hex(&h.finalize());
        assert_eq!(
            got,
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }
}
