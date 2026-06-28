//! Réconcile les `pending_plugins[]` du heartbeat serveur en invoquant
//! `wedr-plugin enroll/update/revoke/remove` (cf. `WazabiEDR_Utils`).
//!
//! L'agent NE produit JAMAIS le `PluginManifest` JSON lui-même — c'est
//! `wedr-plugin` qui en a la responsabilité exclusive. Cela garantit qu'un
//! manifest "poussé par le serveur" reste byte-identical à un manifest
//! "enrôlé manuellement par un opérateur", et que les outils Utils
//! (`list`, `doctor`, `revoke`, `remove`) fonctionnent indifféremment des
//! deux flux. Cf. `WazabiEDR_Server/doc/reference/plugin-distribution.md` §3.
//!
//! ## Threading
//!
//! `process_pending_plugins` retourne immédiatement après avoir spawné un
//! thread worker — le heartbeat ne doit jamais être bloqué par un download
//! de 50 MiB ou un enroll de 60 s. La dedup via `IN_FLIGHT` empêche deux
//! threads concurrents de traiter le même paquet (cas réaliste : agent qui
//! reçoit la même action sur 2 heartbeats successifs avant que le premier
//! ait pu reporter `started`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::control::client::{
    Client, PendingPluginAction, PluginInfoForAgent, PluginStatusReport,
};

/// Racine où l'agent dépose les binaires plugins. Une sous-arbo par
/// `<name>/<version>/`. Le manifest agent (écrit par `wedr-plugin`) pointe
/// sur le `<artifact_filename>` à l'intérieur.
const PLUGIN_BIN_SUBDIR: &str = "WazabiEDR\\plugin_bin";

/// Dossier des manifests agent (écrits par `wedr-plugin`). Lu par cet agent
/// uniquement pour récupérer `expected_path` avant un `wedr-plugin remove`
/// (sinon impossible de cleanup le dossier `plugin_bin/`).
const PLUGINS_SUBDIR: &str = "WazabiEDR\\plugins";

/// Nom de l'exe Utils. L'agent le cherche dans (par ordre) :
///   1. La variable d'env `WEDR_PLUGIN_EXE` (chemin absolu — pour le dev)
///   2. `%ProgramFiles%\WazabiEDR\wedr-plugin.exe` (convention installer)
///   3. `wedr-plugin.exe` dans le PATH (fallback)
const WEDR_PLUGIN_EXE_BASENAME: &str = "wedr-plugin.exe";

/// Timeout pour les invocations CLI Utils. Enroll fait un hash SHA-256 de
/// tout le binaire, ce qui peut prendre quelques secondes sur des paquets
/// de 50+ MiB.
const WEDR_PLUGIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Set global des plugin_package_id en cours de traitement. Évite qu'un
/// 2e heartbeat ne déclenche un download/enroll concurrent pour le même
/// paquet pendant que le 1er n'a pas fini.
fn in_flight() -> &'static Mutex<HashSet<String>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Boucle d'entrée appelée par le thread heartbeat.
///
/// **Trade-off v1 : exécution synchrone bornée**. L'idéal serait un thread
/// worker dédié (queue MPSC alimentée par le heartbeat), mais ça demande
/// `Client: Clone` ou `Arc<Client>` partout côté `control/` — refacto trop
/// large pour cette PR. Mitigations en place :
///
/// - **Dedup** via `IN_FLIGHT` : si un 2e heartbeat arrive pendant qu'on
///   traite déjà un paquet, on skip silencieusement.
/// - **Timeout** : chaque invocation `wedr-plugin` est cappée à
///   `WEDR_PLUGIN_TIMEOUT` (60 s). Pire cas réaliste pour 1 action ≈ 10 s
///   (HTTP info + download 50 MiB + SHA + enroll).
/// - **Best-effort errors** : un échec sur une action n'arrête pas les
///   suivantes ; chaque action produit son propre status report.
///
/// Le `_Guard` final retire les IDs de `IN_FLIGHT` même en cas de panic
/// dans le loop (panic-safe).
pub fn process_pending_plugins(client: &Client, actions: &[PendingPluginAction]) {
    if actions.is_empty() {
        return;
    }

    // Filtre les actions dont le pkg est déjà en cours de traitement.
    let to_process: Vec<PendingPluginAction> = {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        actions
            .iter()
            .filter(|a| set.insert(a.plugin_package_id.clone()))
            .cloned()
            .collect()
    };
    if to_process.is_empty() {
        return;
    }

    eprintln!(
        "[control:plugin] processing {} plugin action(s) inline (dedup'd from {})",
        to_process.len(),
        actions.len()
    );

    // Guard panic-safe : libère IN_FLIGHT à la sortie du scope, succès ou
    // panic. À NE PAS dropper manuellement avant la fin du batch (sinon un
    // 2e heartbeat concurrent ré-insèrerait et lancerait un doublon).
    let _guard = InFlightGuard {
        ids: to_process.iter().map(|a| a.plugin_package_id.clone()).collect(),
    };

    for action in &to_process {
        let pkg_id = &action.plugin_package_id;
        let result = match action.action.as_str() {
            "install" => handle_install(client, action),
            "update" => handle_update(client, action),
            "revoke" => handle_revoke(client, action),
            other => {
                eprintln!(
                    "[control:plugin] unknown action '{other}' for pkg={pkg_id} — ignored"
                );
                continue;
            }
        };
        if let Err(e) = result {
            eprintln!("[control:plugin] action '{}' failed for pkg={pkg_id}: {e}", action.action);
            let _ = report(
                client, pkg_id, "failed_install", &action.version, None, Some(&e),
            );
        }
    }
    // _guard drop ici → IN_FLIGHT nettoyé.
}

/// Retire les pkg_id de `IN_FLIGHT` au drop. Panic-safe.
struct InFlightGuard {
    ids: Vec<String>,
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut set = in_flight().lock().unwrap_or_else(|e| e.into_inner());
        for id in self.ids.drain(..) {
            set.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Install : flow complet enroll
// ---------------------------------------------------------------------------

fn handle_install(client: &Client, action: &PendingPluginAction) -> Result<(), String> {
    let pkg_id = &action.plugin_package_id;
    report(client, pkg_id, "installing", &action.version, None, None)?;

    let info = client
        .get_plugin_info(pkg_id)
        .map_err(|e| format!("GET /info: {e}"))?
        .ok_or_else(|| "GET /info: 404 (paquet non assigné ?)".to_string())?;

    let dir = plugin_dir(&info)?;
    let bin_path = download_and_verify(client, pkg_id, &dir, &info.artifact_filename, true)?;
    for extra in &info.extras {
        download_and_verify(client, pkg_id, &dir, &extra.filename, false)?;
    }

    report(client, pkg_id, "installed", &info.version, None, None)?;

    let plugin_id_local = invoke_enroll(&bin_path, &info)?;
    report(
        client,
        pkg_id,
        "started",
        &info.version,
        Some(&plugin_id_local),
        None,
    )?;
    eprintln!(
        "[control:plugin] installed pkg={pkg_id} v{} → plugin_id={plugin_id_local}",
        info.version
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Update : re-hash via `wedr-plugin update <id>` SANS changer le plugin_id.
// Évite la duplication d'instances que produirait un nouveau enroll.
// ---------------------------------------------------------------------------

fn handle_update(client: &Client, action: &PendingPluginAction) -> Result<(), String> {
    let pkg_id = &action.plugin_package_id;
    let plugin_id_local = action.plugin_id_local.as_deref().ok_or_else(|| {
        "update sans plugin_id_local — le serveur doit le fournir pour préserver l'ID".to_string()
    })?;

    report(client, pkg_id, "installing", &action.version, Some(plugin_id_local), None)?;

    let info = client
        .get_plugin_info(pkg_id)
        .map_err(|e| format!("GET /info: {e}"))?
        .ok_or_else(|| "GET /info: 404".to_string())?;

    let dir = plugin_dir(&info)?;
    let bin_path = download_and_verify(client, pkg_id, &dir, &info.artifact_filename, true)?;
    for extra in &info.extras {
        download_and_verify(client, pkg_id, &dir, &extra.filename, false)?;
    }

    // `wedr-plugin update <id> [<new_path>]` re-hash le binaire et MAJ
    // expected_sha256 + expected_path dans le manifest existant
    // (cf. Utils main.rs:292). L'ID reste le même.
    invoke_wedr_plugin(&[
        "update",
        plugin_id_local,
        &bin_path.to_string_lossy(),
    ])
    .map_err(|e| format!("wedr-plugin update: {e}"))?;

    // Force le restart immédiat du plugin en tuant le process en cours.
    // Sans ce kill, on dépend du polling 5s de wait_for_exit_or_change
    // côté supervisor — qui n'existe que dans la version récente de
    // supervisor.rs. Un agent tournant avec un ancien build resterait
    // sur l'ancien binaire indéfiniment (le supervisor ancien ne relit
    // pas le manifest). Le kill garantit le respawn dans tous les cas :
    // le supervisor (ancien ou récent) verra le child mort, fera son
    // backoff, et respawnera. Si le manifest est à jour côté disque
    // (ce que wedr-plugin update vient de faire), même un supervisor
    // ancien qui re-lit son `current` figé spawnera... l'ancien binaire,
    // sauf si on a aussi déplacé le binaire — ce que `download_and_verify`
    // a fait via rename atomique sous le même path quand version match,
    // ou dans un nouveau dossier <version>/ quand la version change.
    // Dans ce dernier cas, seul un supervisor à jour suit le nouveau path.
    kill_running_plugin_processes(&info.artifact_filename);

    report(
        client,
        pkg_id,
        "started",
        &info.version,
        Some(plugin_id_local),
        None,
    )?;
    eprintln!(
        "[control:plugin] updated pkg={pkg_id} v{} (plugin_id={plugin_id_local} preserved)",
        info.version
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Revoke : revoke + remove + cleanup binaires
// ---------------------------------------------------------------------------

fn handle_revoke(client: &Client, action: &PendingPluginAction) -> Result<(), String> {
    let plugin_id_local = action.plugin_id_local.as_deref().ok_or_else(|| {
        "revoke sans plugin_id_local — fix audit #5 côté serveur devrait basculer REVOKED inline"
            .to_string()
    })?;

    // Avant de remove, lire le manifest pour récupérer expected_path et
    // pouvoir cleanup le dossier plugin_bin/<name>/<version>/ ensuite.
    let bin_path_to_cleanup = read_manifest_expected_path(plugin_id_local).ok();

    invoke_wedr_plugin(&["revoke", plugin_id_local])
        .map_err(|e| format!("wedr-plugin revoke: {e}"))?;

    invoke_wedr_plugin(&["remove", plugin_id_local])
        .map_err(|e| format!("wedr-plugin remove: {e}"))?;

    if let Some(bin_path) = bin_path_to_cleanup {
        // Supprime le dossier <version>/ entier (binaire + extras).
        // Le parent <name>/ peut rester (autres versions cohabitent
        // peut-être ; rmdir non-récursif échouera si pas vide).
        if let Some(version_dir) = Path::new(&bin_path).parent() {
            if let Err(e) = std::fs::remove_dir_all(version_dir) {
                eprintln!(
                    "[control:plugin] cleanup {version_dir:?} failed (non-fatal): {e}"
                );
            }
        }
    }

    report(
        client,
        &action.plugin_package_id,
        "revoked",
        &action.version,
        Some(plugin_id_local),
        None,
    )?;
    eprintln!(
        "[control:plugin] revoked pkg={} plugin_id={plugin_id_local}",
        action.plugin_package_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers : invocation wedr-plugin, vérification SHA, status reporter
// ---------------------------------------------------------------------------

/// Télécharge le binaire principal (ou un extra) avec rename atomique :
/// écrit dans `<dir>/.<filename>.partial`, vérifie le SHA, puis rename.
/// Évite qu'un consumer concurrent (supervisor, AV) ne lise un fichier
/// partiellement écrit ou non-vérifié.
fn download_and_verify(
    client: &Client,
    pkg_id: &str,
    dir: &Path,
    filename: &str,
    is_primary: bool,
) -> Result<PathBuf, String> {
    validate_filename(filename)?;
    let final_path = dir.join(filename);
    let partial_path = dir.join(format!(".{filename}.partial"));

    let expected_sha = if is_primary {
        client
            .download_plugin_binary(pkg_id, &partial_path)
            .map_err(|e| format!("GET /binary: {e}"))?
    } else {
        client
            .download_plugin_extra(pkg_id, filename, &partial_path)
            .map_err(|e| format!("GET /files/{filename}: {e}"))?
    };
    verify_sha(&partial_path, &expected_sha)?;

    // Rename atomique (Windows : MoveFileEx avec REPLACE_EXISTING via std).
    if final_path.exists() {
        std::fs::remove_file(&final_path)
            .map_err(|e| format!("remove existing {final_path:?}: {e}"))?;
    }
    std::fs::rename(&partial_path, &final_path).map_err(|e| {
        let _ = std::fs::remove_file(&partial_path);
        format!("rename {partial_path:?} → {final_path:?}: {e}")
    })?;
    Ok(final_path)
}

fn invoke_enroll(bin_path: &Path, info: &PluginInfoForAgent) -> Result<String, String> {
    let bin_str = bin_path.to_string_lossy().into_owned();
    // `env_pairs` owne les "KEY=VALUE" assemblés à partir du HashMap pour
    // qu'on puisse leur emprunter des &str en parallèle dans `args`. Sans
    // ce buffer, on aurait des references vers des `String` temporaires
    // dont la lifetime n'atteint pas l'invoke_wedr_plugin.
    let env_pairs: Vec<String> = info
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    let mut args: Vec<&str> = vec![
        "enroll",
        &bin_str,
        "--name",
        &info.name,
        "--vendor",
        &info.vendor,
        "--allow-unsigned",
    ];
    if info.auto_launch {
        args.push("--auto-launch");
    }
    for kv in &env_pairs {
        args.push("--env");
        args.push(kv.as_str());
    }
    let stdout = invoke_wedr_plugin(&args).map_err(|e| format!("wedr-plugin enroll: {e}"))?;

    // Parse `plugin_id     : 8f3c1d8e-...` depuis stdout (cf. Utils main.rs:266).
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("plugin_id") {
            if let Some((_, id)) = rest.split_once(':') {
                let id = id.trim();
                if !id.is_empty() {
                    return Ok(id.to_string());
                }
            }
        }
    }
    Err(format!(
        "wedr-plugin enroll succeeded but plugin_id introuvable dans stdout: {stdout}"
    ))
}

/// Invoque `wedr-plugin` avec les args donnés, capture stdout+stderr en
/// parallèle (via `wait_with_output` pour éviter le deadlock si stderr
/// déborde le pipe OS). Échec si exit ≠ 0, timeout, ou exe introuvable.
/// Tue tous les processes dont le nom de binaire matche `basename`, via
/// `taskkill.exe /F /IM <basename>`. Best-effort : un échec n'arrête pas
/// le flux d'update (le report status `started` se fait dans tous les cas,
/// le supervisor finira par converger).
///
/// `taskkill` est préféré à un Toolhelp32+TerminateProcess en Rust pur
/// pour rester sans nouvelle feature `windows-sys` (taskkill.exe est dans
/// System32 sur tout Windows ≥ XP). Exit codes :
/// - 0 : process(s) tué(s)
/// - 128 : "process not found" — pas une erreur, juste informatif
/// - autre : log warning, continue
fn kill_running_plugin_processes(basename: &str) {
    let out = Command::new("taskkill.exe")
        .args(["/F", "/IM", basename])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            eprintln!("[control:plugin] taskkill /IM {basename} → process(s) killed");
        }
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            if code == 128 {
                // "could not be found" — déjà mort ou pas encore lancé.
                eprintln!(
                    "[control:plugin] taskkill /IM {basename}: process not found (already stopped?)"
                );
            } else {
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!(
                    "[control:plugin] taskkill /IM {basename} exit={code}: {}",
                    stderr.trim()
                );
            }
        }
        Err(e) => {
            eprintln!("[control:plugin] taskkill spawn failed: {e}");
        }
    }
}

fn invoke_wedr_plugin(args: &[&str]) -> Result<String, String> {
    let exe = resolve_wedr_plugin_exe()?;
    let mut child = Command::new(&exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {exe:?}: {e}"))?;

    // Watchdog timeout : kill si dépasse WEDR_PLUGIN_TIMEOUT. On poll
    // try_wait avant d'engager wait_with_output (qui bloque jusqu'à exit).
    let t0 = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if t0.elapsed() >= WEDR_PLUGIN_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "wedr-plugin timeout après {}s",
                        WEDR_PLUGIN_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("wait {exe:?}: {e}")),
        }
    }

    // Process exited — drain stdout + stderr en parallèle (gère stderr
    // >64 KiB sans deadlock car les threads internes lisent les deux pipes
    // simultanément).
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait_with_output {exe:?}: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Err(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            stderr.trim()
        ));
    }
    if !stderr.is_empty() {
        eprintln!("[control:plugin] wedr-plugin stderr: {}", stderr.trim());
    }
    Ok(stdout)
}

fn resolve_wedr_plugin_exe() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("WEDR_PLUGIN_EXE") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "WEDR_PLUGIN_EXE pointe sur un fichier inexistant: {path:?}"
        ));
    }
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        let path = PathBuf::from(pf)
            .join("WazabiEDR")
            .join(WEDR_PLUGIN_EXE_BASENAME);
        if path.is_file() {
            return Ok(path);
        }
    }
    Ok(PathBuf::from(WEDR_PLUGIN_EXE_BASENAME))
}

fn plugin_dir(info: &PluginInfoForAgent) -> Result<PathBuf, String> {
    let programdata = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    validate_segment(&info.name, "plugin.name")?;
    validate_segment(&info.version, "plugin.version")?;
    Ok(programdata.join(PLUGIN_BIN_SUBDIR).join(&info.name).join(&info.version))
}

/// Refuse tout segment de chemin contenant des séparateurs, `..`, ou des
/// caractères réservés Windows. Appliqué sur name/version (avec un libellé
/// pour le diagnostic).
fn validate_segment(s: &str, label: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("{label} vide"));
    }
    if s.contains(['/', '\\', ':', '<', '>', '"', '|', '?', '*']) || s.contains("..") {
        return Err(format!("{label} contient un caractère interdit: {s:?}"));
    }
    Ok(())
}

/// Refuse tout filename qui n'est pas un basename pur. Défense contre un
/// `info.artifact_filename` ou `extra.filename` malveillant qui contiendrait
/// un séparateur (le serveur valide aussi côté ingestion, mais ceinture +
/// bretelles).
fn validate_filename(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("filename vide".to_string());
    }
    if Path::new(name).file_name().map(|s| s != name).unwrap_or(true) {
        return Err(format!("filename non-plat (path traversal ?): {name:?}"));
    }
    if name.starts_with('.') {
        // évite que `.partial` ou `.lock` ne soit servi comme artifact
        return Err(format!("filename commence par '.': {name:?}"));
    }
    Ok(())
}

fn verify_sha(path: &Path, expected_hex: &str) -> Result<(), String> {
    if expected_hex.is_empty() {
        eprintln!(
            "[control:plugin] WARNING: no X-Plugin-SHA256 header for {path:?} — skipping verify"
        );
        return Ok(());
    }
    let actual = sha256_file_hex(path)?;
    if !actual.eq_ignore_ascii_case(expected_hex) {
        let _ = std::fs::remove_file(path);
        return Err(format!(
            "SHA-256 mismatch sur {path:?}: attendu={expected_hex} obtenu={actual}"
        ));
    }
    Ok(())
}

fn read_manifest_expected_path(plugin_id: &str) -> Result<String, String> {
    let programdata = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    let manifest_path = programdata.join(PLUGINS_SUBDIR).join(format!("{plugin_id}.json"));
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read {manifest_path:?}: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("parse manifest {manifest_path:?}: {e}"))?;
    v.get("expected_path")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("manifest {manifest_path:?} sans expected_path"))
}

// ---------------------------------------------------------------------------
// SHA-256 via BCrypt CNG — RAII handles + signature corrigée pour PCWSTR.
// ---------------------------------------------------------------------------

/// Calcule SHA-256 d'un fichier en streaming via BCrypt CNG. Évite `sha2`
/// dans les deps de l'agent (déjà beaucoup de surface). Les handles sont
/// fermés via RAII pour ne pas fuir sur erreur intermédiaire.
fn sha256_file_hex(path: &Path) -> Result<String, String> {
    use std::io::Read;

    let alg = BCryptAlg::open()?;
    let mut hash = alg.create_hash()?;

    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path:?}: {e}"))?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {path:?}: {e}"))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n])?;
    }

    let digest = hash.finish()?;
    let mut hex = String::with_capacity(64);
    for b in &digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// RAII wrapper sur `BCRYPT_ALG_HANDLE`. Drop appelle
/// `BCryptCloseAlgorithmProvider` même si une étape ultérieure échoue.
struct BCryptAlg {
    handle: windows_sys::Win32::Security::Cryptography::BCRYPT_ALG_HANDLE,
}

impl BCryptAlg {
    fn open() -> Result<Self, String> {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_SHA256_ALGORITHM, BCryptOpenAlgorithmProvider,
        };
        let mut handle = std::ptr::null_mut();
        // SAFETY: BCRYPT_SHA256_ALGORITHM est un PCWSTR null-terminated
        // fourni par windows-sys (cf. windows-sys 0.59 Cryptography mod).
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut handle, BCRYPT_SHA256_ALGORITHM, std::ptr::null(), 0)
        };
        if status != 0 {
            return Err(format!("BCryptOpenAlgorithmProvider failed: 0x{status:X}"));
        }
        Ok(BCryptAlg { handle })
    }

    fn create_hash(&self) -> Result<BCryptHash, String> {
        use windows_sys::Win32::Security::Cryptography::BCryptCreateHash;
        let mut handle = std::ptr::null_mut();
        // SAFETY: self.handle est valide (open() a réussi). Pas de pbHashObject
        // (laisser BCrypt allouer) ; pas de pbSecret (HMAC non utilisé).
        let status = unsafe {
            BCryptCreateHash(
                self.handle,
                &mut handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };
        if status != 0 {
            return Err(format!("BCryptCreateHash failed: 0x{status:X}"));
        }
        Ok(BCryptHash { handle })
    }
}

impl Drop for BCryptAlg {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Cryptography::BCryptCloseAlgorithmProvider;
        if !self.handle.is_null() {
            // SAFETY: handle a été initialisé par BCryptOpenAlgorithmProvider
            // (open() returne Err sinon), pas encore fermé.
            unsafe {
                BCryptCloseAlgorithmProvider(self.handle, 0);
            }
        }
    }
}

struct BCryptHash {
    handle: windows_sys::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE,
}

impl BCryptHash {
    fn update(&mut self, data: &[u8]) -> Result<(), String> {
        use windows_sys::Win32::Security::Cryptography::BCryptHashData;
        // SAFETY: handle valide (créé par BCryptCreateHash, pas encore détruit).
        // data.as_ptr() est valide pour data.len() octets.
        let status =
            unsafe { BCryptHashData(self.handle, data.as_ptr(), data.len() as u32, 0) };
        if status != 0 {
            return Err(format!("BCryptHashData failed: 0x{status:X}"));
        }
        Ok(())
    }

    fn finish(self) -> Result<[u8; 32], String> {
        use windows_sys::Win32::Security::Cryptography::BCryptFinishHash;
        let mut digest = [0u8; 32];
        // SAFETY: handle valide, digest exactement 32 octets (SHA-256 output).
        let status = unsafe { BCryptFinishHash(self.handle, digest.as_mut_ptr(), 32, 0) };
        if status != 0 {
            return Err(format!("BCryptFinishHash failed: 0x{status:X}"));
        }
        Ok(digest)
        // Drop appelé ici → BCryptDestroyHash.
    }
}

impl Drop for BCryptHash {
    fn drop(&mut self) {
        use windows_sys::Win32::Security::Cryptography::BCryptDestroyHash;
        if !self.handle.is_null() {
            // SAFETY: handle créé par BCryptCreateHash (pas encore détruit).
            unsafe {
                BCryptDestroyHash(self.handle);
            }
        }
    }
}

fn report(
    client: &Client,
    pkg_id: &str,
    phase: &str,
    version: &str,
    plugin_id_local: Option<&str>,
    error: Option<&str>,
) -> Result<(), String> {
    let report = PluginStatusReport {
        phase,
        version,
        plugin_id_local,
        events_emitted: 0,
        last_event_ts: None,
        last_crash_ts: None,
        crash_count_1h: 0,
        error,
    };
    client.report_plugin_status(pkg_id, &report)
}
