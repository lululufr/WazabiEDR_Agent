//! Plugin supervisor: spawns auto-launch plugins at agent startup and
//! restarts them on crash with exponential backoff.
//!
//! ## What gets launched
//!
//! Every manifest in the manifest store with `auto_launch: true` and
//! `revoked: false`. Other plugins (operator-managed services, on-demand
//! tools) are unaffected — they keep connecting on their own. The flag
//! is purely opt-in.
//!
//! ## Lifecycle
//!
//! ```text
//!     supervisor thread per plugin
//!         │
//!         ▼
//!     spawn `expected_path` with WEDR_PLUGIN_ID=<uuid>
//!         │
//!         ▼
//!     poll child every 250 ms (try_wait + SHUTDOWN check)
//!         │
//!     ┌───┴────────────────────────────────────────────────┐
//!     │ SHUTDOWN set                       │ child exited  │
//!     ▼                                    ▼               │
//!  wait ≤ 5 s for graceful exit       compute backoff      │
//!  (children share our console, so    (1s → 2s → 4s …      │
//!  Ctrl+C is broadcast and they       cap 60s; reset to 1s │
//!  should exit on their own)          if alive ≥ 5 min)    │
//!     │                                    │               │
//!     ▼                                    └──────► loop ──┘
//!  if still alive: TerminateProcess
//! ```
//!
//! ## Privilege note
//!
//! Children inherit the agent's token. Today the agent typically runs
//! as Administrator (driver access + manifest dir read), so plugins
//! also run elevated. That's a privilege concern documented in
//! `WazabiEDR_Doc/architecture/plugin-supervisor.md`. Future:
//! per-plugin restricted token / specific user.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::plugin::manifest::{ManifestStore, PluginManifest};
use crate::shutdown::SHUTDOWN;

/// Maximum delay between restart attempts. Prevents a permanently
/// broken plugin from spamming Spawn / log lines forever — once the
/// backoff hits this, retries happen at most once a minute.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Initial delay for the first restart attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// "The plugin lasted long enough to count as healthy" threshold. If
/// a child stays alive for at least this long, the next crash starts
/// the backoff from scratch instead of continuing the exponential
/// sequence — gives transient failures (a bad downstream, a one-off
/// network blip) room to recover without permanently penalising the
/// plugin's restart cadence.
const STABLE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Grace period given to children to react to a Ctrl+C that the
/// console layer broadcast to the process group. Past this, we
/// `TerminateProcess` so a misbehaving plugin cannot stall agent
/// shutdown indefinitely.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Délai entre deux scans du dossier manifests pour détecter les
/// **nouveaux** plugins déposés après le boot de l'agent (typiquement par
/// le control-plane serveur via `wedr-plugin enroll`). Sans ce watcher,
/// un manifest déposé tardivement ne serait jamais auto-launched —
/// le scan initial de `spawn_supervisor` est ponctuel.
const WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// Délai entre deux relectures du manifest d'un plugin EN COURS de
/// supervision, pour détecter :
/// - `revoked = true` → kill child + exit thread (la révocation propagée
///   par `wedr-plugin revoke` doit être prise en compte vivant).
/// - `expected_sha256` ou `expected_path` modifiés → kill child + respawn
///   avec le nouveau binaire (cas update : `wedr-plugin update <id>` a
///   re-hashé suite à un téléchargement de version plus récente).
/// - manifest disparu → kill child + exit thread (cas `wedr-plugin remove`).
const MANIFEST_POLL: Duration = Duration::from_secs(5);

/// Returned to the caller. Holds the supervisor threads + le watcher
/// derrière un `Arc<Mutex<…>>` parce que le watcher pousse de nouveaux
/// supervise_one threads à l'exécution (manifests apparus après le boot).
pub struct SupervisorHandle {
    threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    /// Plugins lancés au boot initial. Indicatif uniquement pour la bannière
    /// de démarrage — le watcher peut en ajouter ensuite (non comptés ici).
    spawned_count: usize,
}

impl SupervisorHandle {
    /// Number of plugins the supervisor decided to spawn at startup.
    /// Useful for the agent's startup banner.
    pub fn spawned_count(&self) -> usize {
        self.spawned_count
    }

    /// Wait for every supervisor thread to exit. Each thread observes
    /// `SHUTDOWN` and stops on its own; this just blocks until they're
    /// all gone. Safe to call without `SHUTDOWN` being set, in which
    /// case it blocks forever — only call after the shutdown signal
    /// has been posted.
    pub fn shutdown(self) {
        // `take` consomme la Vec interne — les threads spawné après par le
        // watcher sont aussi inclus puisqu'on partage le même Arc<Mutex<…>>.
        let threads = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|e| e.into_inner()));
        for h in threads {
            let _ = h.join();
        }
    }
}

/// Read the manifest dir, find every `auto_launch: true` plugin, and
/// spawn one supervisor thread per match. Spawn aussi un thread "watcher"
/// qui re-scan toutes les `WATCH_INTERVAL` secondes pour détecter les
/// manifests déposés après le boot (cas du flux serveur-push : l'agent
/// invoque `wedr-plugin enroll` puis dépend du supervisor pour démarrer
/// le plugin).
///
/// Failure to load the manifest dir doesn't fail-fast — same policy as
/// the rest of the plugin subsystem. We log + continue avec set vide.
pub fn spawn_supervisor(manifest_dir: PathBuf) -> SupervisorHandle {
    // Set partagé entre scan initial + watcher pour ne JAMAIS lancer 2 fois
    // le même plugin_id. Un thread `supervise_one` retire son entrée en
    // sortie (shutdown ou erreur fatale) pour permettre un re-enroll futur.
    let supervised: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

    // Scan initial — synchrone pour que `spawned_count` reflète le boot.
    let initial = scan_and_spawn(&manifest_dir, &supervised, &threads);
    if initial > 0 {
        eprintln!("[supervisor] auto-launched {} plugin(s) at boot", initial);
    }

    // Watcher : rescanne toutes les WATCH_INTERVAL secondes.
    let watcher_dir = manifest_dir.clone();
    let watcher_supervised = Arc::clone(&supervised);
    let watcher_threads = Arc::clone(&threads);
    let watcher_handle = thread::Builder::new()
        .name("wedr-supervisor-watcher".into())
        .spawn(move || {
            while !SHUTDOWN.load(Ordering::Acquire) {
                if !sleep_with_shutdown(WATCH_INTERVAL) {
                    break;
                }
                let added = scan_and_spawn(&watcher_dir, &watcher_supervised, &watcher_threads);
                if added > 0 {
                    eprintln!(
                        "[supervisor] watcher: {} new plugin(s) auto-launched",
                        added
                    );
                }
            }
        })
        .expect("OS refused to spawn supervisor watcher thread");
    threads.lock().unwrap_or_else(|e| e.into_inner()).push(watcher_handle);

    SupervisorHandle {
        threads,
        spawned_count: initial,
    }
}

/// Scan le manifest dir, spawn un `supervise_one` pour chaque manifest
/// `auto_launch && !revoked` pas encore dans `supervised`. Renvoie le
/// nombre de nouveaux threads spawned.
fn scan_and_spawn(
    manifest_dir: &Path,
    supervised: &Arc<Mutex<HashSet<String>>>,
    threads: &Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
) -> usize {
    let store = match ManifestStore::load_dir(manifest_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[supervisor] scan: cannot read manifest dir {:?}: {}",
                manifest_dir, e
            );
            return 0;
        }
    };

    // On lock le set juste assez pour décider quoi lancer, puis on relâche
    // avant les `thread::Builder::spawn` (qui peuvent prendre du temps OS).
    let to_launch: Vec<PluginManifest> = {
        let set = supervised.lock().unwrap_or_else(|e| e.into_inner());
        store
            .iter()
            .filter(|m| m.auto_launch && !m.revoked)
            .filter(|m| !set.contains(&m.plugin_id))
            .cloned()
            .collect()
    };
    if to_launch.is_empty() {
        return 0;
    }

    let count = to_launch.len();
    for manifest in to_launch {
        // Réserver la place dans le set AVANT de spawn, sinon un 2e scan
        // pendant le `spawn` pourrait re-trouver le même manifest et le
        // lancer en double.
        supervised
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(manifest.plugin_id.clone());

        let thread_name = format!("wedr-supervisor-{}", short_id(&manifest.plugin_id));
        let supervised_for_cleanup = Arc::clone(supervised);
        let pid_for_cleanup = manifest.plugin_id.clone();
        let manifest_dir_for_thread = manifest_dir.to_path_buf();
        let h = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                supervise_one(manifest, manifest_dir_for_thread);
                // À la sortie de supervise_one (revoke, manifest absent,
                // shutdown ou erreur fatale côté spawn), libère l'entrée
                // pour permettre un re-enroll ultérieur (cas : opérateur
                // fait `wedr-plugin remove` puis `enroll` à nouveau, ou
                // serveur unassign puis re-assign).
                supervised_for_cleanup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&pid_for_cleanup);
            })
            .expect("OS refused to spawn supervisor thread");
        threads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(h);
    }
    count
}

/// Résultat de l'attente d'un cycle de vie d'un plugin.
enum WaitOutcome {
    /// Process exit normal (ou crash). La boucle décide d'un backoff
    /// puis respawn avec le même manifest.
    ChildExited(Option<std::process::ExitStatus>),
    /// Manifest devenu `revoked=true` ou supprimé du dossier → l'opérateur
    /// (ou le serveur) demande l'arrêt. Kill puis sortie du thread.
    Revoked,
    /// Manifest modifié (nouveau binaire / nouveau chemin). Kill puis
    /// respawn AVEC le nouveau manifest, backoff reset (un update n'est
    /// pas un crash).
    Updated(PluginManifest),
    /// SHUTDOWN posé pendant l'attente.
    Shutdown,
}

/// Single-plugin supervisor loop: spawn → wait → respawn/exit, en relisant
/// périodiquement le manifest pour gérer revoke + update au runtime.
fn supervise_one(initial: PluginManifest, manifest_dir: PathBuf) {
    let label = format!("{} ({})", initial.name, short_id(&initial.plugin_id));
    let manifest_path = manifest_dir.join(format!("{}.json", initial.plugin_id));
    let mut current = initial;
    let mut backoff = INITIAL_BACKOFF;

    while !SHUTDOWN.load(Ordering::Acquire) {
        // ---- spawn ----
        let mut child = match Command::new(&current.expected_path)
            .env("WEDR_PLUGIN_ID", &current.plugin_id)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[supervisor] {} — spawn failed: {} — retrying in {:?}",
                    label, e, backoff
                );
                if !sleep_with_shutdown(backoff) {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };

        let pid = child.id();
        let started = Instant::now();
        eprintln!("[supervisor] {} — launched pid={}", label, pid);

        // ---- wait + manifest poll ----
        let outcome = wait_for_exit_or_change(&mut child, &manifest_path, &current);

        let alive = started.elapsed();

        match outcome {
            WaitOutcome::ChildExited(status) => {
                eprintln!(
                    "[supervisor] {} — pid={} exited after {:.1}s, status={:?}",
                    label, pid, alive.as_secs_f32(), status
                );
                if SHUTDOWN.load(Ordering::Acquire) {
                    return;
                }
                if alive >= STABLE_THRESHOLD {
                    backoff = INITIAL_BACKOFF;
                }
                eprintln!("[supervisor] {} — restarting in {:?}", label, backoff);
                if !sleep_with_shutdown(backoff) {
                    return;
                }
                backoff = next_backoff(backoff);
            }
            WaitOutcome::Updated(new_manifest) => {
                eprintln!(
                    "[supervisor] {} — manifest changed (sha or path), respawning with new binary",
                    label
                );
                // child déjà killed dans wait_for_exit_or_change.
                current = new_manifest;
                backoff = INITIAL_BACKOFF; // un update n'est pas une régression
            }
            WaitOutcome::Revoked => {
                eprintln!(
                    "[supervisor] {} — revoked or manifest removed, exiting (pid={} killed)",
                    label, pid
                );
                return;
            }
            WaitOutcome::Shutdown => {
                eprintln!("[supervisor] {} — shutdown, exiting", label);
                return;
            }
        }
    }
}

/// Block until l'une de ces conditions :
/// - le process child exit → ChildExited
/// - SHUTDOWN posé → grace + kill si nécessaire, return Shutdown
/// - le manifest disparait ou passe `revoked=true` → kill child, return Revoked
/// - `expected_sha256` ou `expected_path` changent → kill child, return Updated(new)
fn wait_for_exit_or_change(
    child: &mut Child,
    manifest_path: &Path,
    current: &PluginManifest,
) -> WaitOutcome {
    let poll = Duration::from_millis(250);
    let mut last_manifest_check = Instant::now();

    loop {
        // Process exit naturel.
        match child.try_wait() {
            Ok(Some(status)) => return WaitOutcome::ChildExited(Some(status)),
            Ok(None) => {}
            Err(e) => {
                eprintln!("[supervisor] try_wait failed: {} — abandoning child", e);
                return WaitOutcome::ChildExited(None);
            }
        }

        // Shutdown global.
        if SHUTDOWN.load(Ordering::Acquire) {
            let deadline = Instant::now() + SHUTDOWN_GRACE;
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    return WaitOutcome::Shutdown;
                }
                thread::sleep(poll);
            }
            let _ = child.kill();
            let _ = child.wait();
            return WaitOutcome::Shutdown;
        }

        // Poll manifest périodique. Ne fait PAS de I/O à chaque tour de
        // loop (250ms) — toutes les MANIFEST_POLL secondes suffit, et on
        // évite de saturer le disque sur des dizaines de plugins.
        if last_manifest_check.elapsed() >= MANIFEST_POLL {
            last_manifest_check = Instant::now();
            match read_manifest(manifest_path, current) {
                ManifestState::Missing => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return WaitOutcome::Revoked;
                }
                ManifestState::Revoked => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return WaitOutcome::Revoked;
                }
                ManifestState::Changed(new) => {
                    // Update : nouveau binaire (sha) ou nouveau chemin.
                    // On tue le child courant pour libérer le fichier (sur
                    // Windows un .exe en cours d'exécution n'est pas
                    // writable — mais notre download_to a déjà rename
                    // l'ancien hors du chemin, donc en pratique c'est OK).
                    let _ = child.kill();
                    let _ = child.wait();
                    return WaitOutcome::Updated(new);
                }
                ManifestState::Unchanged | ManifestState::ReadError => {
                    // ReadError est traité comme Unchanged : on ne tue pas
                    // un plugin sain à cause d'un I/O transitoire. Si le
                    // problème persiste, le prochain poll re-tentera.
                }
            }
        }

        thread::sleep(poll);
    }
}

/// État du manifest entre deux polls. `ReadError` ≠ `Missing` : disparu
/// volontaire vs erreur disk → on traite différemment pour ne pas tuer un
/// plugin sain sur un glitch I/O.
enum ManifestState {
    Unchanged,
    Changed(PluginManifest),
    Revoked,
    Missing,
    ReadError,
}

/// Compare le manifest sur disque avec ce que le supervisor a en mémoire.
/// On ne déclenche `Changed` que sur les champs qui requièrent un respawn
/// (path ou sha) — un changement de `name` ou `vendor` n'a pas d'impact
/// runtime, pas besoin de tuer un process sain.
fn read_manifest(path: &Path, current: &PluginManifest) -> ManifestState {
    use std::fs;
    match fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ManifestState::Missing,
        Err(_) => ManifestState::ReadError,
        Ok(bytes) => match serde_json::from_slice::<PluginManifest>(&bytes) {
            Err(_) => ManifestState::ReadError,
            Ok(m) if m.revoked => ManifestState::Revoked,
            Ok(m)
                if m.expected_sha256 != current.expected_sha256
                    || m.expected_path != current.expected_path =>
            {
                ManifestState::Changed(m)
            }
            Ok(_) => ManifestState::Unchanged,
        },
    }
}

/// Sleep `dur`, slicing on `SHUTDOWN` so backoffs don't keep an
/// agent alive for up to 60 s after Ctrl+C. Returns `false` if
/// shutdown fired during the sleep — caller should bail out.
fn sleep_with_shutdown(dur: Duration) -> bool {
    let slice = Duration::from_millis(250);
    let mut left = dur;
    while left > Duration::ZERO {
        if SHUTDOWN.load(Ordering::Acquire) {
            return false;
        }
        let chunk = std::cmp::min(slice, left);
        thread::sleep(chunk);
        left = left.saturating_sub(chunk);
    }
    !SHUTDOWN.load(Ordering::Acquire)
}

/// `1s → 2s → 4s → 8s → 16s → 32s → 60s (cap)`.
fn next_backoff(prev: Duration) -> Duration {
    let next = prev.saturating_mul(2);
    if next > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        next
    }
}

/// First 8 hex chars of the plugin_id — keeps log lines readable while
/// staying disambiguated for any realistic enrollment.
fn short_id(id: &str) -> &str {
    if id.len() > 8 { &id[..8] } else { id }
}
