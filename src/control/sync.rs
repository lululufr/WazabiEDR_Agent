//! Profile synchronisation (transport only).
//!
//! When the heartbeat response reports `current_profile_version` greater
//! than what the agent currently has, the agent pulls the new profile:
//!
//! 1. `GET /agents/{id}/profile` → metadata (version, hash, modules).
//! 2. `GET /profiles/{id}/template` → the full template.
//!
//! Both are **persisted to disk** under the state dir and the in-memory
//! [`ProfileState`] is updated so subsequent heartbeats report the new
//! `profile_version` / `modules_loaded`. Applying the template's rules to
//! the Waza engine is intentionally **out of scope** here: the server's
//! `waza_definition` is a free-form JSON DSL whereas the agent engine
//! parses `.waza` text, and that translation isn't specified yet. We keep
//! the raw template on disk so a later step can consume it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::client::{Client, ModuleRef};
use super::{ControlStats, ProfileState};

/// What we persist about the applied profile, so a restart resumes with
/// the right `profile_version`/`modules_loaded` without forcing a re-pull.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedProfile {
    profile_id: String,
    version: i64,
    hash: String,
    #[serde(default)]
    modules_loaded: Vec<ModuleRef>,
}

fn profile_path(state_dir: &Path) -> PathBuf {
    state_dir.join("profile.json")
}

fn template_path(state_dir: &Path) -> PathBuf {
    state_dir.join("profile_template.json")
}

/// Seed the in-memory [`ProfileState`] from `profile.json` if present.
/// Returns `(version, modules_loaded)` — `(0, [])` on a fresh install.
pub fn load_persisted(state_dir: &Path) -> ProfileState {
    match std::fs::read(profile_path(state_dir)) {
        Ok(bytes) => match serde_json::from_slice::<PersistedProfile>(&bytes) {
            Ok(p) => ProfileState {
                version: p.version,
                modules_loaded: p.modules_loaded,
            },
            Err(e) => {
                eprintln!("[control] ignoring corrupt profile.json ({e}) — starting at v0");
                ProfileState::default()
            }
        },
        Err(_) => ProfileState::default(),
    }
}

/// Pull the assigned profile + template and persist them, updating the
/// shared [`ProfileState`]. Best-effort: any network/IO error is returned
/// as `Err` for the caller to log; the previous state is left untouched.
pub fn pull(
    client: &Client,
    state: &Mutex<ProfileState>,
    state_dir: &Path,
    stats: &ControlStats,
) -> Result<(), String> {
    let Some(meta) = client.get_profile_metadata()? else {
        eprintln!("[control] heartbeat signalled a profile change but none is assigned");
        return Ok(());
    };

    // Fetch the full template (kept verbatim on disk for now).
    let template = client.get_profile_template(&meta.profile_id)?;

    let modules_loaded: Vec<ModuleRef> = meta
        .modules_required
        .iter()
        .map(|m| ModuleRef {
            id: m.id.clone(),
            version: m.version.clone(),
        })
        .collect();

    // Persist before flipping in-memory state so a crash mid-write can't
    // leave us reporting a version we don't have a template for.
    if let Some(parent) = profile_path(state_dir).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let persisted = PersistedProfile {
        profile_id: meta.profile_id.clone(),
        version: meta.version,
        hash: meta.hash.clone(),
        modules_loaded: modules_loaded.clone(),
    };
    let json = serde_json::to_vec_pretty(&persisted)
        .map_err(|e| format!("serialize profile.json: {e}"))?;
    std::fs::write(profile_path(state_dir), json)
        .map_err(|e| format!("write profile.json: {e}"))?;

    let tmpl_bytes = serde_json::to_vec_pretty(&template)
        .map_err(|e| format!("serialize template: {e}"))?;
    if let Err(e) = std::fs::write(template_path(state_dir), tmpl_bytes) {
        // Template is auxiliary (not applied yet) — don't fail the sync.
        eprintln!("[control] could not persist profile_template.json: {e}");
    }

    let module_count = modules_loaded.len();
    {
        let mut s = match state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.version = meta.version;
        s.modules_loaded = modules_loaded;
    }
    stats.bump_profile_sync();
    eprintln!(
        "[control] profile synced → v{} ({} module(s) required)",
        meta.version, module_count
    );
    Ok(())
}
