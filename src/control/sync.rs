//! Profile synchronisation (transport + apply).
//!
//! When the heartbeat response reports `current_profile_version` greater
//! than what the agent currently has, the agent pulls the new profile:
//!
//! 1. `GET /agents/{id}/profile` → metadata (version, hash, modules).
//! 2. `GET /profiles/{id}/template` → the full template (rules + meta).
//! 3. Persist both to disk under the state dir and update the in-memory
//!    [`ProfileState`] so subsequent heartbeats report the right
//!    `profile_version` / `modules_loaded`.
//! 4. If a `remote_rules_path` is configured, concatenate the enabled
//!    rules' `waza_source` and write them to that path, then trigger a
//!    detection-engine reload. The agent's `detection.rules_path` is
//!    expected to `include` that file — if not, the reload is a no-op
//!    rather than dangerous magic.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::client::{Client, ModuleRef};
use super::{ControlStats, ProfileState, RuleError};
use crate::detection::DetectionEngine;
use crate::detection::waza::parser;
use crate::shutdown::SHUTDOWN;

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

/// Subset of the server's profile template we actually consume to apply
/// rules. We deliberately decode this loosely (extra fields ignored) so a
/// future server-side addition doesn't break the sync.
#[derive(Debug, Deserialize)]
struct TemplateRuleView {
    name: String,
    #[serde(default = "default_enabled")]
    is_enabled: bool,
    #[serde(default)]
    waza_source: String,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct TemplateView {
    #[serde(default)]
    rules: Vec<TemplateRuleView>,
    // `agent_config` est lu directement via `template.get("agent_config")`
    // dans `write_agent_config_overrides` — pas via ce view struct qui
    // sert au parse des règles uniquement.
}

fn profile_path(state_dir: &Path) -> PathBuf {
    state_dir.join("profile.json")
}

fn template_path(state_dir: &Path) -> PathBuf {
    state_dir.join("profile_template.json")
}

fn agent_config_overrides_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent_config_overrides.json")
}

/// Seed the in-memory [`ProfileState`] from `profile.json` if present.
pub fn load_persisted(state_dir: &Path) -> ProfileState {
    match std::fs::read(profile_path(state_dir)) {
        Ok(bytes) => match serde_json::from_slice::<PersistedProfile>(&bytes) {
            Ok(p) => ProfileState {
                version: p.version,
                modules_loaded: p.modules_loaded,
                // Volontairement vide après seed disque : les erreurs
                // ne sont pas persistées entre redémarrages — le prochain
                // pull profil les recalcule.
                rule_errors: Vec::new(),
            },
            Err(e) => {
                eprintln!("[control] ignoring corrupt profile.json ({e}) — starting at v0");
                ProfileState::default()
            }
        },
        Err(_) => ProfileState::default(),
    }
}

/// Pull the assigned profile + template, persist it, and (if wired) apply
/// it to the local detection engine.
///
/// Best-effort: a network/IO error returns `Err` for the caller to log;
/// the previous state is left untouched on failure.
#[allow(clippy::too_many_arguments)]
pub fn pull(
    client: &Client,
    state: &Mutex<ProfileState>,
    state_dir: &Path,
    stats: &ControlStats,
    remote_rules_path: Option<&Path>,
    engine: Option<&Arc<DetectionEngine>>,
) -> Result<(), String> {
    let Some(meta) = client.get_profile_metadata()? else {
        eprintln!("[control] heartbeat signalled a profile change but none is assigned");
        return Ok(());
    };

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
        // Template is auxiliary (audit-only) — don't fail the sync.
        eprintln!("[control] could not persist profile_template.json: {e}");
    }

    // Overrides de config : on écrit sur disque avant de toucher aux
    // règles. Si les overrides ont changé, on demandera un restart en
    // fin de fonction (les autres étapes doivent commit ce qu'elles ont
    // fait avant le kill).
    let config_changed = write_agent_config_overrides(&template, state_dir).unwrap_or_else(|e| {
        eprintln!("[control] agent_config overrides not persisted: {e}");
        false
    });

    // Apply : extract the rule sources and write them to the configured
    // remote_rules_path. This step is opt-in via config; if absent we
    // just persisted the JSON template for audit and we're done.
    //
    // `rule_errors` est calculé même si `remote_rules_path` est `None`
    // (au cas où un opérateur veuille un feedback de validation sans
    // appliquer) — coût négligeable et utile.
    let mut parse_outcome = parse_template_rules(&template)?;
    if let Some(path) = remote_rules_path {
        match write_accepted_rules(&parse_outcome, path, meta.version) {
            Ok(()) => {
                eprintln!(
                    "[control] wrote {} rule(s) to {} (v{}) — {} errors",
                    parse_outcome.accepted.len(),
                    path.display(),
                    meta.version,
                    parse_outcome.errors.len(),
                );
                // Force-reload regardless of whether the detection engine's
                // own poller has fingerprinted the change yet — operator
                // expectation is "click save in console → applied within a
                // heartbeat", not "wait for the next mtime poll".
                if let Some(eng) = engine {
                    if let Err(e) = eng.force_reload() {
                        eprintln!("[control] detection reload failed: {e}");
                        // Si on a un échec de reload alors qu'on a accepté
                        // toutes les règles individuellement, c'est une erreur
                        // de bundle (collision résiduelle, include cassé,
                        // etc.). On la remonte sous un nom synthétique pour
                        // que la console puisse l'afficher (réservé : commence
                        // par `__`, ne matchera aucune Rule.name côté DB).
                        parse_outcome.errors.push(RuleError {
                            rule_name: "__server_bundle__".to_string(),
                            message: format!("reload du fichier `server.waza` échoué : {e}"),
                        });
                    }
                }
            }
            Err(e) => {
                eprintln!("[control] could not apply template to {}: {e}", path.display());
                // Idem : on remonte l'erreur d'écriture pour qu'elle ne
                // disparaisse pas dans le journal local.
                parse_outcome.errors.push(RuleError {
                    rule_name: "__server_bundle__".to_string(),
                    message: format!("écriture de `server.waza` échouée : {e}"),
                });
            }
        }
    }

    let module_count = modules_loaded.len();
    {
        let mut s = match state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.version = meta.version;
        s.modules_loaded = modules_loaded;
        s.rule_errors = parse_outcome.errors;
    }
    stats.bump_profile_sync();
    eprintln!(
        "[control] profile synced → v{} ({} module(s) required)",
        meta.version, module_count
    );

    // Restart automatique si les overrides d'`agent.json` ont changé.
    // Le hot-reload des règles est déjà pris en charge par le moteur ;
    // en revanche des paramètres comme heartbeat_interval, ETW toggles,
    // send_alerts ne sont lus qu'au boot — d'où le kill contrôlé.
    // Le service Windows est configuré "restart on failure" au setup,
    // donc `exit(2)` déclenche un redémarrage propre.
    if config_changed {
        eprintln!("[control] agent_config overrides changed — service restart requested");
        SHUTDOWN.store(true, Ordering::Release);
        // Petit sursis pour que les threads (spool, shipper) drainent
        // le peu qu'ils peuvent — main pilote un shutdown propre sur
        // ce signal, puis on quitte avec un code non-zéro pour signaler
        // au SCM qu'il doit relancer.
        schedule_exit_after_shutdown();
    }
    Ok(())
}

/// Marque l'agent pour arrêt et laisse ~2 s aux threads pour drainer,
/// puis force l'exit. Le code de sortie `2` est intercepté par le SCM
/// (service configuré "restart on failure") qui relance le binaire ;
/// en mode console il termine simplement le process.
fn schedule_exit_after_shutdown() {
    std::thread::Builder::new()
        .name("wedr-restart".into())
        .spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            std::process::exit(2);
        })
        .ok();
}

/// Outcome of parsing a template : règles acceptées (qui partiront dans
/// le `server.waza`) et erreurs (qui partiront dans le heartbeat).
struct TemplateParseOutcome {
    /// `(rule_name, waza_source_trimmed)` — seulement les règles qui ont
    /// parsé en isolation. Le `waza_source` est répété tel quel dans le
    /// fichier final.
    accepted: Vec<(String, String)>,
    errors: Vec<RuleError>,
}

/// Parse chaque règle du template en isolation. Une règle dont la
/// source ne parse pas est écartée du fichier final ; son nom et le
/// message d'erreur partent dans `errors`. Le tout permet d'isoler
/// précisément quelle règle casse, vs un parse global qui échoue en
/// bloc à la première erreur.
///
/// **Collisions de noms de groupe entre règles** : le moteur agent va
/// concaténer toutes les sources acceptées dans un seul fichier puis
/// reparser le tout. Si deux règles différentes déclarent un groupe
/// `Detection` du même nom, le reload final échouera. On détecte donc
/// les collisions ici : la deuxième règle qui apporte un nom déjà vu
/// est rejetée avec un message explicite (et la première gagne).
fn parse_template_rules(
    template: &serde_json::Value,
) -> Result<TemplateParseOutcome, String> {
    let view: TemplateView = serde_json::from_value(template.clone())
        .map_err(|e| format!("decode template view: {e}"))?;

    let mut accepted = Vec::new();
    let mut errors = Vec::new();
    let mut claimed_group_names: HashSet<String> = HashSet::new();
    for r in &view.rules {
        if !r.is_enabled {
            continue;
        }
        if r.waza_source.trim().is_empty() {
            errors.push(RuleError {
                rule_name: r.name.clone(),
                message: "règle vide".to_string(),
            });
            continue;
        }
        // Parse en isolation : la default_window n'importe pas ici
        // (jamais utilisée pour décider si la règle est valide).
        let parsed = match parser::parse_source(&r.waza_source, std::time::Duration::from_secs(5)) {
            Ok(p) => p,
            Err(msg) => {
                errors.push(RuleError {
                    rule_name: r.name.clone(),
                    message: msg,
                });
                continue;
            }
        };
        // Détection des collisions de noms de groupe. Si la règle apporte
        // un groupe Detection déjà revendiqué par une règle précédente,
        // on rejette cette règle entière (au lieu de laisser le reload
        // final échouer sur `duplicate Detection group`).
        let mut collision: Option<&str> = None;
        for g in &parsed {
            if claimed_group_names.contains(&g.name) {
                collision = Some(g.name.as_str());
                break;
            }
        }
        if let Some(name) = collision {
            errors.push(RuleError {
                rule_name: r.name.clone(),
                message: format!(
                    "groupe '{name}' déjà défini par une autre règle du profil — renommer pour les concilier"
                ),
            });
            continue;
        }
        for g in &parsed {
            claimed_group_names.insert(g.name.clone());
        }
        accepted.push((r.name.clone(), r.waza_source.clone()));
    }
    Ok(TemplateParseOutcome { accepted, errors })
}

/// Extrait `agent_config` du template et l'écrit à disque si différent
/// du contenu actuel. Retourne `true` quand un changement a été
/// persisté (le caller déclenche alors un restart du service).
///
/// L'écriture est **atomique** (tmp + rename) et **inconditionnelle
/// sur non-changement** : on ne touche pas le mtime si le contenu est
/// identique, pour éviter des restarts en boucle si le serveur renvoie
/// le même dict à chaque sync.
fn write_agent_config_overrides(
    template: &serde_json::Value,
    state_dir: &Path,
) -> Result<bool, String> {
    let overrides = template.get("agent_config").cloned().unwrap_or_else(|| {
        serde_json::Value::Object(serde_json::Map::new())
    });
    // On stocke toujours un objet, jamais null : simplifie la lecture
    // côté AppConfig::load.
    let overrides = match overrides {
        serde_json::Value::Object(_) => overrides,
        _ => serde_json::Value::Object(serde_json::Map::new()),
    };
    let new_body = serde_json::to_vec_pretty(&overrides)
        .map_err(|e| format!("serialize agent_config: {e}"))?;

    let path = agent_config_overrides_path(state_dir);
    let current = std::fs::read(&path).ok();
    if current.as_deref() == Some(new_body.as_slice()) {
        return Ok(false);
    }

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &new_body)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(true)
}

/// Sérialise les règles acceptées en un fichier `.waza` unique et
/// l'écrit atomiquement (`tmp` + rename). En-tête commenté pour que
/// l'opérateur qui tombe dessus sache qu'il est généré.
fn write_accepted_rules(
    outcome: &TemplateParseOutcome,
    path: &Path,
    version: i64,
) -> Result<(), String> {
    let mut body = String::with_capacity(
        256 + outcome.accepted.iter().map(|(_, s)| s.len()).sum::<usize>(),
    );
    body.push_str("# Géré par l'agent WazabiEDR — NE PAS ÉDITER À LA MAIN.\n");
    body.push_str("# Toute modif sera écrasée au prochain heartbeat avec sync profil.\n");
    body.push_str(&format!("# Profil version : {}\n\n", version));
    for (name, source) in &outcome.accepted {
        body.push_str(&format!("# --- rule '{}' ---\n", name));
        body.push_str(source.trim_end());
        body.push('\n');
        body.push('\n');
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("waza.tmp");
    std::fs::write(&tmp, body.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}
