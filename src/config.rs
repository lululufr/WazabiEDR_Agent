//! Runtime configuration — single source of truth.
//!
//! All tunables live in **one JSON file** at
//! `%ProgramData%\WazabiEDR\agent.json` (Administrators-only ACL at
//! install time — same trust boundary as the plugin manifest store).
//! The agent has no CLI flags and no environment variables: a single
//! place to edit, a single place to audit, no env-var drift across
//! deployment tooling.
//!
//! ```json
//! {
//!   "agent": {
//!     "console_output": true,
//!     "spool_dir": "C:\\ProgramData\\WazabiEDR\\spool",
//!     "max_bytes_per_file": 1048576,
//!     "max_age_secs": 10,
//!     "max_total_bytes": 268435456,
//!     "channel_capacity": 1024,
//!     "zstd_level": 3
//!   },
//!   "shipper": {
//!     "server_url": "https://wazabi.example.com",
//!     "agent_id": "5f1b3a8e-1c4f-4d2e-9b8a-7e3f6a9c0d11",
//!     "token_encrypted_b64": "AQAAANC..."
//!   }
//! }
//! ```
//!
//! Both sections are optional:
//! - missing `agent` ⇒ all defaults below
//! - missing `shipper` (or `enabled: false`) ⇒ spool-only mode
//!
//! Missing the file entirely is fine too: the agent writes a default
//! skeleton on first start so the operator has something concrete to
//! edit, then proceeds with the defaults.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::etw::EtwConfig;
use crate::filter::FilterSection;
use crate::polling::PollingConfig;
use crate::shipper::config::{ShipperConfig, ShipperSection, resolve_shipper};

/// Default location of the config file: `%ProgramData%\WazabiEDR\agent.json`.
pub const AGENT_CONFIG_FILE: &str = "WazabiEDR\\agent.json";

/// Resolved configuration handed to `main`.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub agent: AgentConfig,
    /// `None` means spool-only mode (no upload).
    pub shipper: Option<ShipperConfig>,
    /// Section `filter` brute. Consommée une fois par `filter::init` au
    /// boot — pas de hot reload donc on n'a pas à la conserver après.
    pub filter: Option<FilterSection>,
    /// `None` (or `enabled: false`) means the Waza detection layer is
    /// off — the agent behaves exactly as before this feature existed.
    pub detection: Option<DetectionConfig>,
    /// `None` (or `enabled: false`) means the control plane (heartbeat /
    /// profile sync / commands / alerts) is off. It additionally requires
    /// a configured `shipper` section — that's where the server URL,
    /// agent id and token come from.
    pub control: Option<ControlConfig>,
    /// `None` (or `enabled: false`) means the ETW consumer is off. When
    /// on, the agent spawns one trace session subscribed to DNS / TCP /
    /// PowerShell / WMI / Schannel / AMSI providers (each independently
    /// toggleable). Output events are pushed into the kernel spool.
    pub etw: Option<EtwConfig>,
    /// `None` (or `enabled: false`) means the user-mode persistence
    /// polling is off (services + scheduled tasks). When on, two
    /// dedicated threads diff snapshots at the configured cadence.
    pub polling: Option<PollingConfig>,
}

/// Control-plane tunables. Opt-in: absent section ⇒ no control plane.
/// Credentials (server_url / agent_id / token) are NOT here — they are
/// shared with the `shipper` section.
#[derive(Clone, Debug)]
pub struct ControlConfig {
    /// Fallback heartbeat cadence; the server's `next_checkin_seconds`
    /// overrides it at runtime.
    pub heartbeat_interval: Duration,
    /// Forward Waza rule matches to `POST /agents/{id}/alerts`.
    pub send_alerts: bool,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(60),
            send_alerts: true,
        }
    }
}

/// Waza detection-layer tunables. Opt-in: absent section ⇒ no detection.
#[derive(Clone, Debug)]
pub struct DetectionConfig {
    /// Path to the root `.waza` rules file. `include` directives inside
    /// it are resolved relative to this file.
    pub rules_path: PathBuf,
    /// Optional JSON schema file used only to validate rule field paths
    /// at load time (warns on likely typos). `None` ⇒ validation skipped.
    pub schema_path: Option<PathBuf>,
    /// Correlation window for rule groups that don't declare `window:`.
    pub default_window: Duration,
    /// How often the rules file is polled for changes (hot reload).
    pub reload_interval: Duration,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rules_path: default_rules_path(),
            schema_path: None,
            default_window: Duration::from_secs(5),
            reload_interval: Duration::from_secs(5),
        }
    }
}

/// Agent-side tunables: spool sizing + console output toggle.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub spool_dir: PathBuf,
    pub max_bytes_per_file: u64,
    pub max_age: Duration,
    pub max_total_bytes: u64,
    pub channel_capacity: usize,
    pub zstd_level: i32,
    /// Print kernel events (human lines) and plugin events (JSON) to
    /// stdout. Diagnostic messages (`[agent] ...`, `[plugin] ...`,
    /// errors) stay on stderr regardless — turning this off makes the
    /// agent suitable for unattended / service deployment without
    /// piping stdout into `nul`.
    pub console_output: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        // Spool dir resolves under `%ProgramData%\WazabiEDR\` so
        // unattended runs (future Windows service) land in a sensible
        // place, not the CWD.
        Self {
            spool_dir: default_spool_dir(),
            max_bytes_per_file: 1 * 1024 * 1024,
            max_age: Duration::from_secs(10),
            max_total_bytes: 256 * 1024 * 1024,
            channel_capacity: 1024,
            zstd_level: 3,
            // Off by default: in production the agent runs as a Windows
            // service (no console attached) and `console_output=true`
            // would just burn CPU formatting human lines no one reads.
            // Operators flip it to true ad-hoc when debugging.
            console_output: false,
        }
    }
}

/// Raw JSON shape — what serde sees on disk. Every field is optional
/// so a partial config falls back to defaults instead of refusing to
/// start.
#[derive(Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    agent: Option<AgentSection>,
    #[serde(default)]
    shipper: Option<ShipperSection>,
    #[serde(default)]
    filter: Option<FilterSection>,
    #[serde(default)]
    detection: Option<DetectionSection>,
    #[serde(default)]
    control: Option<ControlSection>,
    #[serde(default)]
    etw: Option<EtwSection>,
    #[serde(default)]
    polling: Option<PollingSection>,
}

#[derive(Deserialize, Default)]
struct EtwSection {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    dns: Option<bool>,
    #[serde(default)]
    tcp: Option<bool>,
    #[serde(default)]
    powershell: Option<bool>,
    #[serde(default)]
    wmi: Option<bool>,
    #[serde(default)]
    schannel: Option<bool>,
    #[serde(default)]
    amsi: Option<bool>,
}

#[derive(Deserialize, Default)]
struct PollingSection {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    services: Option<bool>,
    #[serde(default)]
    scheduled_tasks: Option<bool>,
    #[serde(default)]
    interval_secs: Option<u64>,
    #[serde(default)]
    silent_first_snapshot: Option<bool>,
}

#[derive(Deserialize, Default)]
struct ControlSection {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    send_alerts: Option<bool>,
}

#[derive(Deserialize, Default)]
struct DetectionSection {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    rules_path: Option<String>,
    #[serde(default)]
    schema_path: Option<String>,
    #[serde(default)]
    default_window_secs: Option<u64>,
    #[serde(default)]
    reload_interval_secs: Option<u64>,
}

#[derive(Deserialize, Default)]
struct AgentSection {
    #[serde(default)]
    console_output: Option<bool>,
    #[serde(default)]
    spool_dir: Option<String>,
    #[serde(default)]
    max_bytes_per_file: Option<u64>,
    #[serde(default)]
    max_age_secs: Option<u64>,
    #[serde(default)]
    max_total_bytes: Option<u64>,
    #[serde(default)]
    channel_capacity: Option<usize>,
    #[serde(default)]
    zstd_level: Option<i32>,
}

pub fn default_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join(AGENT_CONFIG_FILE.replace('\\', std::path::MAIN_SEPARATOR_STR))
}

fn default_spool_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join("WazabiEDR").join("spool")
}

fn default_rules_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join("WazabiEDR").join("rules").join("main.waza")
}

impl AppConfig {
    /// Load and resolve the full configuration.
    ///
    /// Returns a fully-defaulted [`AppConfig`] (no shipper) if the file
    /// is absent — and writes a default skeleton at `path` so the next
    /// run has a concrete file to read (and the operator has something
    /// to edit). Failure to write the skeleton is not fatal: we log it
    /// and keep going with in-memory defaults. Returns `Err` only when
    /// the file exists but is malformed, or when a present-but-invalid
    /// `shipper` section can't be resolved (missing URL, undecryptable
    /// token, …). Those are operator mistakes we want loud, not silent.
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Err(write_err) = write_default_config(path) {
                    eprintln!(
                        "[agent] could not write default config {:?}: {} — \
                         continuing with in-memory defaults",
                        path, write_err
                    );
                } else {
                    eprintln!("[agent] wrote default config skeleton to {:?}", path);
                }
                return Ok(Self {
                    agent: AgentConfig::default(),
                    shipper: None,
                    filter: None,
                    detection: None,
                    control: None,
                    etw: None,
                    polling: None,
                });
            }
            Err(e) => return Err(format!("read {:?}: {}", path, e)),
        };

        let parsed: ConfigFile =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {:?}: {}", path, e))?;

        let agent = resolve_agent(parsed.agent.unwrap_or_default());
        let shipper = match parsed.shipper {
            Some(mut s) if s.is_enabled() => {
                if s.needs_autoenroll() {
                    autoenroll_and_persist(&mut s, path)?;
                }
                Some(resolve_shipper(s)?)
            }
            _ => None,
        };
        let detection = match parsed.detection {
            Some(d) if d.enabled.unwrap_or(false) => Some(resolve_detection(d)),
            _ => None,
        };
        let control = match parsed.control {
            Some(c) if c.enabled.unwrap_or(false) => Some(resolve_control(c)),
            _ => None,
        };
        let etw = match parsed.etw {
            Some(e) if e.enabled.unwrap_or(false) => Some(resolve_etw(e)),
            _ => None,
        };
        let polling = match parsed.polling {
            Some(p) if p.enabled.unwrap_or(false) => Some(resolve_polling(p)),
            _ => None,
        };

        Ok(Self {
            agent,
            shipper,
            filter: parsed.filter,
            detection,
            control,
            etw,
            polling,
        })
    }
}

fn resolve_polling(s: PollingSection) -> PollingConfig {
    let d = PollingConfig::default();
    PollingConfig {
        services: s.services.unwrap_or(d.services),
        scheduled_tasks: s.scheduled_tasks.unwrap_or(d.scheduled_tasks),
        interval: s
            .interval_secs
            .map(|n| std::time::Duration::from_secs(n.max(5)))
            .unwrap_or(d.interval),
        silent_first_snapshot: s.silent_first_snapshot.unwrap_or(d.silent_first_snapshot),
    }
}

fn resolve_etw(s: EtwSection) -> EtwConfig {
    let d = EtwConfig::default();
    EtwConfig {
        dns: s.dns.unwrap_or(d.dns),
        tcp: s.tcp.unwrap_or(d.tcp),
        powershell: s.powershell.unwrap_or(d.powershell),
        wmi: s.wmi.unwrap_or(d.wmi),
        schannel: s.schannel.unwrap_or(d.schannel),
        amsi: s.amsi.unwrap_or(d.amsi),
    }
}

fn resolve_control(s: ControlSection) -> ControlConfig {
    let d = ControlConfig::default();
    ControlConfig {
        heartbeat_interval: s
            .heartbeat_interval_secs
            .map(|n| Duration::from_secs(n.max(1)))
            .unwrap_or(d.heartbeat_interval),
        send_alerts: s.send_alerts.unwrap_or(d.send_alerts),
    }
}

fn resolve_detection(s: DetectionSection) -> DetectionConfig {
    let d = DetectionConfig::default();
    // Treat an empty string the same as "absent" so the skeleton's
    // placeholder `"schema_path": ""` doesn't resolve to a bogus path.
    let non_empty = |o: Option<String>| o.filter(|s| !s.trim().is_empty());
    DetectionConfig {
        rules_path: non_empty(s.rules_path)
            .map(PathBuf::from)
            .unwrap_or(d.rules_path),
        schema_path: non_empty(s.schema_path).map(PathBuf::from),
        default_window: s
            .default_window_secs
            .map(Duration::from_secs)
            .unwrap_or(d.default_window),
        reload_interval: s
            .reload_interval_secs
            .map(Duration::from_secs)
            .unwrap_or(d.reload_interval),
    }
}

/// Déclenche `POST /enroll`, écrit le résultat dans le fichier puis
/// mute la section en mémoire pour que `resolve_shipper` voie le bon
/// couple `(agent_id, token_plain)`.
///
/// Si l'enroll échoue (serveur down, token invalide, schéma serveur
/// changé), on remonte une erreur — le caller affichera et l'agent
/// refusera de démarrer. Cohérent avec le reste du resolve : un
/// shipper en cours d'init mal configuré doit être loud.
fn autoenroll_and_persist(s: &mut ShipperSection, path: &Path) -> Result<(), String> {
    let server_url = s
        .server_url
        .clone()
        .ok_or_else(|| "shipper.server_url is required for auto-enroll".to_string())?;
    let enrollment_token = s
        .enrollment_token
        .clone()
        .ok_or_else(|| "shipper.enrollment_token is required for auto-enroll".to_string())?;

    eprintln!("[agent] no agent_id / token persisted yet — running auto-enroll against {server_url}");
    let timeout = Duration::from_secs(s.timeout_secs.max(1));
    let result = crate::shipper::enroll::perform(&server_url, &enrollment_token, timeout)
        .map_err(|e| format!("auto-enroll failed: {e}"))?;
    eprintln!(
        "[agent] enroll succeeded — agent_id={} (persisting to {:?})",
        result.agent_id, path
    );

    persist_enrollment(path, &result.agent_id, &result.agent_token)?;
    s.fill_from_enroll(result.agent_id, result.agent_token);
    Ok(())
}

/// Re-écrit `agent.json` après un enroll réussi : patche
/// `shipper.agent_id` et `shipper.token_plain`, supprime
/// `shipper.enrollment_token`. On manipule le JSON brut pour
/// préserver les autres clés (commentaires, champs non liés au
/// shipper, ordre raisonnable). Si la lecture/parse re-échoue ici,
/// c'est qu'il y a une race avec un éditeur externe — on remonte
/// l'erreur plutôt que d'écraser silencieusement.
fn persist_enrollment(
    path: &Path,
    agent_id: &str,
    agent_token: &str,
) -> Result<(), String> {
    use serde_json::Value;

    let bytes = std::fs::read(path).map_err(|e| format!("re-read {:?}: {}", path, e))?;
    let mut root: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("re-parse {:?}: {}", path, e))?;

    let shipper = root
        .get_mut("shipper")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "shipper section disappeared during enroll".to_string())?;
    shipper.insert("agent_id".into(), Value::String(agent_id.to_string()));
    shipper.insert("token_plain".into(), Value::String(agent_token.to_string()));
    shipper.remove("enrollment_token");
    // Si un `token_encrypted_b64` traîne vide depuis le skeleton par
    // défaut, on le supprime aussi — sinon le prochain load rejette
    // ("mutually exclusive" plein vs DPAPI).
    if shipper
        .get("token_encrypted_b64")
        .and_then(Value::as_str)
        .map(str::is_empty)
        .unwrap_or(false)
    {
        shipper.remove("token_encrypted_b64");
    }

    let mut content = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("re-serialize config: {}", e))?;
    content.push('\n');
    std::fs::write(path, content).map_err(|e| format!("write {:?}: {}", path, e))?;
    Ok(())
}

fn resolve_agent(s: AgentSection) -> AgentConfig {
    let d = AgentConfig::default();
    AgentConfig {
        console_output: s.console_output.unwrap_or(d.console_output),
        spool_dir: s.spool_dir.map(PathBuf::from).unwrap_or(d.spool_dir),
        max_bytes_per_file: s.max_bytes_per_file.unwrap_or(d.max_bytes_per_file),
        max_age: s.max_age_secs.map(Duration::from_secs).unwrap_or(d.max_age),
        max_total_bytes: s.max_total_bytes.unwrap_or(d.max_total_bytes),
        channel_capacity: s.channel_capacity.unwrap_or(d.channel_capacity),
        zstd_level: s.zstd_level.unwrap_or(d.zstd_level),
    }
}

/// Write a default `agent.json` skeleton at `path`.
///
/// Called from [`AppConfig::load`] when the file is missing. Mirrors the
/// in-memory defaults of [`AgentConfig`] so a freshly-installed agent
/// has a self-explanatory config on disk, with the `shipper` section
/// disabled and pre-filled with placeholder values the operator can
/// edit. Creates the parent directory if needed (`%ProgramData%\WazabiEDR`
/// won't exist on a clean machine).
fn write_default_config(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create_dir_all {:?}: {}", parent, e))?;
    }

    let d = AgentConfig::default();
    let cc = ControlConfig::default();
    let dc = DetectionConfig::default();
    // Default skeleton. Everything that needs operator input lives in
    // `shipper` (server URL + enrollment token). The rest is the
    // production posture: control + ETW + polling ON, detection OFF
    // (no .waza rules deployed yet), console_output OFF (we run as a
    // service in prod, no stdout consumer).
    let skeleton = serde_json::json!({
        "agent": {
            "console_output": d.console_output,
            "spool_dir": d.spool_dir.to_string_lossy(),
            "max_bytes_per_file": d.max_bytes_per_file,
            "max_age_secs": d.max_age.as_secs(),
            "max_total_bytes": d.max_total_bytes,
            "channel_capacity": d.channel_capacity,
            "zstd_level": d.zstd_level,
        },
        "shipper": {
            "enabled": false,
            "server_url": "http://127.0.0.1:8080",
            "enrollment_token": "",
            "agent_id": "",
            "token_plain": "",
            "verify_tls": true,
            "timeout_secs": 30,
            "poll_interval_secs": 5,
            "max_backoff_secs": 300
        },
        "control": {
            "enabled": true,
            "heartbeat_interval_secs": cc.heartbeat_interval.as_secs(),
            "send_alerts": cc.send_alerts
        },
        "detection": {
            "enabled": false,
            "rules_path": dc.rules_path.to_string_lossy(),
            "schema_path": "",
            "default_window_secs": dc.default_window.as_secs(),
            "reload_interval_secs": dc.reload_interval.as_secs()
        },
        "etw": {
            "enabled": true,
            "dns": true,
            "tcp": true,
            "powershell": true,
            "wmi": true,
            "schannel": true,
            "amsi": true
        },
        "polling": {
            "enabled": true,
            "services": true,
            "scheduled_tasks": true,
            "interval_secs": 30,
            "silent_first_snapshot": true
        }
    });

    let mut content = serde_json::to_string_pretty(&skeleton)
        .map_err(|e| format!("serialize default config: {}", e))?;
    content.push('\n');

    std::fs::write(path, content).map_err(|e| format!("write {:?}: {}", path, e))
}

/// Print a short message explaining where the config file lives and
/// exit. Called from `main` when any CLI argument is supplied — the
/// agent has no flags anymore.
pub fn print_help_and_exit() -> ! {
    eprintln!(
        "WazabiEDR agent — single-file configuration.\n\
         \n\
         The agent takes no CLI flags. All tunables live in:\n  \
           {}\n\
         \n\
         See WazabiEDR_Doc/usage/configuring-shipper.md for the full schema.\n\
         Minimal example (spool-only, no upload):\n\
         \n\
         {{\n  \
           \"agent\": {{ \"console_output\": true }}\n\
         }}",
        default_path().display()
    );
    std::process::exit(0);
}
