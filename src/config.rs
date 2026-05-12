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
//!     "url": "https://logs.example.com/wazabi/ingest",
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

use crate::shipper::config::{ShipperConfig, ShipperSection, resolve_shipper};

/// Default location of the config file: `%ProgramData%\WazabiEDR\agent.json`.
pub const AGENT_CONFIG_FILE: &str = "WazabiEDR\\agent.json";

/// Resolved configuration handed to `main`.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub agent: AgentConfig,
    /// `None` means spool-only mode (no upload).
    pub shipper: Option<ShipperConfig>,
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
            console_output: true,
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
                });
            }
            Err(e) => return Err(format!("read {:?}: {}", path, e)),
        };

        let parsed: ConfigFile =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {:?}: {}", path, e))?;

        let agent = resolve_agent(parsed.agent.unwrap_or_default());
        let shipper = match parsed.shipper {
            Some(s) if s.is_enabled() => Some(resolve_shipper(s)?),
            _ => None,
        };

        Ok(Self { agent, shipper })
    }
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
    let skeleton = serde_json::json!({
        "_comment": "WazabiEDR agent — auto-generated default config. \
                     See WazabiEDR_Doc/usage/configuring-shipper.md for the full schema.",
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
            "url": "https://logs.example.com/wazabi/ingest",
            "token_encrypted_b64": "",
            "debug": false
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
