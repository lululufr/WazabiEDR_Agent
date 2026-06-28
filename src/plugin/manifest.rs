//! Plugin manifest: who is allowed to connect, and what we expect of them.
//!
//! Manifests live in a directory the agent treats as its enrolment root.
//! On Windows the default is `%ProgramData%\WazabiEDR\plugins\` — that
//! directory should be ACL'd Administrators-only at install time so an
//! unprivileged process cannot drop a manifest and self-enrol.
//!
//! Each manifest is a JSON document, one file per plugin, named
//! `<plugin_id>.json`:
//!
//! ```json
//! {
//!   "plugin_id":      "8f3c1d8e-5a8b-4ad0-94d2-cab9b1d0e2a0",
//!   "name":           "Acme Telemetry",
//!   "vendor":         "Acme Corp",
//!   "expected_path":  "C:\\Program Files\\Acme\\acme-edrplugin.exe",
//!   "expected_sha256": "f4b9…",
//!   "expected_signer": "CN=Acme Corp, O=Acme, C=FR",
//!   "revoked":        false,
//!   "enrolled_at":    "2026-05-09T14:00:00Z"
//! }
//! ```
//!
//! `expected_signer` is optional — when set, Authenticode is required.
//! `expected_sha256` is optional — when set, the binary content is
//! pinned. At least one of the two must be present, otherwise the
//! manifest is rejected at load time (we refuse to enrol something that
//! has no integrity guarantee at all).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Subdirectory we look for under `%ProgramData%`. Kept as a constant so
/// the enrolment tool in `WazabiEDR_Utils` can use the same value.
pub const PLUGINS_SUBDIR: &str = "WazabiEDR\\plugins";

/// On-disk manifest schema. Adding new fields is fine (give them a
/// `#[serde(default)]`). Removing or repurposing a field would require
/// versioning the manifest itself — TODO when we get there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub name: String,
    pub vendor: String,
    /// Absolute path to the plugin binary. Compared case-insensitively
    /// against the connecting process's image path on Windows (NTFS is
    /// case-preserving but case-insensitive by default).
    pub expected_path: String,
    /// Hex-encoded SHA-256 of the plugin binary, lowercase. Set this OR
    /// `expected_signer` (or both). Skipping both = manifest invalid.
    #[serde(default)]
    pub expected_sha256: Option<String>,
    /// Authenticode subject DN, e.g. `"CN=Acme Corp, O=Acme, C=FR"`.
    /// When present, the connecting binary must be signed AND the
    /// signer subject must match this string exactly.
    #[serde(default)]
    pub expected_signer: Option<String>,
    /// Toggle without removing the manifest. Useful for incident
    /// response: an admin can disable a plugin instantly by setting
    /// this and restarting (or in future: hot-reloading) the agent.
    #[serde(default)]
    pub revoked: bool,
    /// Free-form ISO-8601 timestamp recorded by the enrolment tool.
    /// Not used by the agent for any decision — just attribution.
    #[serde(default)]
    pub enrolled_at: Option<String>,
    /// When `true`, the agent's supervisor spawns the plugin's
    /// `expected_path` at startup and restarts it on crash with
    /// exponential backoff. Default `false` so an enroll is never an
    /// implicit "launch" — operators opt in explicitly.
    ///
    /// Revoked manifests are never auto-launched regardless of this
    /// flag.
    #[serde(default)]
    pub auto_launch: bool,

    /// Environment variables passed to the plugin process at spawn time.
    /// Populated from the upstream manifest TOML's `runtime.env` table
    /// at enrolment time. Without this, plugins like the hook injector
    /// never see `WEDR_HOOK_TARGETS=*` and fall back to their built-in
    /// default target list.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

/// Errors returned while loading the manifest store.
#[derive(Debug)]
pub enum ManifestLoadError {
    Io(std::io::Error),
    /// File parsed as JSON but a required field was missing or an
    /// invariant (`plugin_id` matches filename, at least one integrity
    /// check declared) failed. The string carries the path + reason.
    Invalid(String),
}

impl std::fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Invalid(s) => write!(f, "{s}"),
        }
    }
}

impl From<std::io::Error> for ManifestLoadError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Resolve the default manifest directory: `%ProgramData%\WazabiEDR\plugins`.
///
/// Falls back to `C:\ProgramData\WazabiEDR\plugins` if the env var is
/// missing — that's the OS default location for ProgramData anyway.
pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"));
    base.join(PLUGINS_SUBDIR.replace('\\', std::path::MAIN_SEPARATOR_STR))
}

/// In-memory snapshot of every valid manifest under [`default_dir`] (or
/// a caller-provided dir). Lookups are by `plugin_id` — that's the only
/// access pattern during a handshake.
///
/// A `ManifestStore` is **immutable**: hot-reload swaps the whole
/// store rather than mutating one in place. That keeps workers
/// lock-free for the entire session — they grab an `Arc<ManifestStore>`
/// snapshot at handshake time and never reach for it again.
pub struct ManifestStore {
    by_id: std::collections::HashMap<String, PluginManifest>,
    /// Cheap directory fingerprint computed at load time; the reload
    /// thread compares this against a freshly-walked one to decide
    /// whether anything changed since the last scan.
    fingerprint: u64,
}

impl ManifestStore {
    /// Load every `*.json` file in `dir`. Files that fail to parse, or
    /// that fail validation, are skipped with a warning to stderr —
    /// missing manifests must never prevent the agent from starting,
    /// but they should be loud enough that an admin notices.
    pub fn load_dir(dir: &Path) -> Result<Self, ManifestLoadError> {
        let mut by_id = std::collections::HashMap::new();
        let fingerprint = directory_fingerprint(dir);

        // A missing directory is normal on a host that has no plugins
        // enrolled yet. Treat it the same as an empty directory.
        if !dir.exists() {
            return Ok(Self { by_id, fingerprint });
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match Self::load_one(&path) {
                Ok(m) => {
                    if by_id.contains_key(&m.plugin_id) {
                        eprintln!(
                            "[plugin] duplicate plugin_id {:?} in {:?} — keeping first",
                            m.plugin_id, path
                        );
                        continue;
                    }
                    by_id.insert(m.plugin_id.clone(), m);
                }
                Err(e) => {
                    eprintln!("[plugin] skipping manifest {:?}: {}", path, e);
                }
            }
        }

        Ok(Self { by_id, fingerprint })
    }

    /// The fingerprint captured when this store was loaded. The reload
    /// thread compares it with [`directory_fingerprint`] called fresh
    /// to decide whether to re-load.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// An empty store — used as a fallback when the initial load fails
    /// so the server can still come up (and refuse all connections
    /// with `unknown_plugin_id`) until the next reload picks something up.
    pub fn empty() -> Self {
        Self {
            by_id: std::collections::HashMap::new(),
            fingerprint: 0,
        }
    }

    /// Read + validate a single manifest file.
    fn load_one(path: &Path) -> Result<PluginManifest, ManifestLoadError> {
        let bytes = fs::read(path)?;
        let m: PluginManifest = serde_json::from_slice(&bytes).map_err(|e| {
            ManifestLoadError::Invalid(format!("{:?}: not valid manifest JSON: {}", path, e))
        })?;

        // The filename should be `<plugin_id>.json`. Enforcing this
        // makes lookups O(1) by filename if we ever want to reload one
        // manifest in isolation, AND it prevents an attacker from
        // dropping a manifest claiming someone else's plugin_id while
        // hiding it under an innocuous filename.
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if stem != m.plugin_id {
            return Err(ManifestLoadError::Invalid(format!(
                "{:?}: filename stem {:?} does not match plugin_id {:?}",
                path, stem, m.plugin_id
            )));
        }

        if m.expected_sha256.is_none() && m.expected_signer.is_none() {
            return Err(ManifestLoadError::Invalid(format!(
                "{:?}: manifest must declare at least one of expected_sha256 / expected_signer",
                path
            )));
        }

        Ok(m)
    }

    /// Look up a manifest by plugin_id. Returns `None` if no plugin
    /// with that id is enrolled.
    pub fn get(&self, plugin_id: &str) -> Option<&PluginManifest> {
        self.by_id.get(plugin_id)
    }

    /// Number of plugins currently enrolled.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Iterate every loaded manifest. Used by the supervisor at agent
    /// startup to find which plugins to spawn.
    pub fn iter(&self) -> impl Iterator<Item = &PluginManifest> {
        self.by_id.values()
    }
}

/// Cheap fingerprint of every `*.json` file under `dir`: a 64-bit hash
/// over `(name, mtime_ns, size)` tuples, sorted by name so we don't
/// depend on `read_dir` order.
///
/// The point isn't cryptographic strength — it's "did anything we
/// loaded last time change?". A FNV-1a-like accumulation over the
/// triples is plenty: collisions are astronomically unlikely under
/// realistic enrolment activity, and the worst case (false negative)
/// is "operator's change picked up at the next interval instead of
/// this one".
pub fn directory_fingerprint(dir: &Path) -> u64 {
    let entries = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return 0,
    };

    let mut tuples: Vec<(String, u128, u64)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        tuples.push((name, mtime_ns, meta.len()));
    }
    tuples.sort_by(|a, b| a.0.cmp(&b.0));

    // FNV-1a 64-bit. Cheap, deterministic, dependency-free.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (name, mtime, size) in &tuples {
        for b in name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        for b in mtime.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        for b in size.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
    }
    h
}

/// Case-insensitive filesystem-path equality.
///
/// We compare the raw `OsString`s as lowercase Unicode — good enough for
/// the typical "Program Files" vs "PROGRAM FILES" mismatch. Symlinks and
/// 8.3 short names are NOT canonicalised here on purpose: the manifest
/// captures the path the admin enrolled with, and the connecting process
/// reports the path Windows resolved its image to. Mismatches mean
/// something legitimately differs and we shouldn't paper over it.
pub fn paths_match(a: &Path, b: &str) -> bool {
    let a_os: OsString = a.as_os_str().to_owned();
    let a_lower = a_os.to_string_lossy().to_lowercase();
    let b_lower = b.to_lowercase();
    a_lower == b_lower
}
