//! Shipper section of `agent.json`: raw JSON shape + resolver.
//!
//! The full file is loaded by `crate::config`; this module exposes the
//! [`ShipperSection`] type that mirrors the JSON, and
//! [`resolve_shipper`] which turns it into a validated, ready-to-use
//! [`ShipperConfig`] (DPAPI ciphertext decrypted, base URL validated, …).
//!
//! The target is **Wazabi Server** (`WazabiEDR_Server/`) — the FastAPI
//! backend exposes `POST /api/v1/agents/{agent_id}/logs` for NDJSON
//! telemetry ingestion (indexed into OpenSearch `wazabi-events`). The
//! shipper builds that URL from `server_url` + `agent_id`; pointing the
//! agent at a generic backend (Loki, Splunk HEC, …) is no longer
//! supported in v1 — see `WazabiEDR_Doc/reference/server-api.md`.
//!
//! ```json
//! {
//!   "shipper": {
//!     "enabled": true,
//!     "server_url": "https://wazabi.example.com",
//!     "agent_id": "5f1b3a8e-1c4f-4d2e-9b8a-7e3f6a9c0d11",
//!     "tenant_id": "acme",
//!     "tags": { "env": "prod", "region": "eu-w1" },
//!     "token_encrypted_b64": "AQAAANC...",
//!     "verify_tls": true,
//!     "timeout_secs": 30,
//!     "poll_interval_secs": 5,
//!     "max_backoff_secs": 300
//!   }
//! }
//! ```
//!
//! - `server_url` is the base URL of Wazabi Server. The shipper appends
//!   `/api/v1/agents/{agent_id}/logs` itself.
//! - `agent_id` is the UUID assigned by the server at enrolment. Until
//!   the agent learns to enrol itself (out of scope for v1, see
//!   `WazabiEDR_Doc/architecture/shipper.md`), it must be pre-provisioned
//!   in the file.
//! - `token_encrypted_b64` is DPAPI-LOCAL_MACHINE ciphertext, base64'd.
//!   See `WazabiEDR_Doc/usage/configuring-shipper.md` for the
//!   PowerShell snippet that generates it.
//! - `token_plain` is a fallback for development setups — the agent
//!   logs a warning when it's used and refuses if both are set at once.
//! - Everything else has sensible defaults; only `server_url`,
//!   `agent_id` and one of the token forms are strictly required when
//!   the section is enabled.

use std::time::Duration;

use serde::Deserialize;

use crate::shipper::secret::{b64_decode, dpapi_unprotect};

/// Resolved, validated shipper config — what the running shipper sees.
#[derive(Clone, Debug)]
pub struct ShipperConfig {
    /// Base URL of Wazabi Server (scheme + host + optional port). No
    /// trailing slash, no path. The shipper builds the full ingest URL
    /// by appending `/api/v1/agents/{agent_id}/logs`.
    pub server_url: String,
    /// UUID assigned to this agent by the server at enrolment. The
    /// agent does not currently call `/enroll` itself — operator
    /// provisions it in `agent.json`.
    pub agent_id: String,
    pub tenant_id: Option<String>,
    /// Free-form tags appended as HTTP headers (`X-Wazabi-Tag-<key>`).
    /// Kept simple on purpose — anything more structured belongs in
    /// the log server, not in client config.
    pub tags: std::collections::BTreeMap<String, String>,
    /// Bearer token, already decrypted. Never logged.
    pub token: String,
    pub verify_tls: bool,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub max_backoff: Duration,
}

impl ShipperConfig {
    /// Build the full `/logs` endpoint URL once at startup so the hot
    /// loop doesn't reformat it on every iteration. The server expects
    /// `{server_url}/api/v1/agents/{agent_id}/logs` exactly — `agent_id`
    /// is the path parameter, not a header.
    pub fn logs_endpoint(&self) -> String {
        format!("{}/api/v1/agents/{}/logs", self.server_url, self.agent_id)
    }
}

/// Raw JSON shape — what `crate::config` deserialises from disk.
#[derive(Deserialize)]
pub struct ShipperSection {
    #[serde(default = "default_enabled")]
    enabled: bool,
    server_url: Option<String>,
    agent_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    tags: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    token_encrypted_b64: Option<String>,
    #[serde(default)]
    token_plain: Option<String>,
    #[serde(default = "default_verify_tls")]
    verify_tls: bool,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
    #[serde(default = "default_poll_interval_secs")]
    poll_interval_secs: u64,
    #[serde(default = "default_max_backoff_secs")]
    max_backoff_secs: u64,
}

impl ShipperSection {
    /// Whether the section opts the shipper in. `enabled: false` is the
    /// way to keep the credentials in the file but disable shipping.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

fn default_enabled() -> bool {
    true
}
fn default_verify_tls() -> bool {
    true
}
fn default_timeout_secs() -> u64 {
    30
}
fn default_poll_interval_secs() -> u64 {
    5
}
fn default_max_backoff_secs() -> u64 {
    300
}

/// Validate + decrypt the section into a [`ShipperConfig`]. Called by
/// `crate::config` after deserialising the whole file. The caller has
/// already checked `is_enabled`, so the only paths through this
/// function are "everything good → `Ok`" and "operator made a
/// mistake → `Err`".
pub fn resolve_shipper(section: ShipperSection) -> Result<ShipperConfig, String> {
    let token = resolve_token(&section)?;

    let mut server_url = section
        .server_url
        .ok_or_else(|| "shipper.server_url is required".to_string())?;
    if !server_url.starts_with("https://") && !server_url.starts_with("http://") {
        return Err(format!(
            "shipper.server_url must start with http:// or https:// (got {server_url:?})"
        ));
    }
    // Trailing slash would produce `…//api/v1/…`. Strip once at parse
    // time so the hot loop doesn't have to care.
    while server_url.ends_with('/') {
        server_url.pop();
    }
    // HTTP-only is allowed for dev/testing but the operator deserves a
    // loud warning — exfil over plaintext is not an EDR posture.
    if server_url.starts_with("http://") {
        eprintln!(
            "[shipper] WARNING: server_url is plaintext HTTP, all telemetry will \
             travel in clear — production MUST use https://"
        );
    }

    let agent_id = section
        .agent_id
        .ok_or_else(|| "shipper.agent_id is required (UUID assigned by Wazabi Server)".to_string())?;
    if agent_id.trim().is_empty() {
        return Err("shipper.agent_id must not be empty".into());
    }
    // We don't strictly parse the UUID — letting the server return 404
    // on a malformed id is fine and avoids pulling a uuid dependency.
    // But we want the obvious typos caught: spaces, control chars.
    if agent_id
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "shipper.agent_id contains whitespace/control chars: {agent_id:?}"
        ));
    }

    Ok(ShipperConfig {
        server_url,
        agent_id,
        tenant_id: section.tenant_id,
        tags: section.tags,
        token,
        verify_tls: section.verify_tls,
        timeout: Duration::from_secs(section.timeout_secs.max(1)),
        poll_interval: Duration::from_secs(section.poll_interval_secs.max(1)),
        max_backoff: Duration::from_secs(section.max_backoff_secs.max(1)),
    })
}

/// Resolve the bearer token, preferring the DPAPI-protected form. The
/// plaintext fallback exists only for local development — production
/// installs should never carry one.
fn resolve_token(section: &ShipperSection) -> Result<String, String> {
    match (&section.token_encrypted_b64, &section.token_plain) {
        (Some(_), Some(_)) => {
            Err("shipper: token_encrypted_b64 and token_plain are mutually exclusive".into())
        }
        (Some(b64), None) => {
            let cipher = b64_decode(b64).map_err(|e| format!("token_encrypted_b64: {e}"))?;
            let plain = dpapi_unprotect(&cipher)
                .map_err(|e| format!("token_encrypted_b64 decrypt: {e}"))?;
            String::from_utf8(plain).map_err(|e| format!("token not utf-8: {e}"))
        }
        (None, Some(plain)) => {
            eprintln!(
                "[shipper] WARNING: token_plain in use — protect with DPAPI \
                 (token_encrypted_b64) before going to production"
            );
            Ok(plain.clone())
        }
        (None, None) => {
            Err("shipper: a token is required (token_encrypted_b64 or token_plain)".into())
        }
    }
}
