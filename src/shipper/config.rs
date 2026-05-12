//! Shipper section of `agent.json`: raw JSON shape + resolver.
//!
//! The full file is loaded by `crate::config`; this module exposes the
//! [`ShipperSection`] type that mirrors the JSON, and
//! [`resolve_shipper`] which turns it into a validated, ready-to-use
//! [`ShipperConfig`] (DPAPI ciphertext decrypted, URL validated, …).
//!
//! ```json
//! {
//!   "shipper": {
//!     "enabled": true,
//!     "url": "https://logs.example.com/wazabi/ingest",
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
//! - `token_encrypted_b64` is DPAPI-LOCAL_MACHINE ciphertext, base64'd.
//!   See `WazabiEDR_Doc/usage/configuring-shipper.md` for the
//!   PowerShell snippet that generates it.
//! - `token_plain` is a fallback for development setups — the agent
//!   logs a warning when it's used and refuses if both are set at once.
//! - Everything else has sensible defaults; only `url` (and a token in
//!   one form or the other) is strictly required when the section is
//!   enabled.

use std::time::Duration;

use serde::Deserialize;

use crate::shipper::secret::{b64_decode, dpapi_unprotect};

/// Resolved, validated shipper config — what the running shipper sees.
#[derive(Clone, Debug)]
pub struct ShipperConfig {
    pub url: String,
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
    /// Debug mode: decompress each batch in memory before POSTing so the
    /// server receives plain NDJSON (no `Content-Encoding: zstd`). Lets
    /// the operator point the agent at a trivial HTTP listener and read
    /// the payload directly. NOT for production — defeats the spool's
    /// compression benefit on bandwidth.
    pub debug: bool,
}

/// Raw JSON shape — what `crate::config` deserialises from disk.
#[derive(Deserialize)]
pub struct ShipperSection {
    #[serde(default = "default_enabled")]
    enabled: bool,
    url: Option<String>,
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
    #[serde(default)]
    debug: bool,
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

    let url = section
        .url
        .ok_or_else(|| "shipper.url is required".to_string())?;
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(format!(
            "shipper.url must start with http:// or https:// (got {url:?})"
        ));
    }
    // HTTP-only is allowed for dev/testing but the operator deserves a
    // loud warning — exfil over plaintext is not an EDR posture.
    if url.starts_with("http://") {
        eprintln!(
            "[shipper] WARNING: url is plaintext HTTP, all telemetry will \
             travel in clear — production MUST use https://"
        );
    }

    if section.debug {
        eprintln!(
            "[shipper] debug mode: batches will be decompressed before POST \
             — server receives plain NDJSON (Content-Encoding header dropped)"
        );
    }

    Ok(ShipperConfig {
        url,
        tenant_id: section.tenant_id,
        tags: section.tags,
        token,
        verify_tls: section.verify_tls,
        timeout: Duration::from_secs(section.timeout_secs.max(1)),
        poll_interval: Duration::from_secs(section.poll_interval_secs.max(1)),
        max_backoff: Duration::from_secs(section.max_backoff_secs.max(1)),
        debug: section.debug,
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
