//! Thin synchronous HTTP client for the Wazabi Server control-plane
//! endpoints (`/api/v1/agents/{id}/…` + `/api/v1/profiles/{id}/template`).
//!
//! Same conventions as [`crate::shipper`] and [`crate::shipper::enroll`]:
//! `ureq` (sync, rustls) with the `json` feature off, so request bodies
//! are serialised with `serde_json::to_vec` and responses read as a
//! string then `serde_json::from_str`. Every call sets
//! `Authorization: Bearer <token>` per-request.
//!
//! The request/response structs here mirror the server's Pydantic schemas
//! (`WazabiEDR_Server/app/schemas/agent.py` + `profile.py`). They are
//! intentionally lenient on responses (`#[serde(default)]`, extra fields
//! ignored) so a server that grows a field doesn't break the agent.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::ServerCreds;

/// One module the agent reports as loaded (heartbeat) — mirrors the
/// server's `LoadedModuleRef`. Also the shape we keep in [`ProfileState`].
///
/// [`ProfileState`]: super::ProfileState
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRef {
    pub id: String,
    pub version: String,
}

/// Une erreur de parse rencontrée par le moteur Waza sur une règle
/// poussée par le serveur. Remontée à chaque heartbeat — c'est l'unique
/// canal de feedback puisque le serveur ne valide pas avant push (cf.
/// architecture : moteur uniquement côté agent).
///
/// Liste **complète** à chaque envoi : le serveur réconcilie en remplaçant
/// l'ensemble des erreurs connues pour cet agent. Liste vide ⇒ tout
/// parse côté agent.
#[derive(Debug, Clone, Serialize)]
pub struct RuleErrorOut {
    pub rule_name: String,
    pub message: String,
}

/// Body of `POST /agents/{id}/heartbeat`.
#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub status: &'static str,
    pub agent_version: &'static str,
    pub last_rule_version: i64,
    pub profile_version: i64,
    pub modules_loaded: Vec<ModuleRef>,
    /// Erreurs de parse rencontrées au dernier sync de profil. Snapshot
    /// envoyé tel quel à chaque tick — pas de delta.
    #[serde(default)]
    pub rule_errors: Vec<RuleErrorOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
}

/// One command queued for the agent — mirrors the server's `CommandOut`.
#[derive(Debug, Clone, Deserialize)]
pub struct CommandOut {
    pub id: String,
    #[serde(rename = "type")]
    pub cmd_type: String,
    /// The command's parameters. Read by [`super::executor`] to dispatch
    /// (e.g. extract `pid` for `kill_process`); types without a local
    /// executor see this field walk straight back into the ack `result`
    /// as audit context.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Response of `POST /agents/{id}/heartbeat`.
#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    #[serde(default)]
    pub server_time: String,
    #[serde(default)]
    pub current_profile_version: i64,
    #[serde(default)]
    pub pending_commands: Vec<CommandOut>,
    /// Actions plugin à réconcilier côté agent (install/update/revoke).
    /// Idempotent : le serveur renvoie la même action tant que l'agent n'a
    /// pas reporté un status qui la résout.
    #[serde(default)]
    pub pending_plugins: Vec<PendingPluginAction>,
    #[serde(default)]
    pub next_checkin_seconds: i64,
}

/// One plugin action the server wants the agent to apply. Mirror of the
/// server's `PendingPluginAction` (`WazabiEDR_Server/app/schemas/plugin.py`).
#[derive(Debug, Clone, Deserialize)]
pub struct PendingPluginAction {
    pub plugin_package_id: String,
    pub version: String,
    /// `"install"` | `"update"` | `"revoke"`.
    pub action: String,
    /// UUID retourné par `wedr-plugin enroll` lors d'une install antérieure.
    /// Présent uniquement pour `action="revoke"` quand le serveur connaît
    /// la correspondance — sinon l'agent doit faire son propre lookup.
    #[serde(default)]
    pub plugin_id_local: Option<String>,
}

/// Response of `GET /plugins/{id}/info` — what the agent needs to invoke
/// `wedr-plugin enroll`. The actual manifest is written by `wedr-plugin`
/// (cf. WazabiEDR_Utils) — the server never produces a PluginManifest JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginInfoForAgent {
    /// Echo du UUID — l'agent le connaît déjà via le `PendingPluginAction`
    /// qui a déclenché ce GET. Gardé pour cohérence de contrat ; pas lu.
    #[allow(dead_code)]
    pub plugin_package_id: String,
    pub name: String,
    pub vendor: String,
    pub version: String,
    pub artifact_filename: String,
    pub auto_launch: bool,
    #[serde(default)]
    pub extras: Vec<PluginExtraInfo>,
    /// Variables d'env déclarées dans `runtime.env` du manifest TOML du
    /// paquet. Passées à `wedr-plugin enroll --env K=V` puis persistées
    /// dans le manifest local, le supervisor les pose sur le `Command`
    /// du plugin au spawn.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginExtraInfo {
    pub filename: String,
    /// Info éditoriale ("library" | "script" | "data"). L'agent traite
    /// tous les extras de la même façon (drop à côté du binaire principal).
    #[allow(dead_code)]
    pub kind: String,
}

/// Body of `POST /agents/{id}/plugins/{pid}/status` — what the agent reports
/// after each install/update/revoke transition (and as an hourly sentinel).
#[derive(Debug, Serialize)]
pub struct PluginStatusReport<'a> {
    pub phase: &'a str,
    pub version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id_local: Option<&'a str>,
    pub events_emitted: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_ts: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_crash_ts: Option<&'a str>,
    pub crash_count_1h: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}

/// A module the assigned profile requires — subset of the server's
/// `RequiredModuleRef` (we only need id + version for `modules_loaded`).
#[derive(Debug, Clone, Deserialize)]
pub struct RequiredModuleRef {
    pub id: String,
    pub version: String,
}

/// Response of `GET /agents/{id}/profile` — profile metadata only.
#[derive(Debug, Deserialize)]
pub struct ProfileMetadata {
    pub profile_id: String,
    pub version: i64,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub modules_required: Vec<RequiredModuleRef>,
}

/// Body of `POST /agents/{id}/alerts` — one alert. `module` must be a
/// valid server `AgentModule` value (validated by the caller).
#[derive(Debug, Serialize)]
pub struct AlertOut<'a> {
    pub ts: &'a str,
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub severity: &'a str,
    pub module: &'a str,
    pub action_taken: &'a str,
    pub evidence: &'a serde_json::Value,
}

/// Synchronous control-plane client. Cheap to build; holds the shared
/// `ureq::Agent` (connection pool) and the resolved server credentials.
pub struct Client {
    agent: ureq::Agent,
    creds: ServerCreds,
}

impl Client {
    pub fn new(creds: ServerCreds) -> Self {
        if !creds.verify_tls {
            eprintln!(
                "[control] WARNING: verify_tls=false requested but TLS \
                 verification cannot be disabled in this build — server \
                 certificate will still be validated"
            );
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(creds.timeout)
            .build();
        Self { agent, creds }
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{}", self.creds.server_url, suffix)
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.creds.token)
    }

    /// `POST /agents/{id}/heartbeat`. Returns the parsed response.
    pub fn heartbeat(&self, req: &HeartbeatRequest) -> Result<HeartbeatResponse, String> {
        let url = self.url(&format!("/api/v1/agents/{}/heartbeat", self.creds.agent_id));
        let body = serde_json::to_vec(req).map_err(|e| format!("serialize heartbeat: {e}"))?;
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &self.bearer())
            .send_bytes(&body)
            .map_err(stringify_err)?;
        let text = resp
            .into_string()
            .map_err(|e| format!("read heartbeat response: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("parse heartbeat response: {e} — body: {text}"))
    }

    /// `GET /agents/{id}/profile`. `Ok(None)` on 404 (no profile assigned).
    pub fn get_profile_metadata(&self) -> Result<Option<ProfileMetadata>, String> {
        let url = self.url(&format!("/api/v1/agents/{}/profile", self.creds.agent_id));
        match self
            .agent
            .get(&url)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(resp) => {
                let text = resp
                    .into_string()
                    .map_err(|e| format!("read profile response: {e}"))?;
                let meta = serde_json::from_str(&text)
                    .map_err(|e| format!("parse profile metadata: {e} — body: {text}"))?;
                Ok(Some(meta))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(stringify_err(e)),
        }
    }

    /// `GET /profiles/{id}/template`. Returned verbatim as JSON: the agent
    /// persists it for inspection but does not (yet) apply it to the Waza
    /// engine (`waza_definition` translation is out of scope).
    pub fn get_profile_template(&self, profile_id: &str) -> Result<serde_json::Value, String> {
        let url = self.url(&format!("/api/v1/profiles/{}/template", profile_id));
        let resp = self
            .agent
            .get(&url)
            .set("Authorization", &self.bearer())
            .call()
            .map_err(stringify_err)?;
        let text = resp
            .into_string()
            .map_err(|e| format!("read template response: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("parse template: {e}"))
    }

    /// `POST /agents/{id}/alerts` with a batch of alerts. Returns the
    /// number the server acknowledged (`received`), best-effort parsed.
    pub fn post_alerts(&self, alerts: &[AlertOut<'_>]) -> Result<usize, String> {
        let url = self.url(&format!("/api/v1/agents/{}/alerts", self.creds.agent_id));
        let body = serde_json::json!({ "alerts": alerts });
        let bytes = serde_json::to_vec(&body).map_err(|e| format!("serialize alerts: {e}"))?;
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &self.bearer())
            .send_bytes(&bytes)
            .map_err(stringify_err)?;
        // The body is `{ alert_ids, received, skipped }`; we only surface
        // `received` for the stats line. Parse best-effort.
        let received = resp
            .into_string()
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("received").and_then(|n| n.as_u64()))
            .map(|n| n as usize)
            .unwrap_or(alerts.len());
        Ok(received)
    }

    // ---------------------------------------------------------------
    // Plugin distribution endpoints (cf. plugin-distribution.md §3)
    // ---------------------------------------------------------------

    /// `GET /plugins/{id}/info`. `Ok(None)` on 404 (unknown / unassigned).
    /// `Err` on 409 (package not yet ready — agent should retry next tick).
    pub fn get_plugin_info(
        &self,
        plugin_package_id: &str,
    ) -> Result<Option<PluginInfoForAgent>, String> {
        let url = self.url(&format!("/api/v1/plugins/{}/info", plugin_package_id));
        match self
            .agent
            .get(&url)
            .set("Authorization", &self.bearer())
            .call()
        {
            Ok(resp) => {
                let text = resp
                    .into_string()
                    .map_err(|e| format!("read plugin info: {e}"))?;
                let info = serde_json::from_str(&text)
                    .map_err(|e| format!("parse plugin info: {e} — body: {text}"))?;
                Ok(Some(info))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(stringify_err(e)),
        }
    }

    /// `GET /plugins/{id}/binary`. Streams to `dest` and returns the
    /// expected SHA-256 (from header `X-Plugin-SHA256`) so the caller
    /// verifies after writing.
    pub fn download_plugin_binary(
        &self,
        plugin_package_id: &str,
        dest: &std::path::Path,
    ) -> Result<String, String> {
        let url = self.url(&format!("/api/v1/plugins/{}/binary", plugin_package_id));
        self.download_to(&url, dest)
    }

    /// `GET /plugins/{id}/files/{filename}`. Same contract as the primary
    /// binary — extras are pushed to disk next to the binary on the agent.
    pub fn download_plugin_extra(
        &self,
        plugin_package_id: &str,
        filename: &str,
        dest: &std::path::Path,
    ) -> Result<String, String> {
        let url = self.url(&format!(
            "/api/v1/plugins/{}/files/{}",
            plugin_package_id, filename
        ));
        self.download_to(&url, dest)
    }

    /// Shared streaming download: writes the body to `dest`, returns the
    /// SHA-256 declared by the server (header `X-Plugin-SHA256` for the
    /// primary binary, `X-Plugin-File-SHA256` for extras). Empty string
    /// if neither header is present (caller treats as "skip verify").
    fn download_to(&self, url: &str, dest: &std::path::Path) -> Result<String, String> {
        let resp = self
            .agent
            .get(url)
            .set("Authorization", &self.bearer())
            .call()
            .map_err(stringify_err)?;
        let expected_sha = resp
            .header("X-Plugin-SHA256")
            .or_else(|| resp.header("X-Plugin-File-SHA256"))
            .unwrap_or("")
            .to_string();
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
        let mut file = std::fs::File::create(dest)
            .map_err(|e| format!("create {dest:?}: {e}"))?;
        std::io::copy(&mut resp.into_reader(), &mut file)
            .map_err(|e| format!("write {dest:?}: {e}"))?;
        Ok(expected_sha)
    }

    /// `POST /agents/{id}/plugins/{pid}/status`. 204 on success.
    pub fn report_plugin_status(
        &self,
        plugin_package_id: &str,
        report: &PluginStatusReport<'_>,
    ) -> Result<(), String> {
        let url = self.url(&format!(
            "/api/v1/agents/{}/plugins/{}/status",
            self.creds.agent_id, plugin_package_id
        ));
        let bytes = serde_json::to_vec(report)
            .map_err(|e| format!("serialize plugin status: {e}"))?;
        self.agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &self.bearer())
            .send_bytes(&bytes)
            .map_err(stringify_err)?;
        Ok(())
    }

    /// `POST /agents/{id}/commands/{cmd_id}/ack`. `result` is embedded
    /// under the request's `result` field for server-side audit.
    pub fn ack_command(
        &self,
        command_id: &str,
        status: &str,
        result: serde_json::Value,
    ) -> Result<(), String> {
        let url = self.url(&format!(
            "/api/v1/agents/{}/commands/{}/ack",
            self.creds.agent_id, command_id
        ));
        let body = serde_json::json!({ "status": status, "result": result });
        let bytes = serde_json::to_vec(&body).map_err(|e| format!("serialize ack: {e}"))?;
        self.agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &self.bearer())
            .send_bytes(&bytes)
            .map_err(stringify_err)?;
        Ok(())
    }
}

/// Render a `ureq::Error` into a short string, distinguishing an HTTP
/// status response (server reachable, returned non-2xx) from a transport
/// failure (DNS, refused, TLS) — useful when reading the agent's stderr.
fn stringify_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            format!("HTTP {code} — {body}")
        }
        ureq::Error::Transport(t) => format!("transport: {t}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_request_serializes_to_server_shape() {
        let req = HeartbeatRequest {
            status: "healthy",
            agent_version: "9.9.9",
            last_rule_version: 0,
            profile_version: 3,
            modules_loaded: vec![ModuleRef {
                id: "m1".into(),
                version: "1.0".into(),
            }],
            rule_errors: vec![RuleErrorOut {
                rule_name: "Boom".into(),
                message: "line 2: expected ')'".into(),
            }],
            metrics: None,
        };
        let v: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert_eq!(v["status"], "healthy");
        assert_eq!(v["profile_version"], 3);
        assert_eq!(v["modules_loaded"][0]["id"], "m1");
        assert_eq!(v["rule_errors"][0]["rule_name"], "Boom");
        assert_eq!(v["rule_errors"][0]["message"], "line 2: expected ')'");
        // metrics is None → omitted, not null (server treats it optional).
        assert!(v.get("metrics").is_none());
    }

    #[test]
    fn heartbeat_response_parses_and_ignores_unknown_fields() {
        let body = r#"{
            "server_time": "2026-06-22T10:00:00Z",
            "current_profile_version": 4,
            "pending_commands": [
                {"id": "c1", "type": "kill_process", "payload": {"pid": 42}}
            ],
            "next_checkin_seconds": 60,
            "future_field": "ignored"
        }"#;
        let resp: HeartbeatResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.current_profile_version, 4);
        assert_eq!(resp.next_checkin_seconds, 60);
        assert_eq!(resp.pending_commands.len(), 1);
        assert_eq!(resp.pending_commands[0].cmd_type, "kill_process");
    }

    #[test]
    fn profile_metadata_parses_subset() {
        // Server sends more fields than we model — they must be ignored.
        let body = r#"{
            "profile_id": "p1",
            "version": 5,
            "hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "modules_required": [
                {"id": "m1", "module_type": "kernel_callback", "version": "1.2",
                 "binary_sha256": "x", "binary_url": "/b", "blueprint_url": "/bp"}
            ],
            "template_url": "/api/v1/profiles/p1/template",
            "updated_at": "2026-06-22T10:00:00Z"
        }"#;
        let meta: ProfileMetadata = serde_json::from_str(body).unwrap();
        assert_eq!(meta.profile_id, "p1");
        assert_eq!(meta.version, 5);
        assert_eq!(meta.modules_required.len(), 1);
        assert_eq!(meta.modules_required[0].id, "m1");
        assert_eq!(meta.modules_required[0].version, "1.2");
    }

    #[test]
    fn alert_out_serializes_to_alertin_shape() {
        let evidence = serde_json::json!({ "pid": 4321, "event_type": "thread_create" });
        let alert = AlertOut {
            ts: "2026-06-22T10:00:00.000Z",
            rule_id: "ProcessHollowingInjection",
            rule_name: "ProcessHollowingInjection",
            severity: "medium",
            module: "kernel_callback",
            action_taken: "alert",
            evidence: &evidence,
        };
        let v: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&alert).unwrap()).unwrap();
        assert_eq!(v["rule_id"], "ProcessHollowingInjection");
        assert_eq!(v["severity"], "medium");
        assert_eq!(v["module"], "kernel_callback");
        assert_eq!(v["action_taken"], "alert");
        assert_eq!(v["evidence"]["pid"], 4321);
    }

    // -- Online tests --------------------------------------------------
    // Exercise the REAL control-plane client against a running Wazabi
    // Server. `#[ignore]`d (need a server); run with
    // `cargo test -- --ignored` after `WAZABI_TEST_API_URL` is set.
    use crate::test_support;

    fn sample_heartbeat() -> HeartbeatRequest {
        HeartbeatRequest {
            status: "healthy",
            agent_version: "test",
            last_rule_version: 0,
            profile_version: 0,
            modules_loaded: vec![],
            rule_errors: vec![],
            metrics: None,
        }
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn heartbeat_ok() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped heartbeat_ok — set WAZABI_TEST_API_URL");
            return;
        };
        let (id, token) = test_support::enroll_agent(&ts);
        let client = Client::new(test_support::creds(&ts, id, token));
        let resp = client.heartbeat(&sample_heartbeat()).expect("heartbeat should succeed");
        assert!(resp.next_checkin_seconds >= 0);
        eprintln!(
            "[test] heartbeat ok — profile_v={} cmds={}",
            resp.current_profile_version,
            resp.pending_commands.len()
        );
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn profile_metadata_ok() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped profile_metadata_ok — set WAZABI_TEST_API_URL");
            return;
        };
        let (id, token) = test_support::enroll_agent(&ts);
        let client = Client::new(test_support::creds(&ts, id, token));
        // 404 (no profile assigned) is a valid outcome → Ok(None).
        let meta = client.get_profile_metadata().expect("profile metadata call should succeed");
        if let Some(meta) = meta {
            eprintln!("[test] profile v{} ({} modules)", meta.version, meta.modules_required.len());
            client
                .get_profile_template(&meta.profile_id)
                .expect("template fetch should succeed when a profile is assigned");
        } else {
            eprintln!("[test] no profile assigned (Ok(None)) — acceptable");
        }
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn post_alerts_ok() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped post_alerts_ok — set WAZABI_TEST_API_URL");
            return;
        };
        let (id, token) = test_support::enroll_agent(&ts);
        let client = Client::new(test_support::creds(&ts, id, token));
        let evidence = serde_json::json!({ "pid": 1234, "event_type": "thread_create" });
        let alerts = [AlertOut {
            ts: "2026-06-22T10:00:00.000Z",
            rule_id: "integration_test_rule",
            rule_name: "integration_test_rule",
            severity: "medium",
            module: "kernel_callback",
            action_taken: "alert",
            evidence: &evidence,
        }];
        let received = client.post_alerts(&alerts).expect("post_alerts should succeed");
        assert!(received >= 1, "server should accept at least one alert");
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn ack_unknown_command_404() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped ack_unknown_command_404 — set WAZABI_TEST_API_URL");
            return;
        };
        let (id, token) = test_support::enroll_agent(&ts);
        let client = Client::new(test_support::creds(&ts, id, token));
        // A well-formed but unknown command UUID → 404. (Happy-path ack
        // needs a console-created command, out of scope for this test.)
        let err = client
            .ack_command("00000000-0000-0000-0000-000000000000", "completed", serde_json::json!({}))
            .expect_err("acking an unknown command must fail");
        assert!(err.contains("404"), "expected HTTP 404, got: {err}");
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn heartbeat_bad_bearer_401() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped heartbeat_bad_bearer_401 — set WAZABI_TEST_API_URL");
            return;
        };
        let creds = test_support::creds(
            &ts,
            "00000000-0000-0000-0000-000000000000".to_string(),
            "not-a-valid-agent-token".to_string(),
        );
        let client = Client::new(creds);
        let err = client.heartbeat(&sample_heartbeat()).expect_err("bad bearer must be rejected");
        assert!(err.contains("401"), "expected HTTP 401, got: {err}");
    }

    #[test]
    #[ignore = "online: needs a running Wazabi Server (set WAZABI_TEST_API_URL)"]
    fn heartbeat_agent_id_mismatch_403() {
        let Some(ts) = test_support::server() else {
            eprintln!("skipped heartbeat_agent_id_mismatch_403 — set WAZABI_TEST_API_URL");
            return;
        };
        // Valid token, but a path agent_id that isn't this agent → 403.
        let (_id, token) = test_support::enroll_agent(&ts);
        let creds = test_support::creds(
            &ts,
            "11111111-1111-1111-1111-111111111111".to_string(),
            token,
        );
        let client = Client::new(creds);
        let err = client
            .heartbeat(&sample_heartbeat())
            .expect_err("agent_id ≠ token's agent must be rejected");
        assert!(err.contains("403"), "expected HTTP 403, got: {err}");
    }
}
