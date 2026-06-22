//! Shared helpers for the online integration tests that exercise the
//! agent's real server-communication code against a running Wazabi Server.
//!
//! These helpers are only compiled under `#[cfg(test)]`. The tests that
//! use them are all `#[ignore]`d: they need a reachable server and so are
//! opt-in via `cargo test -- --ignored`, with the target configured by
//! environment variables:
//!
//! - `WAZABI_TEST_API_URL`           — e.g. `http://localhost:8080` (required)
//! - `WAZABI_TEST_ENROLLMENT_TOKEN`  — defaults to `dev-enrollment-token-change-me`
//!
//! A test calls [`server`] first; if it returns `None` (URL unset) the
//! test prints a skip line and returns, so an accidental `--ignored` run
//! without configuration is a clear no-op rather than a confusing failure.

use std::time::Duration;

use crate::control::ServerCreds;
use crate::shipper::enroll;

/// Server target resolved from the environment.
pub struct TestServer {
    pub url: String,
    pub enrollment_token: String,
}

/// Resolve the test server from env, or `None` if `WAZABI_TEST_API_URL`
/// is unset. Trailing slashes are trimmed so URL building matches the
/// agent's own normalisation.
pub fn server() -> Option<TestServer> {
    let mut url = std::env::var("WAZABI_TEST_API_URL").ok()?;
    while url.ends_with('/') {
        url.pop();
    }
    if url.is_empty() {
        return None;
    }
    let enrollment_token = std::env::var("WAZABI_TEST_ENROLLMENT_TOKEN")
        .unwrap_or_else(|_| "dev-enrollment-token-change-me".to_string());
    Some(TestServer {
        url,
        enrollment_token,
    })
}

/// Enroll a fresh agent through the **real** [`enroll::perform`] and return
/// `(agent_id, agent_token)`. Panics on failure — a test that needs an
/// authenticated agent can't proceed without one.
pub fn enroll_agent(ts: &TestServer) -> (String, String) {
    let res = enroll::perform(&ts.url, &ts.enrollment_token, Duration::from_secs(15))
        .expect("enroll for test should succeed against a configured server");
    (res.agent_id, res.agent_token)
}

/// Build [`ServerCreds`] for the control-plane client.
pub fn creds(ts: &TestServer, agent_id: String, token: String) -> ServerCreds {
    ServerCreds {
        server_url: ts.url.clone(),
        agent_id,
        token,
        verify_tls: true,
        timeout: Duration::from_secs(15),
    }
}
