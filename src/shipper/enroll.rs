//! Auto-enrollment au premier démarrage.
//!
//! Quand `agent.json` est configuré avec `enrollment_token` mais sans
//! `agent_id` ni token persisté, l'agent appelle lui-même
//! `POST /api/v1/agents/enroll` du serveur Wazabi, récupère le couple
//! `(agent_id, agent_token)`, et persiste les deux dans `agent.json` à
//! la place du `enrollment_token`. Les démarrages suivants utilisent
//! directement les credentials persistés et zappent cette étape.
//!
//! C'est l'équivalent côté agent du `bootstrap.ps1` côté serveur : un
//! seul fichier de config + un token partagé suffisent à amener une
//! machine sur la flotte sans intervention manuelle après
//! installation.
//!
//! ## Pourquoi pas un endpoint d'identité plus solide
//!
//! Pour le MVP on s'en tient au pattern "token partagé" du serveur. Si
//! le serveur passe un jour à mTLS ou TPM-attested enrollment, le
//! contrat de cette fonction restera le même — c'est juste la
//! construction du body qui change.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Résultat d'un enrollment réussi : ce que le serveur a attribué à
/// l'agent.
#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub agent_id: String,
    pub agent_token: String,
}

/// Appelle `POST {server_url}/api/v1/agents/enroll`. Synchrone : appelé
/// une seule fois au boot, avant le démarrage du thread shipper.
///
/// `verify_tls` est ignoré pour l'instant (ureq + rustls ne désactive
/// pas la vérif dans ce build) — même pattern que [`shipper::run`].
pub fn perform(
    server_url: &str,
    enrollment_token: &str,
    timeout: Duration,
) -> Result<EnrollResult, String> {
    let url = format!("{server_url}/api/v1/agents/enroll");

    let body = EnrollRequest {
        enrollment_token: enrollment_token.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        host: HostInfo {
            hostname: hostname(),
            os: "windows".to_string(),
            os_version: os_version(),
            ip: None,
        },
    };

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(timeout)
        .build();

    // `send_json` n'est pas dispo dans cette config ureq (feature `json`
    // désactivée pour rester minimaliste). On sérialise manuellement
    // et on envoie en bytes — même résultat sur le wire.
    let body_bytes =
        serde_json::to_vec(&body).map_err(|e| format!("serialize enroll body: {e}"))?;

    let resp = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_bytes(&body_bytes)
        .map_err(|e| match e {
            // Distinguer "le serveur a répondu non-2xx" (token invalide,
            // schéma cassé) des erreurs transport (DNS, refused, TLS) —
            // les premières ne valent pas la peine d'être retried.
            ureq::Error::Status(code, response) => {
                let body = response.into_string().unwrap_or_default();
                format!("enroll rejected by server: HTTP {code} — {body}")
            }
            ureq::Error::Transport(t) => format!("enroll transport error: {t}"),
        })?;

    // Pareil pour `into_json` (feature `json` off). On lit le body
    // entier en string (cap 64 KiB — la réponse fait <1 KiB en
    // pratique) puis on désérialise via serde_json.
    let body = resp
        .into_string()
        .map_err(|e| format!("read enroll response body: {e}"))?;
    let parsed: EnrollResponse = serde_json::from_str(&body)
        .map_err(|e| format!("parse enroll response: {e} — body was: {body}"))?;

    if parsed.agent_id.trim().is_empty() || parsed.agent_token.trim().is_empty() {
        return Err(format!(
            "enroll response missing agent_id or agent_token: {parsed:?}"
        ));
    }

    Ok(EnrollResult {
        agent_id: parsed.agent_id,
        agent_token: parsed.agent_token,
    })
}

/// Récupère le hostname pour le payload d'enroll. `%COMPUTERNAME%` est
/// présent sur toute session Windows interactive et toujours sous le
/// service `LocalSystem`. Fallback "unknown" si même ça manque (cas
/// pathologique — sandbox build, sysprep partiel).
fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// Best-effort. Le serveur enregistre cette valeur dans `Endpoint.os_version`
/// pour l'inventaire ; si on n'a rien, "unknown" est acceptable et ne
/// bloque pas l'enroll côté `app/routers/agents.py`.
fn os_version() -> String {
    // Lecture du registre Windows pour la version OS impliquerait
    // d'ajouter Win32_System_Registry et 30 lignes de boilerplate
    // unsafe. Le payload est purement informatif (pas validé côté
    // serveur), donc on reste léger.
    "unknown".to_string()
}

#[derive(Serialize)]
struct EnrollRequest {
    enrollment_token: String,
    agent_version: String,
    host: HostInfo,
}

#[derive(Serialize)]
struct HostInfo {
    hostname: String,
    os: String,
    os_version: String,
    ip: Option<String>,
}

#[derive(Deserialize, Debug)]
struct EnrollResponse {
    agent_id: String,
    agent_token: String,
    // D'autres champs (cert_pem, ca_pem, config, checkin_interval_secs…)
    // sont retournés par le serveur ; on les ignore pour l'instant — le
    // MVP n'en a pas besoin et serde::Deserialize tolère les champs
    // supplémentaires par défaut.
}
