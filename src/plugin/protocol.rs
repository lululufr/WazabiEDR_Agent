//! Plugin wire format.
//!
//! Every frame on the named pipe is one length-prefixed JSON document:
//!
//! ```text
//!   +-------------+----------------------+
//!   | LEN: u32 LE | JSON payload (LEN B) |
//!   +-------------+----------------------+
//! ```
//!
//! The framing matches what we already use for the on-disk spool, so a
//! reader of either stream uses the same primitive. JSON for the body is
//! a deliberate trade-off — the kernel-event path is pure binary because
//! it's hot, but plugin events are author-defined documents that need to
//! be parseable from any language. See the `serde_json` rationale in
//! `Cargo.toml`.
//!
//! # Frame sizing
//!
//! [`MAX_FRAME_BYTES`] caps a single frame at 1 MiB. A plugin trying to
//! ship a larger payload gets disconnected — that's the right behavior
//! for an EDR (a runaway plugin must not be allowed to OOM the agent).
//! Plugins that legitimately need to send big blobs should chunk them.
//!
//! # Schema
//!
//! All frames carry a `"type"` discriminator. Plugin → Agent:
//!
//! - `hello`     — first frame, identifies the plugin
//! - `event`     — telemetry record (the whole point of this protocol)
//! - `heartbeat` — liveness ping, optional
//! - `goodbye`   — clean disconnect, optional
//!
//! Agent → Plugin:
//!
//! - `hello_ack` — handshake accepted
//! - `reject`    — handshake refused (with a reason code)
//!
//! Adding a field is backwards-compatible (`#[serde(default)]`); removing
//! one or changing its meaning requires bumping `SCHEMA_VERSION`.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Wire schema version. Bumped on any breaking change to the JSON shape.
pub const SCHEMA_VERSION: u32 = 1;

/// Hard ceiling on a single inbound frame, payload bytes only (LEN
/// prefix excluded). 1 MiB is roughly 4 orders of magnitude more than a
/// typical telemetry record — anything bigger is almost certainly a bug
/// or an attack and we'd rather drop the connection than let it OOM us.
pub const MAX_FRAME_BYTES: u32 = 1 * 1024 * 1024;

// =====================================================================
// Plugin → Agent
// =====================================================================

/// First frame the plugin must send. The agent looks up `plugin_id`
/// against the manifest store and matches the OS-level identity (PID,
/// image path, signer) of the connecting process before accepting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub plugin_id: String,
    /// Plugin author's own version string — stored verbatim for
    /// attribution, not interpreted by the agent.
    pub plugin_version: String,
    /// Schema version the plugin was written against. The agent rejects
    /// the handshake if it doesn't recognise this value.
    pub schema_version: u32,
}

/// Telemetry record. `kind` is a freeform string the plugin author
/// chooses (e.g. `"app.login"`, `"db.slow_query"`); the agent treats it
/// as opaque routing metadata. `payload` is whatever JSON value the
/// plugin wants to ship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Per-session monotonic counter. Lets us spot drops at the
    /// agent→consumer boundary.
    pub seq: u64,
    /// Event time as nanoseconds since the Unix epoch. The plugin sets
    /// this; the agent does NOT trust it for ordering — it stamps its
    /// own ingest timestamp into the enriched record before logging.
    pub ts_unix_ns: u64,
    pub kind: String,
    /// Author-defined payload. Stays as a `serde_json::Value` so we
    /// don't impose a schema we'd later have to migrate.
    pub payload: serde_json::Value,
}

/// Optional liveness ping. Plugins that don't send events for a while
/// should heartbeat so the agent can drop the slot if they go silent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub seq: u64,
}

/// Tagged enum mirroring the `"type"` field on inbound frames.
///
/// `serde(tag = "type", rename_all = "snake_case")` means the JSON
/// `{"type":"hello", ...}` deserialises into [`ClientFrame::Hello`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello(Hello),
    Event(Event),
    Heartbeat(Heartbeat),
    Goodbye {},
}

// =====================================================================
// Agent → Plugin
// =====================================================================

/// Sent on a successful handshake. `session_id` is the attribution key
/// that gets stamped on every event the plugin emits afterwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub session_id: String,
    pub server_version: String,
    pub max_payload_bytes: u32,
    /// Suggested heartbeat interval; the agent disconnects if no frame
    /// (event or heartbeat) is seen for ~3× this value.
    pub heartbeat_sec: u32,
}

/// Reasons the agent uses when refusing a handshake. Sent inside
/// [`Reject`] as a stable string so a plugin author can branch on it.
#[derive(Debug, Clone, Copy)]
pub enum RejectReason {
    /// Frame did not parse as JSON or did not match `ClientFrame`.
    BadHandshake,
    /// `schema_version` differs from [`SCHEMA_VERSION`].
    SchemaMismatch,
    /// `plugin_id` not found in the manifest store.
    UnknownPluginId,
    /// Connecting process's image path does not match the manifest's
    /// `expected_path`.
    PathMismatch,
    /// Connecting binary's SHA-256 does not match the manifest's
    /// `expected_sha256` (when set).
    HashMismatch,
    /// Authenticode signature missing or invalid (when manifest sets
    /// `expected_signer`).
    SignatureInvalid,
    /// Manifest carries a `revoked: true` flag.
    Revoked,
    /// Server already has too many sessions open.
    TooManySessions,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadHandshake => "bad_handshake",
            Self::SchemaMismatch => "schema_mismatch",
            Self::UnknownPluginId => "unknown_plugin_id",
            Self::PathMismatch => "path_mismatch",
            Self::HashMismatch => "hash_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::Revoked => "revoked",
            Self::TooManySessions => "too_many_sessions",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Reject {
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    HelloAck(HelloAck),
    Reject(Reject),
}

// =====================================================================
// Frame I/O
// =====================================================================

/// Errors the framing layer can produce. Connection-level: any of these
/// = drop the client, do NOT recover.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// Peer announced a frame larger than [`MAX_FRAME_BYTES`].
    TooLarge(u32),
    /// JSON inside the frame failed to parse against `ClientFrame`.
    Json(serde_json::Error),
    /// Peer closed the pipe in the middle of a frame.
    Truncated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::TooLarge(n) => write!(f, "frame {} bytes exceeds {} cap", n, MAX_FRAME_BYTES),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Truncated => write!(f, "truncated frame"),
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read exactly `n` bytes — short reads on a Named Pipe in byte mode
/// are perfectly legal, so we have to loop until we get them all.
fn read_exact_or_truncated<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    Ok(())
}

/// Read one inbound frame.
///
/// Returns `Ok(None)` only on a *clean* EOF at the start of a frame
/// (peer hung up between frames). Anything else — half-read length,
/// half-read body — is [`FrameError::Truncated`].
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<ClientFrame>, FrameError> {
    let mut len_buf = [0u8; 4];
    // First read distinguishes "clean end of stream" (we got 0 bytes
    // when expecting a new frame, fine) from "peer died mid-frame"
    // (we got some but not all of the length, that's an error).
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len_buf[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None);
                }
                return Err(FrameError::Truncated);
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }

    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }

    let mut body = vec![0u8; len as usize];
    read_exact_or_truncated(r, &mut body)?;

    let frame: ClientFrame = serde_json::from_slice(&body).map_err(FrameError::Json)?;
    Ok(Some(frame))
}

/// Encode + write one outbound frame.
pub fn write_frame<W: Write>(w: &mut W, frame: &ServerFrame) -> Result<(), FrameError> {
    let body = serde_json::to_vec(frame).map_err(FrameError::Json)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Convenience: build + send a Reject in one call. Used in the handshake
/// rejection paths where we want to be polite before disconnecting.
pub fn write_reject<W: Write>(w: &mut W, reason: RejectReason) -> Result<(), FrameError> {
    let frame = ServerFrame::Reject(Reject {
        reason: reason.as_str(),
    });
    write_frame(w, &frame)
}
