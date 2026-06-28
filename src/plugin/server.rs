//! Plugin pipe server: accept connections, run handshakes, ingest events.
//!
//! # Concurrency
//!
//! - One **acceptor** thread (`wedr-plugin-accept`) creates pipe
//!   instances and waits for clients with overlapped I/O so it can wake
//!   up on shutdown. As soon as a client connects, it hands the pipe
//!   off to a freshly spawned **worker** thread and goes back to
//!   accepting.
//! - Each **worker** thread (`wedr-plugin-NNNN`) owns one connected
//!   pipe end-to-end: identity verification → handshake → event loop.
//!   Workers use blocking I/O — they do NOT poll [`SHUTDOWN`]; on
//!   Ctrl+C the agent process exits and the OS reaps them. That's a
//!   conscious v1 trade-off (graceful shutdown for plugin sessions
//!   would require overlapped reads / cancellable I/O on every worker,
//!   which is meaningful complexity for very little value).
//!
//! # Limits
//!
//! [`MAX_CONCURRENT_SESSIONS`] caps how many plugins can be connected
//! at once. Hitting the cap returns `too_many_sessions` on the
//! handshake — a deliberate choice over silently queueing, so a
//! buggy plugin spawning thousands of processes can't OOM us.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::detection::DetectionEngine;
use crate::detection::event::LogEvent;
use crate::detection::flatten_fields;
use crate::plugin::identity::{
    ClientIdentity, identify_client, sha256_file_hex, verify_authenticode,
};
use crate::plugin::manifest::{ManifestStore, PluginManifest, directory_fingerprint, paths_match};
use crate::plugin::protocol::{
    ClientFrame, Event, Hello, HelloAck, MAX_FRAME_BYTES, RejectReason, SCHEMA_VERSION,
    ServerFrame, read_frame, write_frame, write_reject,
};
use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolSubmitter;
use crate::util::strings::to_wide_nul;

/// The pipe path. Plugins connect to `\\.\pipe\WazabiEDR_plugin`.
pub const PIPE_NAME: &str = r"\\.\pipe\WazabiEDR_plugin";

/// `HANDLE` is `*mut c_void` and therefore `!Send`. Passing it to a
/// worker thread requires either a Send wrapper or — what we use here —
/// a round-trip through `usize`. Kernel handles are address-stable for
/// their lifetime, so the cast back is safe as long as we recover it on
/// the receiving thread before using it.
#[inline]
fn handle_to_usize(h: HANDLE) -> usize {
    h as usize
}
#[inline]
fn handle_from_usize(u: usize) -> HANDLE {
    u as HANDLE
}

/// Maximum number of plugin sessions running concurrently. New
/// connections beyond this are rejected with `too_many_sessions`.
pub const MAX_CONCURRENT_SESSIONS: usize = 64;

/// Per-instance buffers for the named pipe. 64 KiB is large enough for
/// any single frame we accept (capped at 1 MiB by the protocol layer,
/// but the kernel pipe buffer doesn't need to size to the worst case).
const PIPE_BUF_SIZE: u32 = 64 * 1024;

/// Suggested heartbeat interval advertised in the HelloAck. Plugins
/// don't have to honour it — but if they don't and the worker reads
/// nothing for ~3× this, we'd ideally drop them. Read timeout is a
/// future improvement (see module-level note about overlapped reads).
const HEARTBEAT_SEC: u32 = 30;

/// How often the reload thread re-checks the manifest directory.
/// 5 s is fast enough that an admin running `wedr-plugin enroll` sees
/// their plugin pick up "almost immediately" without polling so often
/// that it hits the disk for nothing on a quiet endpoint.
const MANIFEST_RELOAD_INTERVAL_SEC: u64 = 5;

/// How often the stats thread logs a one-line summary. Quiet enough to
/// not pollute the agent's stdout, frequent enough to spot a stuck
/// plugin or a runaway counter within a few minutes.
const STATS_LOG_INTERVAL_SEC: u64 = 30;

/// Counters published by the plugin server. Lightweight: bumped from
/// hot paths but never read in the hot path.
#[derive(Default)]
pub struct PluginStats {
    pub sessions_accepted: AtomicU64,
    pub sessions_rejected: AtomicU64,
    pub events_received: AtomicU64,
    pub events_invalid: AtomicU64,
    /// Number of times the manifest store was reloaded from disk
    /// (excluding the initial load at startup).
    pub manifest_reloads: AtomicU64,
    /// Plugins currently enrolled (size of the live manifest store).
    /// Updated on every reload so a `stats` snapshot reflects the
    /// current state, not the startup state.
    pub enrolled_plugins: AtomicUsize,
}

/// Front-end handle for the running plugin server.
pub struct PluginServerHandle {
    join: Option<JoinHandle<()>>,
    /// `None` means we couldn't spawn the reload thread (rare; OOM).
    /// The agent stays usable, manifests just aren't hot-reloaded.
    reload_join: Option<JoinHandle<()>>,
    /// `None` means we couldn't spawn the stats thread. Logging is
    /// best-effort, the server keeps running.
    stats_join: Option<JoinHandle<()>>,
    stats: Arc<PluginStats>,
    /// Active session counter shared with the acceptor; exposed via
    /// `active_sessions()` so the operator-facing stats summary at
    /// shutdown can include "still N sessions live."
    active_sessions: Arc<AtomicUsize>,
}

impl PluginServerHandle {
    pub fn stats(&self) -> &PluginStats {
        &self.stats
    }

    /// Number of plugin sessions currently being handled.
    pub fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Wait for the background threads to exit. Workers may outlive
    /// this (until they finish their session or the process exits).
    pub fn shutdown(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.reload_join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.stats_join.take() {
            let _ = j.join();
        }
    }
}

/// Spawn the accept loop and the manifest-reload thread. Returns
/// immediately. `manifest_dir` is where the agent looks for plugin
/// manifests on disk. `spool` is the optional sink for ingested plugin
/// events — when `Some`, every accepted event is persisted as NDJSON
/// to that spool. `console_output` mirrors the agent-side flag: when
/// `false`, plugin events are NOT echoed to stdout (spool only); the
/// `[plugin] ...` diagnostic lines on stderr are unaffected.
///
/// Two background threads result:
/// - `wedr-plugin-accept` — pipe accept loop + per-session worker spawn
/// - `wedr-plugin-reload` — periodic re-scan of `manifest_dir`, swaps
///   the live store atomically when it detects a change.
pub fn spawn_server(
    manifest_dir: PathBuf,
    spool: Option<SpoolSubmitter>,
    detection: Option<Arc<DetectionEngine>>,
    console_output: bool,
) -> io::Result<PluginServerHandle> {
    let stats = Arc::new(PluginStats::default());

    // Initial manifest load — failures are tolerated (empty store).
    let initial = match ManifestStore::load_dir(&manifest_dir) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!(
                "[plugin] failed to load manifests from {:?}: {} — \
                 starting with an empty store",
                manifest_dir, e
            );
            Arc::new(ManifestStore::empty())
        }
    };
    stats
        .enrolled_plugins
        .store(initial.len(), Ordering::Relaxed);
    eprintln!(
        "[plugin] {} plugin(s) enrolled at startup ({})",
        initial.len(),
        manifest_dir.display()
    );

    let store: Arc<RwLock<Arc<ManifestStore>>> = Arc::new(RwLock::new(initial));
    let active_sessions = Arc::new(AtomicUsize::new(0));

    // Accept thread.
    let accept_store = Arc::clone(&store);
    let accept_stats = Arc::clone(&stats);
    let accept_active = Arc::clone(&active_sessions);
    let accept_spool = spool.clone();
    let accept_detection = detection.clone();
    let accept_join = thread::Builder::new()
        .name("wedr-plugin-accept".into())
        .spawn(move || {
            accept_loop(
                accept_store,
                accept_stats,
                accept_active,
                accept_spool,
                accept_detection,
                console_output,
            )
        })?;

    // Reload thread. Spawn fallibly but DON'T fail spawn_server on its
    // failure: the accept loop is the load-bearing path, hot reload is
    // a quality-of-life feature.
    let reload_store = Arc::clone(&store);
    let reload_stats = Arc::clone(&stats);
    let reload_dir = manifest_dir.clone();
    let reload_join = thread::Builder::new()
        .name("wedr-plugin-reload".into())
        .spawn(move || reload_loop(reload_dir, reload_store, reload_stats))
        .ok();
    if reload_join.is_none() {
        eprintln!(
            "[plugin] could not spawn reload thread — manifest changes will \
             only be picked up on agent restart"
        );
    }

    // Stats thread. Same best-effort posture.
    let stats_for_logger = Arc::clone(&stats);
    let active_for_logger = Arc::clone(&active_sessions);
    let stats_join = thread::Builder::new()
        .name("wedr-plugin-stats".into())
        .spawn(move || stats_loop(stats_for_logger, active_for_logger))
        .ok();

    Ok(PluginServerHandle {
        join: Some(accept_join),
        reload_join,
        stats_join,
        stats,
        active_sessions,
    })
}

// =====================================================================
// Acceptor
// =====================================================================

fn accept_loop(
    store: Arc<RwLock<Arc<ManifestStore>>>,
    stats: Arc<PluginStats>,
    active_sessions: Arc<AtomicUsize>,
    spool: Option<SpoolSubmitter>,
    detection: Option<Arc<DetectionEngine>>,
    console_output: bool,
) {
    eprintln!("[plugin] server listening on {}", PIPE_NAME);

    while !SHUTDOWN.load(Ordering::Acquire) {
        let pipe = match create_pipe_instance() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[plugin] CreateNamedPipeW failed: {} — retrying", e);
                // Brief sleep so we don't busy-loop if the system is
                // out of pipe instances or similar transient failure.
                thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
        };

        match wait_for_client(pipe) {
            Ok(true) => {
                stats.sessions_accepted.fetch_add(1, Ordering::Relaxed);

                // Cap concurrent sessions: bump the counter, refuse if
                // we'd exceed. Decrement is the worker's responsibility.
                let count = active_sessions.fetch_add(1, Ordering::AcqRel);
                if count >= MAX_CONCURRENT_SESSIONS {
                    active_sessions.fetch_sub(1, Ordering::AcqRel);
                    stats.sessions_rejected.fetch_add(1, Ordering::Relaxed);
                    let mut stream = PipeStream::new(pipe);
                    let _ = write_reject(&mut stream, RejectReason::TooManySessions);
                    unsafe {
                        DisconnectNamedPipe(pipe);
                        CloseHandle(pipe);
                    }
                    continue;
                }

                // Snapshot the current manifest store under a brief
                // read lock. After this, the worker is lock-free for
                // the entire session — a concurrent reload will swap
                // the lock's content but not affect this Arc.
                let session_store = match store.read() {
                    Ok(g) => Arc::clone(&*g),
                    Err(p) => {
                        // Poisoned RwLock: another thread panicked
                        // while holding the write lock. Recover by
                        // grabbing the inner Arc anyway — the data is
                        // still valid (we never expose mutating refs).
                        Arc::clone(&*p.into_inner())
                    }
                };

                let stats_thread = Arc::clone(&stats);
                let counter = Arc::clone(&active_sessions);
                let session_spool = spool.clone();
                let session_detection = detection.clone();
                let pid_label = stats.sessions_accepted.load(Ordering::Relaxed);
                let name = format!("wedr-plugin-{:04}", pid_label);
                let pipe_addr = handle_to_usize(pipe);
                let spawn_result = thread::Builder::new().name(name).spawn(move || {
                    let pipe = handle_from_usize(pipe_addr);
                    let _ = handle_session(
                        pipe,
                        &session_store,
                        &stats_thread,
                        session_spool.as_ref(),
                        session_detection.as_ref(),
                        console_output,
                    );
                    unsafe {
                        DisconnectNamedPipe(pipe);
                        CloseHandle(pipe);
                    }
                    counter.fetch_sub(1, Ordering::AcqRel);
                });

                if let Err(e) = spawn_result {
                    eprintln!("[plugin] could not spawn worker: {} — closing pipe", e);
                    active_sessions.fetch_sub(1, Ordering::AcqRel);
                    unsafe {
                        DisconnectNamedPipe(pipe);
                        CloseHandle(pipe);
                    }
                }
            }
            Ok(false) => {
                // Shutdown was requested while we were waiting — close
                // the unused pipe and exit the loop on the next check.
                unsafe { CloseHandle(pipe) };
            }
            Err(e) => {
                eprintln!("[plugin] ConnectNamedPipe failed: {}", e);
                unsafe { CloseHandle(pipe) };
            }
        }
    }

    eprintln!("[plugin] accept loop exited");
}

/// Periodic stats logger. One short line every
/// [`STATS_LOG_INTERVAL_SEC`] seconds, suppressed when nothing has
/// happened since the last tick (keeps the log clean on quiet hosts).
fn stats_loop(stats: Arc<PluginStats>, active: Arc<AtomicUsize>) {
    let mut prev_accepted: u64 = 0;
    let mut prev_received: u64 = 0;

    while !SHUTDOWN.load(Ordering::Acquire) {
        // 250 ms slices for shutdown responsiveness.
        for _ in 0..(STATS_LOG_INTERVAL_SEC * 4) {
            if SHUTDOWN.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }

        let accepted = stats.sessions_accepted.load(Ordering::Relaxed);
        let received = stats.events_received.load(Ordering::Relaxed);
        let active_now = active.load(Ordering::Relaxed);
        let enrolled = stats.enrolled_plugins.load(Ordering::Relaxed);
        let reloads = stats.manifest_reloads.load(Ordering::Relaxed);

        // If the counters didn't move at all, skip the line so an idle
        // host doesn't paint stderr with "0 events" forever.
        let accepted_delta = accepted.saturating_sub(prev_accepted);
        let received_delta = received.saturating_sub(prev_received);
        if accepted_delta == 0 && received_delta == 0 && active_now == 0 {
            continue;
        }

        eprintln!(
            "[plugin] stats — active: {}, sessions Δ: {}, events Δ: {}, \
             enrolled: {}, reloads: {}",
            active_now, accepted_delta, received_delta, enrolled, reloads
        );

        prev_accepted = accepted;
        prev_received = received;
    }
}

/// Manifest reload loop. Polls `dir` every
/// [`MANIFEST_RELOAD_INTERVAL_SEC`]; on a fingerprint change, builds a
/// fresh `ManifestStore` and atomically swaps the live one.
///
/// In-flight sessions are unaffected (they hold their own `Arc` to the
/// previous store). New sessions accepted after the swap see the new
/// manifests.
fn reload_loop(dir: PathBuf, store: Arc<RwLock<Arc<ManifestStore>>>, stats: Arc<PluginStats>) {
    // Sleep first so we don't immediately rescan the directory we just
    // loaded at startup.
    let mut last_fp = match store.read() {
        Ok(g) => g.fingerprint(),
        Err(p) => p.into_inner().fingerprint(),
    };

    while !SHUTDOWN.load(Ordering::Acquire) {
        // Poll in 250 ms slices so shutdown is responsive.
        for _ in 0..(MANIFEST_RELOAD_INTERVAL_SEC * 4) {
            if SHUTDOWN.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }

        let fp = directory_fingerprint(&dir);
        if fp == last_fp {
            continue;
        }

        // Something changed. Re-load and swap. Keep the previous store
        // around if reload fails — better stale than empty.
        match ManifestStore::load_dir(&dir) {
            Ok(new_store) => {
                let new_len = new_store.len();
                let new_arc = Arc::new(new_store);
                match store.write() {
                    Ok(mut g) => *g = new_arc,
                    Err(p) => *p.into_inner() = new_arc,
                };
                stats.enrolled_plugins.store(new_len, Ordering::Relaxed);
                stats.manifest_reloads.fetch_add(1, Ordering::Relaxed);
                last_fp = fp;
                eprintln!(
                    "[plugin] manifest store reloaded — {} plugin(s) enrolled",
                    new_len
                );
            }
            Err(e) => {
                eprintln!(
                    "[plugin] manifest reload failed ({}); keeping previous store",
                    e
                );
                // Don't update `last_fp` — we want to retry on the next
                // tick if the operator is mid-edit and the dir was
                // momentarily inconsistent.
            }
        }
    }
}

/// Create one named-pipe instance configured the way we need.
///
/// `PIPE_REJECT_REMOTE_CLIENTS` is critical: without it, a plugin pipe
/// is reachable over SMB from any host on the network (with the right
/// creds). For an EDR endpoint pipe that's a non-starter — we want
/// local-only connections.
fn create_pipe_instance() -> io::Result<HANDLE> {
    let wide = to_wide_nul(PIPE_NAME);
    // SECURITY NOTE: passing a NULL SECURITY_ATTRIBUTES gives the pipe
    // the default DACL — owner + LocalSystem + Administrators have
    // full access, Authenticated Users get GENERIC_READ | FILE_WRITE_*
    // on the *first* instance for the same session. That is permissive
    // enough that a same-user plugin can connect, restrictive enough
    // that another user on the same box cannot trivially reach us.
    // Tightening this further (custom DACL granting only enrolled
    // plugins) is a future hardening once we ship hot-reload.
    let h = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUF_SIZE,
            PIPE_BUF_SIZE,
            0, // default timeout (50 ms) for legacy WaitNamedPipe — we don't use it
            ptr::null(),
        )
    };
    if h.is_null() || h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(h)
}

/// Wait for a client to connect, with periodic shutdown polling.
///
/// Returns `Ok(true)` when a client has connected, `Ok(false)` when we
/// got woken up by shutdown before any client showed up, and `Err` for
/// genuine OS failures.
fn wait_for_client(pipe: HANDLE) -> io::Result<bool> {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event;

    let ok = unsafe { ConnectNamedPipe(pipe, &mut overlapped) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        match err {
            // Most common path: pipe is now waiting, the OVERLAPPED
            // event will be signalled when a client connects.
            e if e == ERROR_IO_PENDING => {}
            // Race: a client connected between CreateNamedPipe and
            // ConnectNamedPipe. Treat as success.
            e if e == ERROR_PIPE_CONNECTED => {
                unsafe { CloseHandle(event) };
                return Ok(true);
            }
            other => {
                unsafe { CloseHandle(event) };
                return Err(io::Error::from_raw_os_error(other as i32));
            }
        }
    }

    // Poll the event with a 250 ms granularity so SHUTDOWN gets noticed
    // promptly without burning CPU in a tight loop.
    loop {
        let wait = unsafe { WaitForSingleObject(event, 250) };
        if wait == WAIT_OBJECT_0 {
            unsafe { CloseHandle(event) };
            return Ok(true);
        }
        if wait == WAIT_TIMEOUT {
            if SHUTDOWN.load(Ordering::Acquire) {
                // Cancel the pending connect so the kernel releases the
                // queued I/O before we close the handles.
                unsafe { CancelIoEx(pipe, &overlapped) };
                unsafe { CloseHandle(event) };
                return Ok(false);
            }
            continue;
        }
        // WAIT_FAILED or anything else: surface as an error so the
        // accept loop can log and try a fresh pipe instance.
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(event) };
        return Err(io::Error::from_raw_os_error(err as i32));
    }
}

// =====================================================================
// Worker / per-session
// =====================================================================

/// Whole lifecycle of one connected plugin: identity → handshake → events.
fn handle_session(
    pipe: HANDLE,
    store: &ManifestStore,
    stats: &PluginStats,
    spool: Option<&SpoolSubmitter>,
    detection: Option<&Arc<DetectionEngine>>,
    console_output: bool,
) -> Result<(), String> {
    let identity = identify_client(pipe).map_err(|e| format!("identity: {}", e))?;
    let mut stream = PipeStream::new(pipe);

    // Read HELLO. Anything other than a Hello on the first frame is a
    // protocol violation — we politely send a Reject and disconnect.
    let hello = match read_frame(&mut stream) {
        Ok(Some(ClientFrame::Hello(h))) => h,
        Ok(Some(_)) | Ok(None) | Err(_) => {
            stats.sessions_rejected.fetch_add(1, Ordering::Relaxed);
            let _ = write_reject(&mut stream, RejectReason::BadHandshake);
            return Err("bad first frame".into());
        }
    };

    // Validate against manifest store + OS identity.
    let manifest = match validate_handshake(&hello, &identity, store) {
        Ok(m) => m,
        Err(reason) => {
            stats.sessions_rejected.fetch_add(1, Ordering::Relaxed);
            let _ = write_reject(&mut stream, reason);
            eprintln!(
                "[plugin] rejected pid={} path={:?} plugin_id={:?} reason={}",
                identity.pid,
                identity.image_path,
                hello.plugin_id,
                reason.as_str()
            );
            return Err(format!("rejected: {}", reason.as_str()));
        }
    };

    // Mint a fresh session_id without pulling a UUID crate: 16 random
    // bytes from the system entropy via BCryptGenRandom would be the
    // "right" choice; for v1 we use a 128-bit value derived from the
    // PID + a process-monotonic counter + timestamp. It only has to be
    // unique among live sessions for attribution to work — it's not a
    // secret. See gen_session_id.
    let session_id = gen_session_id(identity.pid);

    let ack = HelloAck {
        session_id: session_id.clone(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        max_payload_bytes: MAX_FRAME_BYTES,
        heartbeat_sec: HEARTBEAT_SEC,
    };
    if let Err(e) = write_frame(&mut stream, &ServerFrame::HelloAck(ack)) {
        return Err(format!("write HelloAck: {}", e));
    }

    eprintln!(
        "[plugin] session opened plugin_id={} name={:?} pid={} path={:?} session_id={}",
        manifest.plugin_id, manifest.name, identity.pid, identity.image_path, session_id
    );

    // Steady state: read frames, dispatch, repeat. Any error or clean
    // EOF tears down the session.
    loop {
        match read_frame(&mut stream) {
            Ok(Some(ClientFrame::Event(ev))) => {
                stats.events_received.fetch_add(1, Ordering::Relaxed);
                emit_event(
                    &manifest,
                    &identity,
                    &session_id,
                    &ev,
                    spool,
                    detection,
                    console_output,
                );
            }
            Ok(Some(ClientFrame::Heartbeat(_))) => {
                // No state to update yet — heartbeat exists so a future
                // server-side timeout can know the plugin is alive.
                continue;
            }
            Ok(Some(ClientFrame::Hello(_))) => {
                // Hello after handshake: protocol error.
                stats.events_invalid.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[plugin] session_id={} sent Hello mid-session — disconnecting",
                    session_id
                );
                break;
            }
            Ok(Some(ClientFrame::Goodbye {})) => {
                eprintln!(
                    "[plugin] session_id={} closed cleanly (goodbye)",
                    session_id
                );
                break;
            }
            Ok(None) => {
                // Clean EOF.
                eprintln!("[plugin] session_id={} disconnected", session_id);
                break;
            }
            Err(e) => {
                stats.events_invalid.fetch_add(1, Ordering::Relaxed);
                eprintln!("[plugin] session_id={} frame error: {}", session_id, e);
                break;
            }
        }
    }

    Ok(())
}

/// Apply all enabled identity + integrity checks. Returns the manifest
/// the plugin is bound to on success, or a [`RejectReason`] otherwise.
fn validate_handshake<'a>(
    hello: &Hello,
    identity: &ClientIdentity,
    store: &'a ManifestStore,
) -> Result<&'a PluginManifest, RejectReason> {
    if hello.schema_version != SCHEMA_VERSION {
        return Err(RejectReason::SchemaMismatch);
    }

    let manifest = store
        .get(&hello.plugin_id)
        .ok_or(RejectReason::UnknownPluginId)?;

    if manifest.revoked {
        return Err(RejectReason::Revoked);
    }

    if !paths_match(&identity.image_path, &manifest.expected_path) {
        return Err(RejectReason::PathMismatch);
    }

    if let Some(expected) = manifest.expected_sha256.as_deref() {
        match sha256_file_hex(&identity.image_path) {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Ok(_) => return Err(RejectReason::HashMismatch),
            Err(_) => return Err(RejectReason::HashMismatch),
        }
    }

    if manifest.expected_signer.is_some() {
        if verify_authenticode(&identity.image_path).is_err() {
            return Err(RejectReason::SignatureInvalid);
        }
        // Subject-DN match is a TODO — see verify_authenticode.
    }

    Ok(manifest)
}

/// Stamp an event with session attribution and emit it.
///
/// One line written to stdout (human-readable feed) and, when a spool
/// submitter is bound, the same line forwarded into the plugin spool
/// as NDJSON for the shipper to upload.
///
/// We rebuild the JSON object explicitly with `serde_json::Map` rather
/// than re-serialising the plugin's `Event` struct: it guarantees that
/// the attribution fields (`plugin_id`, `session_id`, …) come from the
/// session state and CANNOT be spoofed by anything the plugin stuffed
/// into its payload. The shape matches the kernel envelope
/// (`ts`/`module`/`event_type`/`source`/`kind`/`raw`) so a single
/// OpenSearch index (Wazabi Server's `wazabi-events`) and a single SIEM
/// rule can match across both sources.
fn emit_event(
    manifest: &PluginManifest,
    identity: &ClientIdentity,
    session_id: &str,
    ev: &Event,
    spool: Option<&SpoolSubmitter>,
    detection: Option<&Arc<DetectionEngine>>,
    console_output: bool,
) {
    // Tous les events plugin partagent module="plugin" et event_type=
    // "plugin_event" — l'allow-list contrôle donc le canal entier (on
    // ou off). Une granularité par `kind` viendra avec les règles Waza
    // côté agent.
    if !crate::filter::allows("plugin", "plugin_event") {
        return;
    }

    // Agent-side wall-clock ingest time. We do NOT trust `ev.ts_unix_ns`
    // for ordering — the plugin chose it; if its clock is skewed the
    // shipper's downstream pipeline would mis-order. We still ship it
    // verbatim as the plugin's claim.
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let ts_iso = format_iso8601_ns(now_ns);

    let mut obj = serde_json::Map::with_capacity(12);
    obj.insert("ts".into(), serde_json::Value::String(ts_iso));
    obj.insert("ts_unix_ns".into(), serde_json::Value::from(now_ns));
    obj.insert("source".into(), serde_json::Value::String("plugin".into()));
    // Server-required fields (Wazabi Server `EventIn` schema). Plugin
    // `kind` is free-form, so we route every plugin event through the
    // `plugin_event` catch-all and keep the original label in `kind`
    // (and `raw.kind`, since the server applies `extra="allow"`).
    obj.insert(
        "module".into(),
        serde_json::Value::String("plugin".into()),
    );
    obj.insert(
        "event_type".into(),
        serde_json::Value::String("plugin_event".into()),
    );
    obj.insert("kind".into(), serde_json::Value::String(ev.kind.clone()));
    obj.insert(
        "plugin_id".into(),
        serde_json::Value::String(manifest.plugin_id.clone()),
    );
    obj.insert(
        "plugin_name".into(),
        serde_json::Value::String(manifest.name.clone()),
    );
    obj.insert("plugin_pid".into(), serde_json::Value::from(identity.pid));
    obj.insert(
        "session_id".into(),
        serde_json::Value::String(session_id.to_string()),
    );
    obj.insert("seq".into(), serde_json::Value::from(ev.seq));
    obj.insert(
        "plugin_ts_unix_ns".into(),
        serde_json::Value::from(ev.ts_unix_ns),
    );
    // Stored under `raw` to match the server's `EventIn.raw` field
    // (and the kernel envelope's `raw`). Si le payload contient un
    // `raw_xml` (cas Defender Event Log, ETW, etc.), on aplatit le bloc
    // <Data Name="X">VALUE</Data> en champs top-level pour que la console
    // search puisse les exposer directement sans avoir à parser XML en JS.
    // Plugin reste libre du shape — on ne fait QU'ENRICHIR, jamais
    // écraser, et `raw_xml` est conservé pour debug.
    let mut enriched = ev.payload.clone();
    enrich_with_xml_data_fields(&mut enriched);
    obj.insert("raw".into(), enriched);

    let mut line = match serde_json::to_vec(&serde_json::Value::Object(obj)) {
        Ok(b) => b,
        Err(_) => return,
    };
    line.push(b'\n');

    // stdout for humans, spool for the shipper. stdout failure is
    // benign (closed pipe in tests / no console attached) — don't let
    // it stop spool ingest. The console flag gates stdout only —
    // diagnostic stderr lines are unaffected.
    if console_output {
        let _ = std::io::stdout().write_all(&line);
    }
    if let Some(s) = spool {
        let shared: Arc<[u8]> = Arc::from(line.into_boxed_slice());
        let _ = s.try_submit(shared);
    }

    // Feed the Waza detection engine. A plugin event maps to
    // module="plugin", event_type=<the plugin's own `kind`> (so rules can
    // target a specific telemetry kind, e.g. `plugin.app_login.user`),
    // with the author-defined payload flattened into the field map. This
    // is independent of the NDJSON/server schema above — it affects only
    // local detection.
    if let Some(engine) = detection {
        let fields = match &ev.payload {
            serde_json::Value::Object(obj) => flatten_fields(obj),
            _ => std::collections::HashMap::new(),
        };
        let log = LogEvent {
            module: "plugin".to_string(),
            event_type: ev.kind.clone(),
            fields,
            timestamp: std::time::Instant::now(),
        };
        engine.process(log);
    }
}

// =====================================================================
// XML→JSON enrichment for plugin payloads containing `raw_xml`
// =====================================================================
//
// Si un plugin nous envoie du XML brut (typique des plugins qui pontent
// vers Windows Event Log via EvtRender — DefenderBridge, futur ETW
// channels), on aplatit le bloc `<EventData>` en champs typés au niveau
// du payload. Le plugin n'a rien à faire ; on couvre TOUS les plugins
// présents et futurs sans imposer de logique XML côté SDK.
//
// Format Defender / Event Log standard :
//   <Event>
//     <System>
//       <EventID>1116</EventID>
//       ...
//     </System>
//     <EventData>
//       <Data Name="Threat Name">Virus:DOS/EICAR_Test_File</Data>
//       <Data Name="Severity Name">Severe</Data>
//       ...
//     </EventData>
//   </Event>
//
// On ne remplace JAMAIS un champ déjà présent dans le payload — si le
// plugin parse lui-même (cas DefenderBridge v0.1.4+), ses champs ont
// priorité. `raw_xml` est gardé tel quel pour debug.

/// Enrichit le payload : si `raw_xml` est présent, ajoute `event_id` et
/// tous les `<Data Name="X">VALUE</Data>` comme champs top-level (en
/// snake_case). No-op silencieux si pas de `raw_xml`.
fn enrich_with_xml_data_fields(payload: &mut serde_json::Value) {
    let Some(obj) = payload.as_object_mut() else { return };

    // Clone parce qu'on doit insert dans obj après — pas possible de
    // tenir une référence à un de ses champs en même temps.
    let xml = match obj.get("raw_xml") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return,
    };

    // event_id : utile pour search/filter même quand le plugin ne l'a
    // pas explicitement mis dans son payload.
    if !obj.contains_key("event_id") {
        if let Some(id) = scan_event_id(&xml) {
            obj.insert("event_id".into(), serde_json::Value::from(id));
        }
    }

    // Tous les <Data Name="..."> aplatits.
    for (key, value) in scan_data_fields(&xml) {
        if !obj.contains_key(&key) {
            obj.insert(key, serde_json::Value::String(value));
        }
    }
}

/// Locate `<EventID>NNN</EventID>` (or `<EventID Qualifiers="...">NNN</EventID>`).
fn scan_event_id(xml: &str) -> Option<u32> {
    let start = xml.find("<EventID")?;
    let close = xml[start..].find('>')? + start + 1;
    let end_rel = xml[close..].find("</EventID>")?;
    xml[close..close + end_rel].trim().parse().ok()
}

/// Extrait toutes les paires `<Data Name="X">VALUE</Data>` (ou avec
/// apostrophes `<Data Name='X'>VALUE</Data>` — EvtRender Defender utilise
/// des apostrophes alors que MOST autres providers utilisent double-quote).
/// Pattern fixe et stable (schéma `Microsoft-Windows-EventSchema`) — pas
/// besoin de dépendance XML lourde. HTML entities (`&amp;`, `&lt;`...)
/// décodées pour que les paths avec `&` apparaissent proprement.
fn scan_data_fields(xml: &str) -> Vec<(String, String)> {
    const OPEN_PREFIX: &str = "<Data Name=";
    const CLOSE: &str = "</Data>";
    let mut out = Vec::with_capacity(24);
    let mut rest = xml;
    while let Some(off) = rest.find(OPEN_PREFIX) {
        rest = &rest[off + OPEN_PREFIX.len()..];
        // Détecter le quote utilisé (single ou double) puis le matcher.
        let Some(quote) = rest.chars().next() else { break };
        if quote != '"' && quote != '\'' {
            // Pas un quote reconnu — skip jusqu'à la prochaine occurrence.
            continue;
        }
        rest = &rest[quote.len_utf8()..];
        let Some(name_end) = rest.find(quote) else { break };
        let name = &rest[..name_end];
        rest = &rest[name_end + quote.len_utf8()..];
        let Some(tag_end) = rest.find('>') else { break };
        rest = &rest[tag_end + 1..];
        let Some(val_end) = rest.find(CLOSE) else { break };
        let value = rest[..val_end].trim();
        rest = &rest[val_end + CLOSE.len()..];
        if value.is_empty() {
            continue;
        }
        out.push((normalize_data_key(name), decode_xml_entities(value)));
    }
    out
}

/// "Threat Name" → "threat_name", "FWLink" → "fwlink".
fn normalize_data_key(name: &str) -> String {
    name.trim()
        .chars()
        .map(|c| if c == ' ' { '_' } else { c.to_ascii_lowercase() })
        .collect()
}

fn decode_xml_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// Format a `u64` nanoseconds-since-Unix-epoch as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// We could pull in `chrono` or `time`, but the formatting only needs
/// to handle a single, well-defined case (UTC, Gregorian, millisecond
/// precision) and the project's stance is to avoid date-time crates
/// when not strictly required. Algorithm: standard "days since
/// 1970-01-01" → year/month/day decomposition.
fn format_iso8601_ns(ns: u64) -> String {
    let total_secs = ns / 1_000_000_000;
    let ms = ((ns % 1_000_000_000) / 1_000_000) as u32;
    let secs = (total_secs % 60) as u32;
    let mins = ((total_secs / 60) % 60) as u32;
    let hours = ((total_secs / 3600) % 24) as u32;
    let mut days = (total_secs / 86_400) as i64;

    // Civil-from-days algorithm (Howard Hinnant's date paper). Works
    // for any reasonable Unix-time value; no leap-second handling
    // (matches what FILETIME does on Windows).
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if m <= 2 { y + 1 } else { y }) as i32;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, m, d, hours, mins, secs, ms
    )
}

/// Generate an opaque, per-session identifier.
///
/// 128 bits of "good enough" uniqueness: a process-monotonic counter, a
/// nanosecond timestamp, the PID of the connecting plugin, and a few
/// bits from the system clock. NOT a secret, NOT cryptographically
/// random — only a routing key. Crash-restart of the agent gives a
/// fresh counter; collisions across two live sessions are practically
/// impossible without contrived clock manipulation.
fn gen_session_id(pid: u32) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // 8-4-4-4-12 hex layout is just for visual convention; this is not
    // an RFC-compliant UUID, hence the leading "s-" so nobody parses it
    // as one downstream.
    format!(
        "s-{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        pid,
        (ns >> 48) as u16,
        (ns >> 32) as u16 & 0xffff,
        (n >> 48) as u16,
        n & 0x0000_ffff_ffff_ffff
    )
}

// =====================================================================
// PipeStream: Read+Write adapter over a HANDLE
// =====================================================================

/// Thin Read/Write wrapper around a connected pipe HANDLE so the
/// protocol layer's `read_frame` / `write_frame` can use any standard
/// `io::Read` / `io::Write` trait bounds.
///
/// Does NOT close the handle on drop — the worker that owns the
/// handle is responsible for `DisconnectNamedPipe` + `CloseHandle`.
pub struct PipeStream {
    handle: HANDLE,
}

impl PipeStream {
    pub fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n: u32 = 0;
        let ok = unsafe {
            ReadFile(
                self.handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            // ERROR_BROKEN_PIPE (109): client closed; report 0 to
            // signal clean EOF, matching std::net::TcpStream behaviour.
            if err == 109 {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(n as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut n: u32 = 0;
        let ok = unsafe {
            WriteFile(
                self.handle,
                buf.as_ptr(),
                buf.len() as u32,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
