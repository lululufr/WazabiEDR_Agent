//! ETW (Event Tracing for Windows) consumer.
//!
//! Spawns a single real-time ETW session (`wedr-etw`) subscribed to a
//! curated set of OS-native providers. Each event is normalised to a
//! Wazabi JSON envelope (same shape as `ipc::json` for kernel events)
//! and pushed into the kernel spool / shipper pipeline.
//!
//! # Why ETW and not another driver
//!
//! DNS resolution, TCP/IP socket activity, PowerShell script-block
//! logging, WMI subscriptions, TLS handshakes and AMSI scans are all
//! emitted by Windows itself via ETW providers. Re-implementing any
//! of them as a custom kernel module would mean writing — and signing
//! — a second driver. Hooking the user-mode ETW consumer API is a
//! supported, documented path that needs no kernel code.
//!
//! # Privileges
//!
//! Most providers require `SeSystemProfilePrivilege` (Administrators
//! group implicitly carry it). Failure to enable a provider is logged
//! and non-fatal — the rest of the agent runs unchanged.

mod amsi;
mod dns;
mod envelope;
mod powershell;
mod schannel;
mod tcp;
mod wmi;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace, stop_trace_by_name};

use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolSubmitter;

pub use envelope::EtwEvent;

const SESSION_NAME: &str = "wedr-etw";

/// Per-provider counters reported on shutdown. `Arc<AtomicU64>` so the
/// callback closure (which must be `Send + Sync + 'static`) can hold a
/// shared reference next to the outer `EtwHandle::stats`.
#[derive(Default)]
pub struct EtwStats {
    pub dns: Arc<AtomicU64>,
    pub tcp: Arc<AtomicU64>,
    pub powershell: Arc<AtomicU64>,
    pub wmi: Arc<AtomicU64>,
    pub schannel: Arc<AtomicU64>,
    pub amsi: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
}

pub struct EtwHandle {
    join: Option<JoinHandle<()>>,
    stop_join: Option<JoinHandle<()>>,
    /// Keeps the session alive until shutdown. The watchdog stops the
    /// session by name first (synchronised on `stopped`); dropping
    /// `_trace` afterwards is a no-op cleanup at that point — but kept
    /// here so a panic that skips the watchdog still tears the session
    /// down via Drop.
    _trace: Option<UserTrace>,
    /// Shared with the watchdog. Both `EtwHandle::shutdown` and the
    /// watchdog thread compete to flip this bit; whoever flips first
    /// owns the `stop_trace_by_name` call.
    stopped: Arc<AtomicBool>,
    pub stats: Arc<EtwStats>,
}

impl EtwHandle {
    pub fn shutdown(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.stop_join.take() {
            let _ = j.join();
        }
        // Belt-and-braces: if main shuts down without SHUTDOWN being
        // set (test paths), we still stop the session here.
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let _ = stop_trace_by_name(SESSION_NAME);
        }
        // _trace drops here.
    }
}

/// Per-provider opt-in flags. Operator-set; defaults all ON.
#[derive(Clone, Debug)]
pub struct EtwConfig {
    pub dns: bool,
    pub tcp: bool,
    pub powershell: bool,
    pub wmi: bool,
    pub schannel: bool,
    pub amsi: bool,
}

impl Default for EtwConfig {
    fn default() -> Self {
        Self {
            dns: true,
            tcp: true,
            powershell: true,
            wmi: true,
            schannel: true,
            amsi: true,
        }
    }
}

/// Wire a provider with a handler that returns `Option<EtwEvent>`.
///
/// `Some(evt)` → serialised and submitted to the spool, counter bumped.
/// `None`      → event silently dropped (event-ID we don't care about).
fn build_provider(
    guid: &str,
    counter: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    submitter: SpoolSubmitter,
    handler: fn(&EventRecord, &Parser) -> Option<EtwEvent>,
) -> Provider {
    Provider::by_guid(guid)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            let schema = match schema_locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            if let Some(evt) = handler(record, &parser) {
                // Bump counter only when the event will actually ship
                // (serde succeeded). Otherwise we'd lie about throughput.
                if let Some(line) = evt.into_ndjson_line() {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let bytes: Arc<[u8]> = Arc::from(line);
                    if !submitter.try_submit(bytes) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
        .build()
}

pub fn spawn(cfg: EtwConfig, submitter: SpoolSubmitter) -> Option<EtwHandle> {
    let stats = Arc::new(EtwStats::default());

    let mut providers: Vec<Provider> = Vec::new();

    macro_rules! enable {
        ($flag:expr, $module:ident, $counter:ident) => {
            if $flag {
                providers.push(build_provider(
                    $module::GUID,
                    Arc::clone(&stats.$counter),
                    Arc::clone(&stats.dropped),
                    submitter.clone(),
                    $module::handle,
                ));
            }
        };
    }

    enable!(cfg.dns, dns, dns);
    enable!(cfg.tcp, tcp, tcp);
    enable!(cfg.powershell, powershell, powershell);
    enable!(cfg.wmi, wmi, wmi);
    enable!(cfg.schannel, schannel, schannel);
    enable!(cfg.amsi, amsi, amsi);

    if providers.is_empty() {
        eprintln!("[etw] all providers disabled — skipping session");
        return None;
    }

    // If a previous run died without cleanup, the named ETW session
    // survives in the kernel and the next start() returns
    // ERROR_ALREADY_EXISTS. Preemptive stop is no-op when the session
    // doesn't exist — makes the spawn path idempotent.
    let _ = stop_trace_by_name(SESSION_NAME);

    let mut builder = UserTrace::new().named(SESSION_NAME.to_string());
    for p in providers {
        builder = builder.enable(p);
    }

    // `start()` returns the session handle + a separate processing
    // handle. We hand the processing handle to the worker (blocking
    // ProcessTrace loop) and keep the session in the main thread so the
    // watchdog can call stop() on it when shutdown fires.
    let (trace, processing_handle) = match builder.start() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!(
                "[etw] cannot start session: {e:?} — ETW telemetry disabled \
                 (privilege issue? agent needs SeSystemProfilePrivilege)"
            );
            return None;
        }
    };

    let join = thread::Builder::new()
        .name("wedr-etw".into())
        .spawn(move || {
            eprintln!("[etw] session started — processing events");
            if let Err(e) = UserTrace::process_from_handle(processing_handle) {
                eprintln!("[etw] process loop ended: {e:?}");
            }
        })
        .ok();

    // Watchdog: when SHUTDOWN flips, stop the named session by name.
    // That returns ProcessTrace in the worker, which then joins.
    // The `stopped` AtomicBool guards against double-stop: dropping
    // _trace at the end of EtwHandle::shutdown would also implicitly
    // stop, and Windows ETW logs a benign warning when we ask twice.
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_for_watchdog = Arc::clone(&stopped);
    let stop_join = thread::Builder::new()
        .name("wedr-etw-stop".into())
        .spawn(move || {
            while !SHUTDOWN.load(Ordering::Acquire) {
                thread::sleep(std::time::Duration::from_millis(500));
            }
            if !stopped_for_watchdog.swap(true, Ordering::AcqRel) {
                let _ = stop_trace_by_name(SESSION_NAME);
            }
        })
        .ok();

    Some(EtwHandle {
        join,
        stop_join,
        _trace: Some(trace),
        stopped,
        stats,
    })
}
