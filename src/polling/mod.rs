//! User-mode persistence polling.
//!
//! Two long-running threads observe Windows persistence surfaces that
//! aren't reliably emitted by ETW or the kernel callbacks:
//!
//! - **Services** — `EnumServicesStatusExW` + `QueryServiceConfigW`.
//!   We snapshot the service list every `interval`, diff against the
//!   previous snapshot, and emit `service_create / _modify / _delete /
//!   _start / _stop` events.
//! - **Scheduled tasks** — walk `C:\Windows\System32\Tasks\`. Each
//!   task is a single XML file ; presence + mtime + content hash are
//!   diffed across snapshots → `scheduled_task_create / _modify /
//!   _delete`. We deliberately avoid the COM `ITaskService` interface
//!   to keep the dependency surface clean and the binary CRT-only.
//!
//! Both feed into the kernel spool via the shared `SpoolSubmitter`.

mod envelope;
mod services;
mod tasks;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::shutdown::SHUTDOWN;
use crate::spool::SpoolSubmitter;

// PersistenceEvent is only consumed inside this module — no re-export.

#[derive(Default)]
pub struct PollingStats {
    pub service_events: Arc<AtomicU64>,
    pub task_events: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
}

pub struct PollingHandle {
    services_join: Option<JoinHandle<()>>,
    tasks_join: Option<JoinHandle<()>>,
    pub stats: Arc<PollingStats>,
}

impl PollingHandle {
    pub fn shutdown(mut self) {
        if let Some(j) = self.services_join.take() {
            let _ = j.join();
        }
        if let Some(j) = self.tasks_join.take() {
            let _ = j.join();
        }
    }
}

#[derive(Clone, Debug)]
pub struct PollingConfig {
    pub services: bool,
    pub scheduled_tasks: bool,
    /// Snapshot cadence. 30s is a good default: low enough to catch
    /// most persistence installs before the operator pivots, high
    /// enough to avoid measurable CPU/IO load on the endpoint.
    pub interval: Duration,
    /// Skip the first diff so the agent doesn't flood the SIEM with
    /// "create" events for every pre-existing service / task on boot.
    /// Set to false in tests.
    pub silent_first_snapshot: bool,
}

impl Default for PollingConfig {
    fn default() -> Self {
        Self {
            services: true,
            scheduled_tasks: true,
            interval: Duration::from_secs(30),
            silent_first_snapshot: true,
        }
    }
}

pub fn spawn(cfg: PollingConfig, submitter: SpoolSubmitter) -> Option<PollingHandle> {
    if !cfg.services && !cfg.scheduled_tasks {
        return None;
    }
    let stats = Arc::new(PollingStats::default());

    let services_join = if cfg.services {
        let sub = submitter.clone();
        let counter = Arc::clone(&stats.service_events);
        let dropped = Arc::clone(&stats.dropped);
        let interval = cfg.interval;
        let silent = cfg.silent_first_snapshot;
        thread::Builder::new()
            .name("wedr-poll-svc".into())
            .spawn(move || {
                services::run(sub, counter, dropped, interval, silent);
            })
            .ok()
    } else {
        None
    };

    let tasks_join = if cfg.scheduled_tasks {
        let sub = submitter;
        let counter = Arc::clone(&stats.task_events);
        let dropped = Arc::clone(&stats.dropped);
        let interval = cfg.interval;
        let silent = cfg.silent_first_snapshot;
        thread::Builder::new()
            .name("wedr-poll-tasks".into())
            .spawn(move || {
                tasks::run(sub, counter, dropped, interval, silent);
            })
            .ok()
    } else {
        None
    };

    Some(PollingHandle {
        services_join,
        tasks_join,
        stats,
    })
}

/// Sleep up to `dur`, waking within ~500 ms of `SHUTDOWN` so the agent
/// stops promptly rather than waiting out a full poll interval.
pub(crate) fn responsive_sleep(dur: Duration) {
    let until = std::time::Instant::now() + dur;
    while std::time::Instant::now() < until {
        if SHUTDOWN.load(Ordering::Acquire) {
            return;
        }
        let remaining = until.saturating_duration_since(std::time::Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(500)));
    }
}
