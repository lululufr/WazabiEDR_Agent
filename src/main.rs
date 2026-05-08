//! WazabiEDR userland agent.
//!
//! Connects to the kernel driver and:
//! 1. prints incoming events to stdout (interactive use), and
//! 2. persists them to a local on-disk spool (`./spool/` by default) as
//!    length-prefixed records, sealed periodically into zstd-compressed
//!    batches ready to be uploaded by a future control-plane component.
//!
//! # Architecture
//!
//! ```text
//!   driver ─IOCTL──> pump thread (main) ─┬─> stdout (parse_and_print)
//!                                        └─> spool::SpoolHandle (channel)
//!                                                    │
//!                                                    ▼
//!                                            wedr-spool thread
//!                                                    │
//!                                                    ▼
//!                                  active.bin  →  batch-<ts>-<seq>.zst
//! ```
//!
//! The spool channel is bounded; if disk I/O can't keep up the pump
//! drops the event rather than blocking. Both kinds of drops (kernel
//! ring full vs. agent channel full) are visible separately so we can
//! tell who is the bottleneck.
//!
//! # Module map
//!
//! - [`ipc`]      — wire format, device open/close, pump loop, parser
//! - [`shutdown`] — Ctrl+C flag and handler
//! - [`spool`]    — on-disk write-ahead log of raw events
//! - [`util`]     — UTF-16 conversion + FILETIME formatting

mod ipc;
mod shutdown;
mod spool;
mod util;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};

use crate::ipc::device::{close_device, open_device, run_pump_loop};
use crate::spool::{SpoolConfig, spawn_writer};

/// Default spool directory. Relative to the agent's CWD; production
/// installs would point this at `%PROGRAMDATA%\WazabiEDR\spool` or
/// similar via a future configuration mechanism.
const DEFAULT_SPOOL_DIR: &str = "spool";

fn main() -> io::Result<()> {
    shutdown::install();

    let handle = open_device();
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    // Spin up the spool writer first so the pump can start submitting
    // immediately. If the writer's setup fails internally (cannot
    // create the dir, etc.) it'll just absorb-and-drop submissions —
    // the agent keeps printing to stdout regardless.
    let spool_cfg = SpoolConfig::with_dir(PathBuf::from(DEFAULT_SPOOL_DIR));
    let spool = spawn_writer(spool_cfg);

    println!(
        "[agent] connected to \\\\.\\WazabiEDR (Ctrl+C to stop) — spool dir: {}",
        DEFAULT_SPOOL_DIR
    );
    io::stdout().flush().ok();

    run_pump_loop(handle, Some(&spool));

    close_device(handle);

    // Read the counters BEFORE shutdown so we don't move-or-borrow
    // dance with the handle. They're behind Arcs anyway.
    let s = spool.stats();
    let written = s.events_written.load(Ordering::Relaxed);
    let dropped = s.events_dropped.load(Ordering::Relaxed);
    let sealed = s.batches_sealed.load(Ordering::Relaxed);
    let evicted = s.batches_evicted.load(Ordering::Relaxed);

    spool.shutdown();
    println!(
        "[agent] disconnected — spool: {} events written, {} dropped, \
         {} batches sealed, {} evicted",
        written, dropped, sealed, evicted
    );
    Ok(())
}
