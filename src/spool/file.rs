//! Append-only event file with simple length-prefix framing.
//!
//! Wire layout on disk (active file, before compression):
//!
//! ```text
//!   +------------------+
//!   | MAGIC: u32 LE    |  0x52444557 ("WEDR" little-endian)
//!   | FORMAT_VER: u16  |  spool format version (1)
//!   | EVENT_VER: u16   |  EVENT_VERSION at write time, e.g. 3
//!   +------------------+
//!   | LEN: u32 LE      |  size of the event payload that follows
//!   | <event bytes>    |  raw IOCTL output, exactly LEN bytes
//!   +------------------+
//!   | LEN: u32 LE      |
//!   | <event bytes>    |
//!     …
//! ```
//!
//! There is intentionally no per-event checksum: the IOCTL output is
//! already validated by the parser before being written, and adding a
//! crc32 per event would double the per-event syscall cost. A future
//! version could add a footer with a single checksum over the whole file.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::ipc::events::EVENT_VERSION;

/// "WEDR" little-endian — distinguishes a Wazabi spool file from random
/// bytes when a future tool walks the directory.
pub const SPOOL_MAGIC: u32 = 0x52444557;

/// Format version for the on-disk framing itself (independent from the
/// event-payload version `EVENT_VERSION`). Bumped only when the framing
/// changes — adding new event types does NOT bump this.
pub const SPOOL_FORMAT_VERSION: u16 = 1;

/// Header size: MAGIC (4) + FORMAT_VER (2) + EVENT_VER (2).
pub const HEADER_LEN: u64 = 8;

/// Append-only handle over a buffered writer.
///
/// Tracks `bytes_written` so the writer thread can decide when to rotate
/// without having to call `metadata()` on every event (a per-event
/// syscall would dominate the rest of our cost).
pub struct ActiveFile {
    inner: BufWriter<File>,
    bytes_written: u64,
}

impl ActiveFile {
    /// Create or truncate the file at `path` and write the header.
    ///
    /// Truncation is deliberate: we never resume writing into an
    /// existing active file. A leftover `active.bin` from a previous
    /// run is treated as data lost on crash.
    pub fn create(path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        // 64 KiB buffer — coalesces many small event writes into one
        // OS-level WriteFile, which is where the actual cost lives.
        let mut inner = BufWriter::with_capacity(64 * 1024, f);

        inner.write_all(&SPOOL_MAGIC.to_le_bytes())?;
        inner.write_all(&SPOOL_FORMAT_VERSION.to_le_bytes())?;
        inner.write_all(&EVENT_VERSION.to_le_bytes())?;

        Ok(Self {
            inner,
            bytes_written: HEADER_LEN,
        })
    }

    /// Append one event record (length-prefixed).
    ///
    /// Flushes only when the underlying `BufWriter` decides it must —
    /// no per-call `flush()`. Callers who want durability after a
    /// rotation should call [`Self::finish`] which flushes explicitly.
    pub fn write_event(&mut self, payload: &[u8]) -> io::Result<()> {
        // Defensive cast: u32 can hold any payload we'd ever produce
        // (kernel events are bounded by IOCTL_MAX); silently truncating
        // would corrupt the stream, so reject loudly instead.
        let len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "event > u32"))?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(payload)?;
        self.bytes_written += 4 + payload.len() as u64;
        Ok(())
    }

    /// Number of bytes already written, including the header.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flush the buffered writer and consume the handle.
    ///
    /// Called when the writer thread rotates this file; doesn't fsync
    /// (we trust the OS to flush within a few seconds, and the
    /// uploader will re-read from disk anyway, so a hard crash losing
    /// the last few seconds of events is acceptable).
    pub fn finish(mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
