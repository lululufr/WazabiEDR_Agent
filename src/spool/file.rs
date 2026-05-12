//! Append-only NDJSON file.
//!
//! On-disk layout (active file, before compression): a stream of newline-
//! terminated JSON documents — one event per line. After rotation, the
//! whole file is run through `zstd` and stored as `batch-<ts>-<seq>.zst`;
//! the compressed batch is byte-identical to what the shipper sends to
//! the log server (`Content-Encoding: zstd` + `Content-Type:
//! application/x-ndjson`). No custom framing, no header — opening a
//! decompressed batch with any NDJSON-aware tool (`jq`, Vector, …) works
//! out of the box.
//!
//! Reading partial NDJSON after a crash is straightforward: parse line by
//! line and discard a trailing line that doesn't end with `\n` (= the
//! agent died mid-write). The spool writer doesn't actually recover an
//! inherited active file today — see `writer::writer_main` — but the
//! format permits it.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Append-only handle over a buffered writer.
///
/// Tracks `bytes_written` so the writer thread can decide when to rotate
/// without a per-event `metadata()` syscall.
pub struct ActiveFile {
    inner: BufWriter<File>,
    bytes_written: u64,
}

impl ActiveFile {
    /// Create or truncate the file at `path`. Truncation is deliberate:
    /// we treat any leftover active file from a previous run as data
    /// lost on crash (rebuilding partial NDJSON would be possible but
    /// has near-zero value — see the writer's recovery comment).
    pub fn create(path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        // 64 KiB buffer — coalesces many small event writes into one
        // OS-level WriteFile, which is where the actual cost lives.
        let inner = BufWriter::with_capacity(64 * 1024, f);
        Ok(Self {
            inner,
            bytes_written: 0,
        })
    }

    /// Append one already-serialised line. The caller is responsible for
    /// including the trailing `\n`; we don't add one because callers
    /// (`ipc::json`, the plugin-side JSON builder) already produce a
    /// terminated line and double-newline would corrupt the stream.
    pub fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.inner.write_all(line)?;
        self.bytes_written += line.len() as u64;
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flush the buffered writer and consume the handle. No fsync — we
    /// trust the OS to flush within a few seconds, and the shipper will
    /// re-read from disk anyway, so a hard crash losing the last few
    /// seconds of events is accepted.
    pub fn finish(mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
