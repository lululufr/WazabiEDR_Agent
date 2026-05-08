//! On-disk spool for raw events before they are uploaded somewhere.
//!
//! # Why
//!
//! Production EDRs almost never send events one-by-one over the network.
//! Doing so wastes bandwidth (TLS handshakes, headers per event) and
//! cannot survive transient network outages. The standard pattern is:
//!
//! 1. The kernel pump produces events as fast as the OS hands them to us.
//! 2. The agent persists them on disk in a write-ahead log (this module).
//! 3. A separate uploader (added later) reads sealed batches from disk
//!    and ships them to a control plane over a long-lived TLS channel.
//!
//! Splitting (2) and (3) means: an agent crash loses at most the last
//! few unflushed events; an offline endpoint accumulates batches locally
//! and drains them when the network comes back.
//!
//! # Layout
//!
//! - `<spool>/active.bin`              — the file currently being written.
//! - `<spool>/batch-<unix>-<seq>.zst`  — sealed, zstd-compressed batches
//!                                       ready to be picked up by the
//!                                       uploader (or shipped manually).
//!
//! Each file (active or sealed before compression) is a stream of
//! length-prefixed event records — see [`file::write_event`].
//!
//! # Resource ceilings
//!
//! See [`SpoolConfig`] for the knobs. Defaults are conservative:
//! 1 MiB per active file, sealed every 10 s, 256 MiB cap on the whole
//! spool directory.

pub mod file;
pub mod writer;

pub use writer::{SpoolConfig, SpoolHandle, spawn_writer};
