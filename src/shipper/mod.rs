//! Network shipper: drain sealed `.zst` batches from the spool(s) and
//! POST them to a remote log server.
//!
//! # What it does, in three sentences
//!
//! The spool writer already produces `batch-<ts>-<seq>.zst` files —
//! NDJSON compressed with zstd — and never deletes them. This module
//! adds a background thread that, on a poll interval, lists those
//! batches in rotation order, POSTs each one to the configured
//! endpoint, and deletes it only after a 2xx ack. Anything that fails
//! (4xx logged once, 5xx / network retried with backoff) stays on disk
//! — the spool's `max_total_bytes` cap is what bounds usage in case the
//! server stays unreachable.
//!
//! # Why a separate thread (and not async)
//!
//! Aligned with the rest of the agent: explicit threads, blocking I/O.
//! `ureq` is sync + rustls-backed and tiny enough to keep the supply-
//! chain footprint reasonable for an EDR. The shipper isn't on the hot
//! path — its throughput target is "stay ahead of the spool's seal
//! rate" (~1 batch / 10 s by default), not "match the kernel ring."
//!
//! # Module map
//!
//! - [`config`] — load + validate `agent.json`
//! - [`secret`] — DPAPI wrap/unwrap + base64 (zero-crate)
//! - [`run`]    — the actual thread that does the POSTing

pub mod config;
pub mod enroll;
pub mod run;
pub mod secret;

pub use run::spawn_shipper;
