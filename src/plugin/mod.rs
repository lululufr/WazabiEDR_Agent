//! Plugin telemetry: the second ingest path of the agent.
//!
//! While the kernel driver feeds the agent low-level Windows events
//! (process create, image load, registry, …), the plugin server lets
//! third-party authors push application-level telemetry from any local
//! process. The two paths are wired side-by-side in `main.rs`.
//!
//! See:
//! - [`protocol`] — wire format + frame I/O
//! - [`manifest`] — on-disk enrolment store
//! - [`identity`] — OS-level + integrity + Authenticode verification
//! - [`server`]   — accept loop, per-session worker, event ingest

pub mod assignment;
pub mod identity;
pub mod manifest;
pub mod protocol;
pub mod server;
pub mod supervisor;

pub use assignment::process_pending_plugins;
pub use server::spawn_server;
pub use supervisor::spawn_supervisor;
