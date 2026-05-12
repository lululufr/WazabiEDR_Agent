//! Driver-facing communication: the wire format we expect, the device
//! pump that reads it, and the parser that turns it into stdout lines.

pub mod device;
pub mod events;
pub mod json;
pub mod parser;
