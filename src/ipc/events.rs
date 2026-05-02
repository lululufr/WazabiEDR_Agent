//! Wire format expected from the driver.
//!
//! These definitions MUST mirror `WazabiEDR_Driver::events` byte-for-byte.
//! Any change has to be replicated on both sides AND bump `EVENT_VERSION`,
//! otherwise the agent will reject the next event the driver sends.

/// Schema version we expect from the driver. Mismatched versions produce a
/// parse error rather than a misinterpreted event.
pub const EVENT_VERSION: u16 = 1;

pub const EVENT_TYPE_PROCESS_CREATE: u16 = 1;
pub const EVENT_TYPE_PROCESS_EXIT: u16 = 2;
pub const EVENT_TYPE_IMAGE_LOAD: u16 = 3;

/// Maximum number of UTF-16 code units the driver will send for an image
/// path. Longer paths are truncated by the driver.
pub const IMAGE_PATH_MAX: usize = 512;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EventHeader {
    pub version: u16,
    pub type_: u16,
    /// 100ns ticks since 1601-01-01 UTC (Windows FILETIME).
    pub timestamp: i64,
    pub size: u32,
    /// Number of events the driver dropped between the previous delivered
    /// event and this one.
    pub drop_count: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProcessCreateEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub parent_process_id: u32,
    pub creating_process_id: u32,
    pub image_path: [u16; IMAGE_PATH_MAX],
    /// UTF-16 character count (NOT bytes), no terminating NUL.
    pub image_path_len: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
}

/// Image-load event.
///
/// `process_id == 0` means the image was mapped into the kernel address
/// space (driver / system module). Non-zero values are user-mode loads
/// (DLL, EXE) into that PID.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ImageLoadEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub image_base: u64,
    pub image_size: u64,
    pub image_path: [u16; IMAGE_PATH_MAX],
    pub image_path_len: u16,
}
