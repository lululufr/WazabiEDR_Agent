//! Wire format expected from the driver.
//!
//! These definitions MUST mirror `WazabiEDR_Driver::events` byte-for-byte.
//! Any change has to be replicated on both sides AND bump `EVENT_VERSION`,
//! otherwise the agent will reject the next event the driver sends.

/// Schema version we expect from the driver. Mismatched versions produce a
/// parse error rather than a misinterpreted event.
///
/// Bumped to 6 when `ProcessCreateEvent` gained `integrity_level` and
/// `ProcessExitEvent` gained `exit_code` — the two extra fields that
/// let detection rules express "elevation without UAC consent" and
/// "process exited via TerminateProcess(non-zero)".
pub const EVENT_VERSION: u16 = 6;

pub const EVENT_TYPE_PROCESS_CREATE: u16 = 1;
pub const EVENT_TYPE_PROCESS_EXIT: u16 = 2;
pub const EVENT_TYPE_IMAGE_LOAD: u16 = 3;
pub const EVENT_TYPE_REGISTRY_MODIFY: u16 = 4;
pub const EVENT_TYPE_THREAD_CREATE: u16 = 5;
pub const EVENT_TYPE_THREAD_EXIT: u16 = 6;
pub const EVENT_TYPE_PROCESS_HANDLE_ACCESS: u16 = 7;

/// Sub-discriminant carried in `RegistryEvent::operation`. Values must
/// match `WazabiEDR_Driver::events::RegistryOp` exactly.
pub const REGISTRY_OP_SET_VALUE: u16 = 1;
pub const REGISTRY_OP_DELETE_VALUE: u16 = 2;
pub const REGISTRY_OP_DELETE_KEY: u16 = 3;
pub const REGISTRY_OP_RENAME_KEY: u16 = 4;
pub const REGISTRY_OP_CREATE_KEY: u16 = 5;

/// Sub-discriminant carried in `ProcessHandleAccessEvent::operation`.
pub const HANDLE_ACCESS_OP_CREATE: u16 = 1;
pub const HANDLE_ACCESS_OP_DUPLICATE: u16 = 2;

/// Maximum number of UTF-16 code units the driver will send for an image
/// path. Longer paths are truncated by the driver.
pub const IMAGE_PATH_MAX: usize = 512;

/// Maximum UTF-16 units for a process command line on the wire.
pub const COMMAND_LINE_MAX: usize = 4096;

/// Maximum UTF-16 units for the SDDL string form of a user SID on the wire.
pub const USER_SID_MAX: usize = 192;

/// Maximum number of UTF-16 code units shipped for a registry key path.
pub const REGISTRY_KEY_PATH_MAX: usize = 512;
/// Maximum number of UTF-16 code units shipped for a registry value name.
pub const REGISTRY_VALUE_NAME_MAX: usize = 128;
/// Maximum number of bytes of value data shipped with a `SetValue` event.
pub const REGISTRY_DATA_PREVIEW_MAX: usize = 256;

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
    /// Number of path / value-name / data-preview fields the driver had
    /// to truncate (because they exceeded the per-event fixed-size
    /// buffers) since the previous delivered event.
    pub trunc_count: u32,
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
    /// Command line of the new process. Empty (`command_line_len == 0`)
    /// when the kernel didn't supply one — see driver-side comment.
    pub command_line: [u16; COMMAND_LINE_MAX],
    pub command_line_len: u16,
    /// NT path of the parent's executable. Empty when the parent had
    /// already exited or the kernel lookup failed.
    pub parent_image_path: [u16; IMAGE_PATH_MAX],
    pub parent_image_path_len: u16,
    /// SDDL string form of the primary token's user SID, e.g.
    /// `S-1-5-21-…-1001`. Empty when the token wasn't resolvable.
    pub user_sid: [u16; USER_SID_MAX],
    pub user_sid_len: u16,
    /// Last sub-authority of the TokenIntegrityLevel SID
    /// (`S-1-16-XXXX`). Common values: 0x1000=Low, 0x2000=Medium,
    /// 0x3000=High, 0x4000=System. `0xFFFFFFFF` = unresolved.
    pub integrity_level: u32,
}

// Wire-format byte-identity guard — driver-side has the same const _
// assertions on the same expected values. If anyone changes a field
// width or reorders here without the equivalent kernel change, this
// fails to compile rather than silently producing garbage events at
// runtime.
const _: () = assert!(std::mem::size_of::<EventHeader>() == 24);
const _: () = assert!(std::mem::size_of::<ProcessCreateEvent>() == 10672);
const _: () = assert!(std::mem::size_of::<ProcessExitEvent>() == 32);

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
    /// Exit status as returned by `PsGetProcessExitStatus`. Mirrors the
    /// driver-side comment: 0 = clean, non-zero = explicit exit code or
    /// NTSTATUS from `TerminateProcess`.
    pub exit_code: i32,
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

/// Registry-modification event. Fields populated depend on `operation`
/// (see `REGISTRY_OP_*` constants) — see the driver-side comment on
/// `RegistryEvent` for the per-operation layout.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct RegistryEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub operation: u16,
    pub value_type: u32,
    pub data_size: u32,
    pub key_path: [u16; REGISTRY_KEY_PATH_MAX],
    pub key_path_len: u16,
    pub value_name: [u16; REGISTRY_VALUE_NAME_MAX],
    pub value_name_len: u16,
    pub data_preview: [u8; REGISTRY_DATA_PREVIEW_MAX],
    pub data_preview_len: u16,
}

/// Thread-creation event. `creating_process_id != process_id` flags a
/// remote thread creation — the canonical CreateRemoteThread injection
/// pattern.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ThreadCreateEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub thread_id: u32,
    pub creating_process_id: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ThreadExitEvent {
    pub header: EventHeader,
    pub process_id: u32,
    pub thread_id: u32,
}

/// Handle-access event on a process object. Pre-filtered by the driver
/// against a "dangerous access" mask, so anything that arrives here is
/// already noteworthy (VM read/write, CreateRemoteThread, Terminate, …).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProcessHandleAccessEvent {
    pub header: EventHeader,
    pub source_process_id: u32,
    pub target_process_id: u32,
    pub desired_access: u32,
    pub original_desired_access: u32,
    pub operation: u16,
}
