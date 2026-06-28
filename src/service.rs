//! Windows Service Control Manager glue.
//!
//! The same `WazabiEDR_Agent.exe` is meant to run either as a real
//! Windows service (production posture, installed by the setup.exe) or
//! as a foreground console process (developer workflow, no SCM needed).
//!
//! [`run`] always tries the service path first by calling
//! `StartServiceCtrlDispatcher`. If the SCM refuses with
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) — i.e. we were not
//! launched by services.exe — we transparently fall back to the
//! console code path. Operators never have to pass a flag.

use std::ffi::OsString;
use std::io;
use std::time::Duration;

use windows_service::Error as ServiceError;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::shutdown;

/// Must match what the installer's `sc create` registers.
pub const SERVICE_NAME: &str = "WazabiEDR_Agent";

/// Entry point invoked from `main`.
///
/// First tries to hand control to the SCM. On the well-known "we are
/// not a service" error, falls back to foreground execution so a dev
/// can just double-click the EXE or run it from a shell.
// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT — returned by
// StartServiceCtrlDispatcher when the calling process was NOT spawned
// by services.exe (typical: developer running the EXE from a shell).
// This is the canonical "not a service" indicator and is the only
// error we treat as a soft fall-back; every other error means a real
// SCM-level failure and stays fatal.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

pub fn run() -> io::Result<()> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(()),
        Err(ServiceError::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            crate::run_agent(false)
        }
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    // `service_main` runs on a dedicated thread spawned by the SCM
    // dispatcher. Anything that fails here is invisible (no console);
    // we log to stderr anyway in case Event Log forwarding is wired
    // up later, and report a non-zero exit code via ServiceStatus.
    if let Err(e) = run_service() {
        eprintln!("[agent/service] fatal: {e}");
    }
}

fn run_service() -> Result<(), String> {
    // Control handler: SCM calls this on its own thread when an
    // operator runs `sc stop WazabiEDR_Agent` or the OS reboots. We
    // funnel STOP / SHUTDOWN through the same `shutdown::request`
    // path the Ctrl+C handler uses — atomic flag + CancelIoEx on the
    // pump device handle. Everything downstream is already
    // shutdown-aware.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown::request();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| format!("register service control handler: {e}"))?;

    // Announce RUNNING immediately. The agent's startup work
    // (opening the device, spawning the spool / shipper / control
    // plane / ETW threads) takes a couple seconds; without an early
    // RUNNING notification the SCM would consider us hung and kill
    // us at the default 30 s START_PENDING timeout. The agent is
    // happy to receive STOP at any point during startup — every
    // sub-thread polls SHUTDOWN.
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(running)
        .map_err(|e| format!("set RUNNING: {e}"))?;

    // Blocking. Returns when the pump loop sees SHUTDOWN set (by us
    // from the control handler above) and the teardown cascade
    // finishes.
    let exit_code: u32 = match crate::run_agent(true) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[agent/service] run_agent error: {e}");
            1
        }
    };

    let stopped = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle
        .set_service_status(stopped)
        .map_err(|e| format!("set STOPPED: {e}"))?;
    Ok(())
}
