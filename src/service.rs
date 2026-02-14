// ──────────────────────────────────────────────────────────────
//  Raypher — Windows Service Module
//  Registers with the Service Control Manager (SCM) and runs
//  the Watchtower loop as an invisible background process.
// ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(target_os = "windows")]
use tracing::{info, warn, error};

#[cfg(target_os = "windows")]
use crate::database::{Database, Event, Severity};
#[cfg(target_os = "windows")]
use crate::identity;

// ── Constants ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
const SERVICE_NAME: &str = "RaypherService";

#[cfg(target_os = "windows")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ── Service Entry Point ────────────────────────────────────────

/// Called from main() when --service flag is detected.
/// This function MUST NOT return until the service is stopped.
#[cfg(target_os = "windows")]
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize file-based logging (no console in service mode)
    init_service_logging();

    info!("RaypherService starting — registering with SCM...");

    // Register the service dispatcher. This call blocks until the
    // service exits. Windows calls `service_main` internally.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;

    Ok(())
}

// The macro generates the FFI-compatible function signature that
// the Windows SCM expects. It wraps our real `service_main`.
#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, service_main);

/// The real service main function. Called by the SCM dispatcher.
/// Must report SERVICE_RUNNING within 30 seconds or Windows kills us.
#[cfg(target_os = "windows")]
fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service_inner(arguments) {
        error!("Service fatal error: {}", e);
    }
}

#[cfg(target_os = "windows")]
fn run_service_inner(_arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    // Shared shutdown flag — same pattern as Phase 1's Watchtower
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // ── Step 1: Register the event handler ─────────────────────
    // The SCM sends Stop/Interrogate/Pause signals through this handler.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("SCM requested STOP — initiating graceful shutdown...");
                shutdown_clone.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => {
                // SCM checking if we're alive. Just acknowledge it.
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // ── Step 2: Report START_PENDING ───────────────────────────
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    info!("Service START_PENDING — initializing core systems...");

    // ── Step 3: Initialize core systems ────────────────────────

    // Initialize database
    let db = match Database::init() {
        Ok(db) => {
            info!("Database initialized successfully.");
            Some(db)
        }
        Err(e) => {
            warn!("Database initialization failed: {}. Continuing without audit logging.", e);
            None
        }
    };

    // Read Silicon ID
    let silicon_id = identity::get_silicon_id();
    info!("Silicon ID: {}", silicon_id);

    // Store identity in audit ledger
    if let Some(ref db) = db {
        if let Err(e) = db.store_identity(&silicon_id) {
            warn!("Failed to store identity: {}", e);
        }
        // Log service start event
        let event = Event {
            event_type: "SERVICE_START".to_string(),
            details_json: serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "silicon_id": silicon_id,
            }).to_string(),
            severity: Severity::Info,
        };
        if let Err(e) = db.log_event(&event) {
            warn!("Failed to log service start event: {}", e);
        }
    }

    // ── Step 4: Report RUNNING ─────────────────────────────────
    // CRITICAL: We must reach this point within 30 seconds of startup
    // or the SCM will kill us.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("✅ Service reported RUNNING to SCM. Entering main loop...");

    // ── Step 5: Main Service Loop ──────────────────────────────
    // This is the Watchtower — scan for AI processes at regular intervals.
    // The Watchdog monitors our health; the Updater checks GitHub every 6 hours.
    let scan_interval = Duration::from_secs(5);
    let mut cycle_count: u64 = 0;
    let mut sys = crate::scanner::create_system();

    // ── Watchdog: Track heartbeats for health monitoring ──
    let watchdog = crate::watchdog::Watchdog::default();

    // ── Update Timer: Check GitHub every 6 hours ──
    let update_interval = crate::updater::UPDATE_CHECK_INTERVAL;
    let mut last_update_check = std::time::Instant::now();

    while !shutdown.load(Ordering::SeqCst) {
        cycle_count += 1;

        // Scan for AI processes
        let processes = crate::scanner::scan_all_processes(&mut sys);
        let ai_count = processes.iter()
            .filter(|p| p.risk_level != crate::scanner::RiskLevel::None)
            .count();

        // ── Record heartbeat after successful scan ──
        watchdog.heartbeat();

        if ai_count > 0 {
            info!("Cycle {}: Found {} potential AI processes out of {} total.",
                cycle_count, ai_count, processes.len());

            // Log to audit ledger
            if let Some(ref db) = db {
                let event = Event {
                    event_type: "WATCHTOWER_SCAN".to_string(),
                    details_json: serde_json::json!({
                        "cycle": cycle_count,
                        "total_processes": processes.len(),
                        "ai_detected": ai_count,
                    }).to_string(),
                    severity: if ai_count > 5 { Severity::Warning } else { Severity::Info },
                };
                let _ = db.log_event(&event);
            }
        }

        // Heartbeat log every 100 cycles (includes watchdog status)
        if cycle_count % 100 == 0 {
            let status = watchdog.status_report();
            info!("Heartbeat: {} scan cycles | Uptime: {:?} | Healthy: {}",
                cycle_count, status.uptime, status.healthy);
        }

        // ── Auto-Update Check (every 6 hours) ──
        if last_update_check.elapsed() >= update_interval {
            info!("Running scheduled update check...");
            let result = crate::updater::check_and_update();
            match &result {
                crate::updater::UpdateResult::UpToDate(v) => {
                    info!("Update check: up to date (v{}).", v);
                }
                crate::updater::UpdateResult::Updated { from, to } => {
                    info!("🔄 Updated from v{} to v{}! Service restart required.", from, to);
                    if let Some(ref db) = db {
                        let event = Event {
                            event_type: "AUTO_UPDATE".to_string(),
                            details_json: serde_json::json!({
                                "from": from,
                                "to": to,
                            }).to_string(),
                            severity: Severity::Info,
                        };
                        let _ = db.log_event(&event);
                    }
                }
                crate::updater::UpdateResult::Error(e) => {
                    warn!("Update check failed: {}", e);
                }
            }
            last_update_check = std::time::Instant::now();
        }

        // Sleep, but check shutdown flag every second
        for _ in 0..scan_interval.as_secs() {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    // ── Step 6: Graceful Shutdown ──────────────────────────────
    info!("Shutdown signal received. Cleaning up...");

    // Log service stop event
    if let Some(ref db) = db {
        let event = Event {
            event_type: "SERVICE_STOP".to_string(),
            details_json: serde_json::json!({
                "cycles_completed": cycle_count,
                "reason": "SCM_STOP_SIGNAL",
            }).to_string(),
            severity: Severity::Info,
        };
        let _ = db.log_event(&event);
    }

    // Report STOPPED to the SCM
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("RaypherService stopped cleanly after {} cycles.", cycle_count);
    Ok(())
}

// ── Service Logging ────────────────────────────────────────────

/// Initialize file-based logging for service mode.
/// In service mode, there is NO console — println! goes nowhere.
/// We write to %USERPROFILE%\.raypher\logs\raypher.log
#[cfg(target_os = "windows")]
fn init_service_logging() {
    let log_dir = get_log_directory();
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!("Failed to create log directory: {}", e);
        return;
    }

    let file_appender = tracing_appender::rolling::daily(&log_dir, "raypher.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)       // No color codes in log files
        .with_target(true)      // Show module::path
        .with_level(true)       // Show INFO/WARN/ERROR
        .init();

    // Note: _guard is leaked intentionally — the logger must live for the
    // entire service lifetime. When the process exits, it's cleaned up.
    std::mem::forget(_guard);
}

/// Get the log directory path: %ProgramData%\Raypher\logs or fallback
#[cfg(target_os = "windows")]
fn get_log_directory() -> std::path::PathBuf {
    if let Ok(program_data) = std::env::var("ProgramData") {
        std::path::PathBuf::from(program_data)
            .join("Raypher")
            .join("logs")
    } else {
        // Fallback to the current directory
        std::path::PathBuf::from(".raypher").join("logs")
    }
}

// ── Linux / Non-Windows Stub ───────────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Windows Service mode is not available on this platform.");
    eprintln!("Use 'systemd' instead: sudo systemctl start raypher");
    std::process::exit(1);
}
