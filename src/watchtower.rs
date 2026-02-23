use std::collections::HashSet;
use std::time::{Duration, Instant};
use sysinfo::System;
use tracing::{info, warn};
use crate::scanner;
use crate::heuristics;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Configuration for the Watchtower monitoring loop.
#[derive(Debug, Clone)]
pub struct WatchtowerConfig {
    /// How often to scan (in seconds). Default: 2
    pub scan_interval_secs: u64,
    /// Minimum risk level to alert on
    pub alert_threshold: scanner::RiskLevel,
    /// Whether to log all processes or only threats
    pub verbose: bool,
    /// Maximum number of scan cycles (0 = infinite)
    pub max_cycles: u64,
}

impl Default for WatchtowerConfig {
    fn default() -> Self {
        WatchtowerConfig {
            scan_interval_secs: 2,
            alert_threshold: scanner::RiskLevel::Medium,
            verbose: false,
            max_cycles: 0,
        }
    }
}

/// State maintained across scan cycles for delta detection.
struct WatchtowerState {
    /// Fingerprints of processes seen in previous scans
    known_processes: HashSet<String>,
    /// Total scan cycles completed
    cycle_count: u64,
    /// Running average of scan duration
    avg_scan_ms: f64,
}

/// The main Watchtower monitoring loop.
pub fn run_watchtower(
    config: WatchtowerConfig,
    system: &mut System,
) {
    info!("🗼 WATCHTOWER ACTIVATED");
    info!(
        interval_secs = config.scan_interval_secs,
        threshold = ?config.alert_threshold,
        "Configuration loaded"
    );

    // Setup shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));
    let s_clone = shutdown.clone();
    
    if let Err(e) = ctrlc::set_handler(move || {
        info!("🛑 Shutdown signal received — completing current scan...");
        s_clone.store(true, Ordering::SeqCst);
    }) {
        warn!("Failed to set Ctrl+C handler: {}", e);
    }

    let mut state = WatchtowerState {
        known_processes: HashSet::new(),
        cycle_count: 0,
        avg_scan_ms: 0.0,
    };

    // Populate initial known process set
    let initial_scan = scanner::scan_with_system_awareness(system);
    for proc in &initial_scan {
        state.known_processes.insert(scanner::fingerprint_process(proc));
    }
    info!(
        baseline_processes = initial_scan.len(),
        "Initial baseline established"
    );

    // Main monitoring loop
    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("Graceful shutdown complete.");
            break;
        }

        state.cycle_count += 1;
        if config.max_cycles > 0 && state.cycle_count > config.max_cycles {
            info!("Maximum cycle count reached — shutting down");
            break;
        }

        let cycle_start = Instant::now();

        // Efficient refresh
        scanner::refresh_system(system);

        // Scan and analyze
        let mut processes = scanner::scan_with_system_awareness(system);
        heuristics::analyze_all(&mut processes);

        // Delta Detection
        let mut new_threats = Vec::new();
        let mut current_fingerprints = HashSet::new();

        for proc in &processes {
            let fp = scanner::fingerprint_process(proc);
            current_fingerprints.insert(fp.clone());

            if !state.known_processes.contains(&fp) {
                if proc.risk_level >= config.alert_threshold {
                    new_threats.push(proc.clone());
                }
                if config.verbose {
                    info!(
                        pid = proc.pid,
                        name = %proc.name,
                        risk = ?proc.risk_level,
                        "New process detected"
                    );
                }
            }
        }

        // Update known processes
        state.known_processes = current_fingerprints;

        // Timing
        let scan_duration = cycle_start.elapsed();
        state.avg_scan_ms = (state.avg_scan_ms * 0.9) + (scan_duration.as_millis() as f64 * 0.1);

        // Alert
        if !new_threats.is_empty() {
            warn!(
                count = new_threats.len(),
                cycle = state.cycle_count,
                "🚨 NEW THREATS DETECTED"
            );
            for threat in &new_threats {
                warn!(
                    pid = threat.pid,
                    name = %threat.name,
                    risk = ?threat.risk_level,
                    reason = %threat.risk_reason,
                    "THREAT: {}", threat.name
                );
            }
        }

        // Heartbeat
        if config.verbose || state.cycle_count % 10 == 0 {
            info!(
                cycle = state.cycle_count,
                processes = processes.len(),
                avg_scan_ms = format!("{:.1}", state.avg_scan_ms),
                "Watchtower heartbeat"
            );
        }

        // Interruptible sleep
        let sleep_duration = Duration::from_secs(config.scan_interval_secs);
        let sleep_start = Instant::now();
        while sleep_start.elapsed() < sleep_duration {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
