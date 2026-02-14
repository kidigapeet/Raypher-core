// monitor.rs — The "Guard" Loop (Passive Mode)
// Continuous scanning with resource-usage alerts.

use crate::database::{Database, Event, Severity};
use crate::scanner;

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for the monitor loop.
pub struct MonitorConfig {
    /// How often to scan (in seconds)
    pub interval_secs: u64,
    /// Memory threshold (percentage of total system RAM) to trigger a warning
    pub memory_threshold_percent: f64,
    /// How long a process must exceed the threshold before alerting (in seconds)
    pub alert_after_secs: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            interval_secs: 1,
            memory_threshold_percent: 80.0,
            alert_after_secs: 10,
        }
    }
}

/// Run the passive monitor loop.
/// Scans every `interval_secs`, checks for high-memory AI processes,
/// and logs WARNING events to the database.
///
/// **This is passive mode — it does NOT kill anything.**
pub fn run_monitor(config: &MonitorConfig) {
    println!("  📡 Monitor active — scanning every {}s", config.interval_secs);
    println!(
        "  ⚠️  Alert threshold: >{:.0}% memory for >{}s",
        config.memory_threshold_percent, config.alert_after_secs
    );
    println!("  🛡️  Mode: PASSIVE (observe only, no kills)");
    println!("  ────────────────────────────────────────────");
    println!("  Press Ctrl+C to stop.\n");

    // Track how long each PID has been over the threshold
    let mut offenders: HashMap<u32, Instant> = HashMap::new();
    // Track which PIDs we already alerted on (avoid spamming)
    let mut alerted: HashMap<u32, bool> = HashMap::new();

    let total_memory = {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        sys.total_memory()
    };

    let threshold_bytes =
        (total_memory as f64 * (config.memory_threshold_percent / 100.0)) as u64;

    let interval = Duration::from_secs(config.interval_secs);
    let mut scan_count: u64 = 0;

    loop {
        let results = scanner::scan_for_ai();
        scan_count += 1;

        // Check each AI process against the memory threshold
        let mut current_pids: Vec<u32> = Vec::new();

        for process in &results {
            current_pids.push(process.pid);

            if process.memory_usage > threshold_bytes {
                // Process is over the threshold
                let first_seen = offenders.entry(process.pid).or_insert_with(Instant::now);
                let duration = first_seen.elapsed();

                if duration.as_secs() >= config.alert_after_secs
                    && !alerted.get(&process.pid).unwrap_or(&false)
                {
                    // ALERT — process has been over threshold for too long
                    let mem_percent =
                        (process.memory_usage as f64 / total_memory as f64) * 100.0;

                    println!(
                        "  🚨 ALERT: {} (PID {}) using {:.1}% memory for {}s!",
                        process.name,
                        process.pid,
                        mem_percent,
                        duration.as_secs()
                    );

                    // Log to database
                    if let Ok(db) = Database::init() {
                        let details = serde_json::json!({
                            "pid": process.pid,
                            "name": process.name,
                            "memory_bytes": process.memory_usage,
                            "memory_percent": format!("{:.1}%", mem_percent),
                            "duration_secs": duration.as_secs(),
                            "cmd": process.cmd,
                        });

                        let event = Event {
                            event_type: "MONITOR_ALERT".to_string(),
                            details_json: details.to_string(),
                            severity: Severity::Warning,
                        };

                        if let Ok(id) = db.log_event(&event) {
                            println!("  📝 Warning logged (Event ID: {})", id);
                        }
                    }

                    alerted.insert(process.pid, true);
                }
            } else {
                // Process is under threshold — reset its timer
                offenders.remove(&process.pid);
                alerted.remove(&process.pid);
            }
        }

        // Clean up PIDs that no longer exist
        offenders.retain(|pid, _| current_pids.contains(pid));
        alerted.retain(|pid, _| current_pids.contains(pid));

        // Status line (overwrite with \r for clean output)
        if scan_count % 5 == 0 {
            println!(
                "  ⏳ Scan #{} — {} AI process(es) active",
                scan_count,
                results.len()
            );
        }

        std::thread::sleep(interval);
    }
}
