use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sysinfo::{System, ProcessRefreshKind};
use tracing::{info, warn};

/// Confidence level for process data accuracy.
/// Some fields may be unavailable due to OS permission restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataConfidence {
    /// All fields populated successfully
    Full,
    /// Command-line args unavailable — fell back to process name
    Partial,
    /// Most fields unavailable — system/root process
    Low,
}

/// Risk classification for a discovered process
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Complete snapshot of a running process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessData {
    /// Process ID (OS-assigned)
    pub pid: u32,
    /// Process name (e.g., "python.exe", "node")
    pub name: String,
    /// Full command-line arguments
    pub cmd: Vec<String>,
    /// Memory usage in bytes
    pub memory: u64,
    /// CPU usage percentage (0.0 - 100.0)
    pub cpu_usage: f32,
    /// Parent process ID (for tree building in Week 3)
    pub parent_pid: Option<u32>,
    /// Executable path on disk
    pub exe_path: Option<String>,
    /// Data accuracy level
    pub confidence: DataConfidence,
    /// Heuristic risk score (populated by heuristics engine)
    pub risk_level: RiskLevel,
    /// Human-readable reason for the risk classification
    pub risk_reason: String,
    /// Timestamp when this data was captured
    pub scanned_at: DateTime<Utc>,
}

/// Scans all running processes and returns structured data.
/// Handles permission errors gracefully with confidence tagging.
pub fn scan_all_processes(system: &System) -> Vec<ProcessData> {
    let mut results = Vec::new();
    let now = Utc::now();

    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        let name = process.name().to_string_lossy().to_string();

        // THE TRAP FIX: Command-line fallback logic
        // From build plan: "If cmd is empty, fall back to process name.
        // Log a 'Low Confidence' warning internally."
        let (cmd_line, confidence) = if process.cmd().is_empty() {
            // System process or permission denied — use name as fallback
            warn!(
                pid = pid_u32,
                name = %name,
                "Command-line unavailable — Low Confidence scan"
            );
            (vec![name.clone()], DataConfidence::Partial)
        } else {
            (
                process.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect(),
                DataConfidence::Full,
            )
        };

        // Get executable path (may also fail on protected processes)
        let exe_path = process.exe()
            .map(|p| p.to_string_lossy().to_string());

        // Get parent PID (critical for Week 3 process tree)
        let parent_pid = process.parent().map(|p| p.as_u32());

        let data = ProcessData {
            pid: pid_u32,
            name,
            cmd: cmd_line,
            memory: process.memory(),
            cpu_usage: process.cpu_usage(),
            parent_pid,
            exe_path,
            confidence,
            risk_level: RiskLevel::None,  // Scored in heuristics pass
            risk_reason: String::new(),
            scanned_at: now,
        };

        results.push(data);
    }

    info!(
        total_processes = results.len(),
        "Process scan complete"
    );

    results
}

/// Creates and initializes a System object with optimal refresh settings.
/// TRAP from build plan: "sysinfo::System::new_all() is expensive."
/// We use targeted refresh to only load what we need.
pub fn create_system() -> System {
    let mut system = System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::everything()
    );
    system
}

/// Refreshes process data without reinitializing the entire System.
/// This is the efficient path used in the Week 4 loop.
pub fn refresh_system(system: &mut System) {
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::everything()
    );
}

/// Returns a list of process names that should always be marked Low confidence.
/// These are OS-level processes that will NEVER expose their command-line.
pub fn get_known_system_processes() -> Vec<&'static str> {
    #[cfg(target_os = "windows")]
    {
        vec![
            "System", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe",
            "dwm.exe", "winlogon.exe", "fontdrvhost.exe",
            "Registry", "Memory Compression",
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            "systemd", "kthreadd", "ksoftirqd", "kworker",
            "rcu_sched", "migration", "watchdog",
            "init", "cron", "sshd",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![
            "kernel_task", "launchd", "WindowServer",
            "loginwindow", "opendirectoryd", "diskarbitrationd",
            "notifyd", "UserEventAgent",
        ]
    }
}

/// Enhanced scan that applies system process knowledge
pub fn scan_with_system_awareness(system: &System) -> Vec<ProcessData> {
    let known_system = get_known_system_processes();
    let mut processes = scan_all_processes(system);

    for proc in &mut processes {
        if known_system.contains(&proc.name.as_str()) {
            proc.confidence = DataConfidence::Low;
        }
    }

    processes
}

/// Creates a unique SHA-256 fingerprint for a process based on its
/// immutable characteristics (pid + name + exe_path + cmd args).
pub fn fingerprint_process(proc: &ProcessData) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(proc.pid.to_le_bytes());
    hasher.update(proc.name.as_bytes());
    if let Some(ref path) = proc.exe_path {
        hasher.update(path.as_bytes());
    }
    for arg in &proc.cmd {
        hasher.update(arg.as_bytes());
    }
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string() // First 16 hex chars
}

/// Scan statistics and reporting
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub total_processes: usize,
    pub full_confidence: usize,
    pub partial_confidence: usize,
    pub low_confidence: usize,
    pub total_memory_mb: f64,
    pub scan_duration_ms: u128,
    pub timestamp: DateTime<Utc>,
}

pub fn generate_report(processes: &[ProcessData], duration_ms: u128) -> ScanReport {
    ScanReport {
        total_processes: processes.len(),
        full_confidence: processes.iter().filter(|p| p.confidence == DataConfidence::Full).count(),
        partial_confidence: processes.iter().filter(|p| p.confidence == DataConfidence::Partial).count(),
        low_confidence: processes.iter().filter(|p| p.confidence == DataConfidence::Low).count(),
        total_memory_mb: processes.iter().map(|p| p.memory as f64).sum::<f64>() / 1_048_576.0,
        scan_duration_ms: duration_ms,
        timestamp: Utc::now(),
    }
}

// ------------------------------------------------------------------
// Compatibility layer for older CLI/monitor code
// Provides a lightweight AiProcess view and helper functions
// expected by `monitor.rs` and `main.rs` earlier versions.
// ------------------------------------------------------------------

/// Known AI-related process names to look for.
const AI_PROCESS_NAMES: &[&str] = &[
    "ollama",
    "python",
    "python3",
    "uvicorn",
    "gunicorn",
    "node",
    "llamafile",
    "llama-server",
    "text-generation",
    "vllm",
    "tritonserver",
    "jupyter",
    "ipykernel",
    "localai",
    "lmstudio",
    "chat",
    "copilot",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProcess {
    pub pid: u32,
    pub name: String,
    pub memory_usage: u64,
    pub cmd: Vec<String>,
    pub risk_level: RiskLevel,
    pub risk_reason: String,
}

/// Scan the system and return only AI-related processes.
pub fn scan_for_ai() -> Vec<AiProcess> {
    let mut sys = create_system();
    let processes = scan_with_system_awareness(&sys);

    let mut results: Vec<AiProcess> = Vec::new();

    for p in processes.into_iter() {
        let name_lower = p.name.to_lowercase();
        let is_ai = AI_PROCESS_NAMES.iter().any(|&kw| name_lower.contains(kw) || p.cmd.iter().any(|c| c.to_lowercase().contains(kw)));
        if is_ai {
            results.push(AiProcess {
                pid: p.pid,
                name: p.name,
                memory_usage: p.memory,
                cmd: p.cmd,
                risk_level: p.risk_level,
                risk_reason: p.risk_reason,
            });
        }
    }

    results
}

/// Print a simple table of scan results for CLI usage.
pub fn print_scan_results(results: &Vec<AiProcess>) {
    if results.is_empty() {
        println!("  ✅ No AI-related processes found.");
        return;
    }

    println!("  🔎 Found {} AI-related process(es):\n", results.len());
    for p in results {
        println!("  PID {:<8} | {:<20} | Mem: {:>8} KB | Cmd: {}", p.pid, p.name, p.memory_usage / 1024, p.cmd.join(" "));
    }
}
