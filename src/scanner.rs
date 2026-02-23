use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sysinfo::System;
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
    /// Environment variables (KEY=VALUE)
    pub environ: Vec<String>,
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
            environ: process.environ().iter().map(|s| s.to_string_lossy().to_string()).collect(),
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

/// Known agent signatures — maps command-line patterns to friendly display names.
/// Checked against the full command-line string (case-insensitive).
/// This is how OpenClaw shows as "OpenClaw.ai" instead of "node.exe".
const AGENT_SIGNATURES: &[(&str, &str)] = &[
    ("openclaw",    "OpenClaw.ai"),
    ("aider",       "Aider"),
    ("cursor",      "Cursor IDE"),
    ("copilot",     "GitHub Copilot"),
    ("continue",    "Continue.dev"),
    ("cline",       "Cline"),
    ("windsurf",    "Windsurf"),
    ("devin",       "Devin"),
    ("autogpt",     "AutoGPT"),
    ("langchain",   "LangChain Agent"),
    ("crewai",      "CrewAI"),
    ("antigravity", "Antigravity"),
    ("claude",      "Claude Desktop"),
    ("chatgpt",     "ChatGPT Desktop"),
    ("gemini",      "Gemini"),
    ("llamafile",   "LlamaFile"),
    ("ollama",      "Ollama"),
    ("lmstudio",    "LM Studio"),
    ("jan",         "Jan AI"),
];

/// Resolve a human-friendly agent name from a process name and its command-line arguments.
///
/// This is the key function that maps `node.exe` running an openclaw script
/// to the display name "OpenClaw.ai" instead of just "node.exe".
///
/// Priority:
/// 1. Check full command-line string for known agent signatures.
/// 2. Check the process binary name itself.
/// 3. Fall back to the raw binary name.
pub fn resolve_agent_name(process_name: &str, cmd_args: &[String]) -> String {
    let full_cmd = format!("{} {}", process_name, cmd_args.join(" ")).to_lowercase();
    for (signature, friendly_name) in AGENT_SIGNATURES {
        if full_cmd.contains(signature) {
            return friendly_name.to_string();
        }
    }
    // Fallback: capitalize the binary name (strip .exe on Windows)
    let base = process_name.trim_end_matches(".exe").trim_end_matches(".EXE");
    base.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProcess {
    pub pid: u32,
    pub name: String,
    /// Friendly name resolved from command-line (e.g., "OpenClaw.ai" not "node.exe")
    pub friendly_name: String,
    pub memory_usage: u64,
    pub cmd: Vec<String>,
    pub risk_level: RiskLevel,
    pub risk_reason: String,
    /// Number of processes grouped under this name (1 = ungrouped)
    pub process_count: u32,
    /// All PIDs in this group
    pub child_pids: Vec<u32>,
}

/// Scan the system and return only AI-related processes, grouped by name.
/// Deduplicates same-name processes so the dashboard shows one tile per agent type.
pub fn scan_for_ai() -> Vec<AiProcess> {
    let sys = create_system();
    let processes = scan_with_system_awareness(&sys);

    let mut raw: Vec<AiProcess> = Vec::new();

    for p in processes.into_iter() {
        let name_lower = p.name.to_lowercase();
        let is_ai = AI_PROCESS_NAMES.iter().any(|&kw| name_lower.contains(kw) || p.cmd.iter().any(|c| c.to_lowercase().contains(kw)));
        if is_ai {
            let friendly = resolve_agent_name(&p.name, &p.cmd);
            raw.push(AiProcess {
                pid: p.pid,
                name: p.name,
                friendly_name: friendly,
                memory_usage: p.memory,
                cmd: p.cmd,
                risk_level: p.risk_level,
                risk_reason: p.risk_reason,
                process_count: 1,
                child_pids: vec![p.pid],
            });
        }
    }

    // Group by process name
    let mut groups: std::collections::HashMap<String, AiProcess> = std::collections::HashMap::new();
    for p in raw {
        let entry = groups.entry(p.friendly_name.clone()).or_insert_with(|| AiProcess {
            pid: p.pid,
            name: p.name.clone(),
            friendly_name: p.friendly_name.clone(),
            memory_usage: 0,
            cmd: p.cmd.clone(),
            risk_level: RiskLevel::None,
            risk_reason: String::new(),
            process_count: 0,
            child_pids: Vec::new(),
        });
        entry.memory_usage += p.memory_usage;
        entry.process_count += 1;
        entry.child_pids.push(p.pid);
        // Keep the highest risk level
        if p.risk_level > entry.risk_level {
            entry.risk_level = p.risk_level;
            entry.risk_reason = p.risk_reason;
        }
    }

    groups.into_values().collect()
}

/// Print a simple table of scan results for CLI usage.
pub fn print_scan_results(results: &Vec<AiProcess>) {
    if results.is_empty() {
        println!("  ✅ No AI-related processes found.");
        return;
    }

    println!("  🔎 Found {} AI-related agent(s):\n", results.len());
    for p in results {
        println!("  {:<20} | ×{:<4} | Mem: {:>8} KB | PIDs: {:?}", p.name, p.process_count, p.memory_usage / 1024, p.child_pids);
    }
}

// ─── Phase 5: Child Process Spawn Detection ───────────────────────────────────

/// Represents a detected child process spawn event.
#[derive(Debug, Clone)]
pub struct ChildSpawnAlert {
    /// The parent AI agent's friendly name
    pub agent_name: String,
    /// The parent PID (known agent PID)
    pub parent_pid: u32,
    /// Newly detected child process PID
    pub child_pid: u32,
    /// Child process name (binary), if available
    pub child_name: String,
}

/// Compare two agent scans and return alerts for any new child PIDs that
/// appeared under a tracked agent process.
///
/// Usage: call this from the watchtower loop each scan cycle:
/// ```ignore
/// let prev = scan_for_ai();
/// // ... wait scan_interval ...
/// let curr = scan_for_ai();
/// let alerts = detect_new_child_processes(&prev, &curr);
/// for alert in alerts { /* log CHILD_SPAWN_ALERT event */ }
/// ```
pub fn detect_new_child_processes(
    previous: &[AiProcess],
    current: &[AiProcess],
) -> Vec<ChildSpawnAlert> {
    use std::collections::{HashMap, HashSet};

    // Build map: friendly_name → set of PIDs from previous scan
    let prev_pids: HashMap<&str, HashSet<u32>> = previous
        .iter()
        .map(|a| (a.friendly_name.as_str(), a.child_pids.iter().cloned().collect()))
        .collect();

    let mut alerts = Vec::new();

    for agent in current {
        if let Some(old_pids) = prev_pids.get(agent.friendly_name.as_str()) {
            // Any PID in current that wasn't in previous is a new child spawn
            for &pid in &agent.child_pids {
                if !old_pids.contains(&pid) {
                    // Try to get the child process name via sysinfo
                    let child_name = get_process_name_for_pid(pid)
                        .unwrap_or_else(|| format!("pid-{}", pid));

                    alerts.push(ChildSpawnAlert {
                        agent_name: agent.friendly_name.clone(),
                        parent_pid: agent.pid,
                        child_pid: pid,
                        child_name,
                    });
                }
            }
        }
    }

    alerts
}

/// Get the process name for a given PID using sysinfo.
/// Returns None if the process is not found or the name is empty.
fn get_process_name_for_pid(pid: u32) -> Option<String> {
    use sysinfo::{System, Pid};
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod child_spawn_tests {
    use super::*;

    fn make_agent(name: &str, pids: Vec<u32>) -> AiProcess {
        AiProcess {
            pid: pids[0],
            name: name.to_string(),
            friendly_name: name.to_string(),
            memory_usage: 0,
            cmd: vec![],
            risk_level: RiskLevel::None,
            risk_reason: String::new(),
            process_count: pids.len() as u32,
            child_pids: pids,
        }
    }

    #[test]
    fn test_no_new_children() {
        let prev = vec![make_agent("OpenClaw.ai", vec![1000, 1001])];
        let curr = vec![make_agent("OpenClaw.ai", vec![1000, 1001])];
        assert!(detect_new_child_processes(&prev, &curr).is_empty());
    }

    #[test]
    fn test_detects_new_child() {
        let prev = vec![make_agent("OpenClaw.ai", vec![1000])];
        let curr = vec![make_agent("OpenClaw.ai", vec![1000, 1002])];
        let alerts = detect_new_child_processes(&prev, &curr);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].child_pid, 1002);
        assert_eq!(alerts[0].agent_name, "OpenClaw.ai");
    }

    #[test]
    fn test_new_agent_not_flagged_as_spawn() {
        // An entirely new agent (not in prev) should not produce alerts
        let prev: Vec<AiProcess> = vec![];
        let curr = vec![make_agent("NewAgent", vec![2000])];
        assert!(detect_new_child_processes(&prev, &curr).is_empty());
    }
}
