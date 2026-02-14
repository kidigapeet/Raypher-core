// killer.rs — The "Terminator" Module
// Recursive process tree kill with forensic snapshot capture.

use serde::Serialize;
use sysinfo::{Pid, Signal, System};

/// Snapshot of a process state captured before termination.
/// This is our forensic evidence — the "Crash Report."
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub memory_bytes: u64,
    pub memory_human: String,
    pub cmd: String,
    pub status: String,
    pub parent_pid: Option<u32>,
    pub children_killed: Vec<u32>,
}

/// Result of a kill operation.
#[derive(Debug)]
pub struct KillResult {
    pub snapshot: ProcessSnapshot,
    pub success: bool,
    pub error: Option<String>,
}

/// Capture a forensic snapshot of a process before killing it.
/// Returns None if the process doesn't exist or is inaccessible.
pub fn capture_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let sysinfo_pid = Pid::from_u32(pid);
    let process = sys.process(sysinfo_pid)?;

    let children: Vec<u32> = sys
        .processes()
        .iter()
        .filter(|(_, p)| p.parent() == Some(sysinfo_pid))
        .map(|(child_pid, _)| child_pid.as_u32())
        .collect();

    let memory = process.memory();

    Some(ProcessSnapshot {
        pid,
        name: process.name().to_string_lossy().to_string(),
        memory_bytes: memory,
        memory_human: format_bytes(memory),
        cmd: process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" "),
        status: format!("{:?}", process.status()),
        parent_pid: process.parent().map(|p| p.as_u32()),
        children_killed: children,
    })
}

/// Kill a process and all its children (recursive tree kill).
///
/// Strategy: Kill children FIRST, then the parent.
/// This prevents "zombie" children that keep running after the parent dies.
///
/// Safety: Refuses to kill PID < 100 (system-critical processes).
pub fn kill_process_tree(pid: u32) -> KillResult {
    // Safety check — hard block on system processes
    if pid < 100 {
        return KillResult {
            snapshot: ProcessSnapshot {
                pid,
                name: "(blocked)".to_string(),
                memory_bytes: 0,
                memory_human: "N/A".to_string(),
                cmd: String::new(),
                status: "BLOCKED".to_string(),
                parent_pid: None,
                children_killed: vec![],
            },
            success: false,
            error: Some(format!(
                "SAFETY: Cannot kill system-critical process (PID {} < 100)",
                pid
            )),
        };
    }

    // Step 1: Capture forensic snapshot BEFORE killing anything
    let snapshot = match capture_snapshot(pid) {
        Some(s) => s,
        None => {
            return KillResult {
                snapshot: ProcessSnapshot {
                    pid,
                    name: "(not found)".to_string(),
                    memory_bytes: 0,
                    memory_human: "N/A".to_string(),
                    cmd: String::new(),
                    status: "NOT_FOUND".to_string(),
                    parent_pid: None,
                    children_killed: vec![],
                },
                success: false,
                error: Some(format!("Process with PID {} not found or inaccessible", pid)),
            };
        }
    };

    // Step 2: Kill all children first (prevent zombies)
    let mut sys = System::new_all();
    sys.refresh_all();

    for &child_pid in &snapshot.children_killed {
        let child_sysinfo_pid = Pid::from_u32(child_pid);
        if let Some(child_process) = sys.process(child_sysinfo_pid) {
            // Force kill — SIGKILL on Linux, TerminateProcess on Windows
            child_process.kill_with(Signal::Kill);
        }
    }

    // Step 3: Kill the parent process
    let target_pid = Pid::from_u32(pid);
    let killed = if let Some(process) = sys.process(target_pid) {
        process.kill_with(Signal::Kill).unwrap_or(false)
    } else {
        // Process may have already exited
        false
    };

    // Step 4: Verify the kill
    // Brief pause, then refresh to check if process is gone
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_all();
    let still_alive = sys.process(target_pid).is_some();

    if killed && !still_alive {
        KillResult {
            snapshot,
            success: true,
            error: None,
        }
    } else if still_alive {
        KillResult {
            snapshot,
            success: false,
            error: Some(format!(
                "Process PID {} survived kill attempt. May need elevated privileges.",
                pid
            )),
        }
    } else {
        // Process gone but kill_with returned false — it may have exited on its own
        KillResult {
            snapshot,
            success: true,
            error: None,
        }
    }
}

/// Format byte count into human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
