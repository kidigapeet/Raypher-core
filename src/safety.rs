use sysinfo::{Pid};
use tracing::warn;

/// Determines if a process is safe to terminate.
/// 
/// This is the most critical safety check in Raypher. 
/// It prevents "blue-screening" the user by killing system processes.
pub fn is_safe_to_kill(pid: u32, name: &str) -> bool {
    // 1. Never kill low-PID system processes (0-100)
    if pid < 100 {
        warn!(pid = pid, name = name, "Safety Denied: System PID");
        return false;
    }

    // 2. Never kill Raypher itself (suicide check)
    let my_pid = std::process::id();
    if pid == my_pid {
        warn!(pid = pid, name = name, "Safety Denied: Suicide prevention");
        return false;
    }

    // 3. Critical Windows processes whitelist (Hardcoded)
    let critical_processes = [
        "explorer.exe",
        "csrss.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "smss.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
    ];

    let name_lower = name.to_lowercase();
    for critical in &critical_processes {
        if name_lower == *critical {
            warn!(pid = pid, name = name, "Safety Denied: Critical OS process");
            return false;
        }
    }

    true
}
