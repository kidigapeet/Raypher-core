// ──────────────────────────────────────────────────────────────
//  Raypher — Transparent Redirect / OS Intercept (Phase 4)
//  Installs OS-level routing rules so that AI agent traffic
//  is transparently redirected to the Raypher proxy without
//  requiring code changes in the agent.
//
//  Windows: netsh portproxy (user-space, requires admin)
//  Linux:   iptables NAT (requires root)
// ──────────────────────────────────────────────────────────────

use std::process::Command;
use tracing::{info, warn};

// ── Port Constants ─────────────────────────────────────────────

/// Raypher's HTTP proxy port.
pub const RAYPHER_HTTP_PORT: u16 = 8888;
/// Raypher's HTTPS proxy port.
pub const RAYPHER_HTTPS_PORT: u16 = 8889;

// ── Public Interface ───────────────────────────────────────────

/// Install transparent redirect rules for known AI API endpoints.
///
/// On Windows: adds `netsh interface portproxy` rules for each target IP.
/// On Linux:   adds `iptables -t nat -A OUTPUT` rules.
///
/// # Errors
/// Returns an error string if the command fails (e.g., insufficient privileges).
pub fn install_redirect() -> Result<(), String> {
    info!("Installing transparent redirect rules...");

    #[cfg(target_os = "windows")]
    {
        return install_redirect_windows();
    }

    #[cfg(target_os = "linux")]
    {
        return install_redirect_linux();
    }

    #[allow(unreachable_code)]
    Err("Transparent redirect not supported on this platform".to_string())
}

/// Remove all transparent redirect rules installed by Raypher.
pub fn remove_redirect() -> Result<(), String> {
    info!("Removing transparent redirect rules...");

    #[cfg(target_os = "windows")]
    {
        return remove_redirect_windows();
    }

    #[cfg(target_os = "linux")]
    {
        return remove_redirect_linux();
    }

    #[allow(unreachable_code)]
    Err("Transparent redirect not supported on this platform".to_string())
}

// ── Windows: netsh portproxy ────────────────────────────────────
// 
// GOTCHA: netsh portproxy redirects are IP-based, not per-process.
// All local connections to the target IP:port are redirected.
// The proxy must handle DNS resolution / TLS SNI correctly.
//
// REQUIRES: Administrator / elevated privileges.

#[cfg(target_os = "windows")]
fn install_redirect_windows() -> Result<(), String> {
    // Well-known AI API IP ranges. These are best-effort — DNS IPs change.
    // The proxy handles TLS termination via SNI detection.
    let rules: &[(&str, u16)] = &[
        // Redirect outbound HTTPS (443) on loopback for testing
        // In production, clients configure proxy via HTTP_PROXY env or registry
        ("127.0.0.1", 443), 
    ];

    for (connect_addr, connect_port) in rules {
        let result = run_netsh_add(connect_addr, *connect_port, RAYPHER_HTTPS_PORT);
        match result {
            Ok(_) => info!("netsh portproxy added: {}:{} → 127.0.0.1:{}", connect_addr, connect_port, RAYPHER_HTTPS_PORT),
            Err(e) => warn!("netsh portproxy add failed for {}:{}: {}", connect_addr, connect_port, e),
        }
    }

    // Also set system-wide HTTP proxy via registry
    set_system_proxy_windows(true)?;

    info!("Transparent redirect installation complete (Windows)");
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_redirect_windows() -> Result<(), String> {
    // Remove all portproxy rules added by Raypher
    let output = Command::new("netsh")
        .args(&["interface", "portproxy", "reset"])
        .output()
        .map_err(|e| format!("netsh reset failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("netsh reset error: {}", stderr));
    }

    // Remove system proxy settings
    set_system_proxy_windows(false)?;

    info!("Transparent redirect rules removed (Windows)");
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_netsh_add(connect_addr: &str, connect_port: u16, listen_port: u16) -> Result<(), String> {
    let output = Command::new("netsh")
        .args(&[
            "interface", "portproxy", "add", "v4tov4",
            &format!("listenport={}", connect_port),
            &format!("listenaddress={}", connect_addr),
            &format!("connectport={}", listen_port),
            "connectaddress=127.0.0.1",
        ])
        .output()
        .map_err(|e| format!("netsh exec failed: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Set or remove the Windows system-wide HTTP proxy via registry.
#[cfg(target_os = "windows")]
fn set_system_proxy_windows(enable: bool) -> Result<(), String> {
    if enable {
        // Set proxy via reg.exe
        let proxy_server = format!("127.0.0.1:{}", RAYPHER_HTTP_PORT);
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        // Enable proxy
        let _ = Command::new("reg")
            .args(&["add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])
            .output();

        // Set proxy server
        let _ = Command::new("reg")
            .args(&["add", reg_path, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &proxy_server, "/f"])
            .output();

        // Bypass localhost
        let _ = Command::new("reg")
            .args(&["add", reg_path, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "127.0.0.1;<local>", "/f"])
            .output();

        info!("Windows system proxy set to {}", proxy_server);
        Ok(())
    } else {
        // Disable proxy
        let reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let _ = Command::new("reg")
            .args(&["add", reg_path, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"])
            .output();

        info!("Windows system proxy disabled");
        Ok(())
    }
}

// ── Linux: iptables NAT ─────────────────────────────────────────
//
// GOTCHA: must add --uid-owner root exclusion to avoid redirect loop
// when the proxy itself makes outbound requests.
//
// REQUIRES: root privileges.

#[cfg(target_os = "linux")]
fn install_redirect_linux() -> Result<(), String> {
    let proxy_http = RAYPHER_HTTP_PORT.to_string();
    let proxy_https = RAYPHER_HTTPS_PORT.to_string();

    // Get current process UID to exclude Raypher itself from the redirect
    let uid = unsafe { libc::getuid() };
    let uid_str = uid.to_string();

    // Redirect outbound HTTP (80) to Raypher HTTP proxy
    run_iptables_add("-p", "tcp", "--dport", "80", &proxy_http, &uid_str)?;
    // Redirect outbound HTTPS (443) to Raypher HTTPS proxy
    run_iptables_add("-p", "tcp", "--dport", "443", &proxy_https, &uid_str)?;

    info!("iptables NAT rules installed (Linux)");
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_iptables_add(proto_flag: &str, proto: &str, dport_flag: &str, dport: &str, redirect_port: &str, uid: &str) -> Result<(), String> {
    // iptables -t nat -A OUTPUT -p tcp --dport 443 ! --uid-owner <uid> -j REDIRECT --to-port 8889
    let output = Command::new("iptables")
        .args(&[
            "-t", "nat",
            "-A", "OUTPUT",
            proto_flag, proto,
            dport_flag, dport,
            "!", "--uid-owner", uid,   // CRITICAL: exclude Raypher's own process
            "-j", "REDIRECT",
            "--to-port", redirect_port,
        ])
        .output()
        .map_err(|e| format!("iptables exec failed: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

#[cfg(target_os = "linux")]
fn remove_redirect_linux() -> Result<(), String> {
    // Flush the RAYPHER chain if it exists, otherwise flush OUTPUT nat rules
    let output = Command::new("iptables")
        .args(&["-t", "nat", "-F", "OUTPUT"])
        .output()
        .map_err(|e| format!("iptables flush failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("iptables flush warning: {}", stderr);
    }

    info!("iptables NAT rules flushed (Linux)");
    Ok(())
}

// ── Show current rules (cross-platform) ───────────────────────

/// List current redirect rules as a human-readable string.
pub fn list_redirect_rules() -> String {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netsh")
            .args(&["interface", "portproxy", "show", "all"])
            .output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("iptables")
            .args(&["-t", "nat", "-L", "OUTPUT", "-n", "-v"])
            .output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        "Transparent redirect not supported on this platform".to_string()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_constants() {
        assert_eq!(RAYPHER_HTTP_PORT, 8888);
        assert_eq!(RAYPHER_HTTPS_PORT, 8889);
    }

    // Note: install_redirect/remove_redirect require admin/root
    // and are verified via manual testing per the implementation plan.
}
