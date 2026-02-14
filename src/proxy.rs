// ──────────────────────────────────────────────────────────────
//  Raypher — Localhost Proxy (The Vault)
//  Listens on 127.0.0.1:8888, intercepts API calls from AI agents,
//  verifies the caller PID/exe hash, injects real API keys from
//  the TPM vault, and forwards requests to the target API.
// ──────────────────────────────────────────────────────────────

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use tracing::{info, warn, error};

use crate::database::{Database, Event, Severity};
use crate::secrets;

// ── Configuration ──────────────────────────────────────────────

/// Proxy configuration — shared across all async handlers via Arc.
pub struct ProxyState {
    /// HTTP client with connection pooling for outbound requests
    pub http_client: reqwest::Client,
    /// The target API base URL (e.g., "https://api.openai.com")
    pub target_base_url: String,
    /// Database for audit logging and allow-list checks (Mutex for thread safety)
    pub db: Option<Mutex<Database>>,
}

/// Default proxy listen address — NEVER bind to 0.0.0.0
const PROXY_ADDR: &str = "127.0.0.1:8888";

// ── Public Interface ───────────────────────────────────────────

/// Start the proxy server. This blocks the async runtime.
/// Called from `service.rs` (service mode) or from CLI for testing.
pub async fn start_proxy() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Raypher proxy on {}", PROXY_ADDR);

    // Build reqwest client with connection pooling (Keep-Alive)
    let http_client = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(120))
        .build()?;

    // Initialize database
    let db = match Database::init() {
        Ok(db) => {
            info!("Proxy database connection established.");
            Some(Mutex::new(db))
        }
        Err(e) => {
            warn!("Proxy database unavailable: {}. Audit logging disabled.", e);
            None
        }
    };

    let state = Arc::new(ProxyState {
        http_client,
        target_base_url: "https://api.openai.com".to_string(),
        db,
    });

    // Build the router
    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/v1/{*path}", any(handle_proxy))
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(PROXY_ADDR).await?;
    info!("✅ Raypher proxy listening on {}", PROXY_ADDR);

    axum::serve(listener, app).await?;
    Ok(())
}

// ── Route Handlers ─────────────────────────────────────────────

/// GET /health — Simple health check endpoint
async fn handle_health() -> impl IntoResponse {
    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let body = serde_json::json!({
        "status": "ok",
        "service": "raypher-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": uptime,
    });

    (StatusCode::OK, axum::Json(body))
}

/// Catch-all handler for /v1/* — The core proxy logic.
///
/// Flow:
/// 1. Extract X-Raypher-Token header
/// 2. Identify caller PID from TCP socket
/// 3. Verify against allow-list (exe hash check)
/// 4. Unseal real API key from TPM vault
/// 5. Forward request with real key
/// 6. Stream response back to caller
async fn handle_proxy(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, StatusCode> {
    let start = std::time::Instant::now();

    // ── Step 1: Extract the Raypher token ──────────────────────
    let raypher_token = headers
        .get("x-raypher-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if raypher_token.is_empty() {
        warn!(
            client = %addr,
            "Proxy request missing X-Raypher-Token header"
        );

        // Log unauthorized attempt
        log_proxy_event(
            &state.db,
            "PROXY_UNAUTHORIZED",
            &addr,
            uri.path(),
            Severity::Warning,
        );

        return Err(StatusCode::UNAUTHORIZED);
    }

    // ── Step 2: Identify the calling process ───────────────────
    let caller_port = addr.port();
    let caller_pid = get_pid_from_port(caller_port);

    info!(
        client = %addr,
        pid = ?caller_pid,
        path = uri.path(),
        "Proxy request received"
    );

    // ── Step 3: Verify caller against allow-list ───────────────
    // For now, we verify the caller has a valid PID.
    // Full exe-hash verification will be wired up with the Allow subcommand.
    if let Some(pid) = caller_pid {
        if let Some(ref db_mutex) = state.db {
            if let Ok(db) = db_mutex.lock() {
                let exe_info = get_exe_path_for_pid(pid);
                if let Some(ref exe) = exe_info {
                    if !secrets::is_allowed(&db, exe) {
                        warn!(
                            pid = pid,
                            exe = exe,
                            "Process NOT in allow list — blocking request"
                        );
                        log_proxy_event(
                            &state.db,
                            "PROXY_BLOCKED",
                            &addr,
                            uri.path(),
                            Severity::Critical,
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        }
    }

    // ── Step 4: Unseal the real API key ────────────────────────
    // Look up the provider from the token or default to "openai"
    let provider = "openai"; // TODO: extract from X-Raypher-Provider header
    let real_key = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            secrets::unseal_key(&db, provider).ok()
        } else {
            None
        }
    } else {
        None
    };

    // ── Step 5: Build and forward the request ──────────────────
    let target_url = format!("{}{}", state.target_base_url, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(uri.path()));

    // Collect request body
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    // Build the outbound request
    let mut outbound = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &target_url,
    );

    // Copy relevant headers (skip host, connection, and the raypher token)
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "host"
            || name_str == "connection"
            || name_str == "x-raypher-token"
            || name_str == "x-raypher-provider"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            outbound = outbound.header(name.as_str(), v);
        }
    }

    // Inject the real API key (or forward the token as-is if no sealed key found)
    if let Some(ref key) = real_key {
        outbound = outbound.header("Authorization", format!("Bearer {}", key));
    } else {
        // Fallback: pass through the original auth if present
        if let Some(auth) = headers.get("authorization") {
            if let Ok(v) = auth.to_str() {
                outbound = outbound.header("Authorization", v);
            }
        }
    }

    // Send the request
    let response = outbound
        .body(body_bytes.to_vec())
        .send()
        .await
        .map_err(|e| {
            error!("Proxy forward error: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    let elapsed = start.elapsed();

    // ── Step 6: Audit logging ──────────────────────────────────
    info!(
        path = uri.path(),
        status = response.status().as_u16(),
        latency_ms = elapsed.as_millis(),
        pid = ?caller_pid,
        "Proxy request completed"
    );

    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let details = serde_json::json!({
                "path": uri.path(),
                "method": method.as_str(),
                "status": response.status().as_u16(),
                "latency_ms": elapsed.as_millis() as u64,
                "caller_pid": caller_pid,
                "provider": provider,
                "key_injected": real_key.is_some(),
            });
            let event = Event {
                event_type: "PROXY_FORWARD".to_string(),
                details_json: details.to_string(),
                severity: Severity::Info,
            };
            let _ = db.log_event(&event);
        }
    }

    // ── Build the response back to the caller ──────────────────
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let resp_headers = response.headers().clone();
    let resp_body = response.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    builder
        .body(Body::from(resp_body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── PID Identification ─────────────────────────────────────────

/// Get the PID of the process owning a TCP connection on the given local port.
/// Uses platform-specific methods.
#[cfg(target_os = "windows")]
fn get_pid_from_port(port: u16) -> Option<u32> {
    use std::process::Command;

    // Use netstat to find the PID — simple and reliable approach
    let output = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            // Look for local address matching our port
            if let Some(addr) = parts.get(1) {
                if addr.ends_with(&format!(":{}", port)) {
                    if let Some(pid_str) = parts.last() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn get_pid_from_port(port: u16) -> Option<u32> {
    use std::fs;

    // Parse /proc/net/tcp to find the socket inode
    let tcp_data = fs::read_to_string("/proc/net/tcp").ok()?;
    let port_hex = format!("{:04X}", port);

    for line in tcp_data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 10 {
            let local_addr = parts[1];
            if let Some(addr_port) = local_addr.split(':').nth(1) {
                if addr_port == port_hex {
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        return find_pid_by_inode(inode);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
    use std::fs;

    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(fds) = fs::read_dir(&fd_dir) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.contains(&format!("socket:[{}]", target_inode)) {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get the executable path for a given PID
fn get_exe_path_for_pid(pid: u32) -> Option<String> {
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::everything(),
    );

    let sysinfo_pid = sysinfo::Pid::from_u32(pid);
    system.process(sysinfo_pid).and_then(|p| {
        p.exe().map(|e| e.to_string_lossy().to_string())
    })
}

// ── Utility ────────────────────────────────────────────────────

/// Log a proxy event to the audit ledger
fn log_proxy_event(
    db: &Option<Mutex<Database>>,
    event_type: &str,
    addr: &SocketAddr,
    path: &str,
    severity: Severity,
) {
    if let Some(ref db_mutex) = db {
        if let Ok(db) = db_mutex.lock() {
            let details = serde_json::json!({
                "client": addr.to_string(),
                "path": path,
            });
            let event = Event {
                event_type: event_type.to_string(),
                details_json: details.to_string(),
                severity,
            };
            let _ = db.log_event(&event);
        }
    }
}
