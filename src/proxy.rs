// ──────────────────────────────────────────────────────────────
//  Raypher — Localhost Proxy (The Vault)
//  Listens on 127.0.0.1:8888, intercepts API calls from AI agents,
//  verifies the caller PID/exe hash, injects real API keys from
//  the TPM vault, and forwards requests to the target API.
// ──────────────────────────────────────────────────────────────

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post, delete},
    Router,
};
use tracing::{info, warn, error};

use crate::database::{Database, Event, Severity};
use crate::secrets;
use crate::installer;
use crate::dlp;
use crate::tls;

// ── Configuration ──────────────────────────────────────────────

/// Proxy configuration — shared across all async handlers via Arc.
pub struct ProxyState {
    /// HTTP client with connection pooling for outbound requests
    pub http_client: reqwest::Client,
    /// The target API base URL (e.g., "https://api.openai.com")
    pub target_base_url: String,
    /// Database for audit logging and allow-list checks (Mutex for thread safety)
    pub db: Option<Arc<Mutex<Database>>>,
    /// Service start time for uptime tracking
    pub start_time: Instant,
    /// Shared policy holder (hot-reloads from YAML)
    pub policy: Arc<crate::policy::PolicyHolder>,
    /// TLS Manager for HTTPS interception
    pub tls_manager: Option<Arc<crate::tls::TlsManager>>,
}

/// Default proxy listen address — NEVER bind to 0.0.0.0
const PROXY_ADDR: &str = "127.0.0.1:8888";
/// HTTPS proxy listen address
const PROXY_TLS_ADDR: &str = "127.0.0.1:8889";

// ── Public Interface ───────────────────────────────────────────

/// Start the proxy server. This blocks the async runtime.
/// Called from `service.rs` (service mode) or from CLI for testing.
pub async fn start_proxy() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls CryptoProvider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

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
            Some(Arc::new(Mutex::new(db)))
        }
        Err(e) => {
            warn!("Proxy database unavailable: {}. Audit logging disabled.", e);
            None
        }
    };

    // Load initial policy
    let initial_policy = if let Some(ref db_mutex) = db {
        let db_lock = db_mutex.lock().unwrap();
        crate::policy::load_policy(&db_lock)
    } else {
        crate::policy::PolicyConfig::default()
    };
    
    let policy_holder = Arc::new(crate::policy::PolicyHolder::new(initial_policy));

    if let Some(ref db_mutex) = db {
        // Start policy watcher (background)
        let _watcher = crate::policy::start_policy_watcher(policy_holder.clone(), db_mutex.clone());
    }

    let tls_manager = if let Some(ref db_arc) = db {
        let db_lock = db_arc.lock().unwrap();
        Some(Arc::new(crate::tls::TlsManager::new(&db_lock, "raypher-local-machine")))
    } else {
        None
    };

    let state = Arc::new(ProxyState {
        http_client,
        target_base_url: "https://api.openai.com".to_string(),
        db,
        start_time: Instant::now(),
        policy: policy_holder,
        tls_manager,
    });

    // Build the router
    let app = Router::new()
        // ─── Existing routes ───
        .route("/health", get(handle_health))
        .route("/dashboard", get(crate::dashboard::handle_dashboard))
        .route("/api/status", get(crate::dashboard::handle_api_status))
        .route("/api/events", get(crate::dashboard::handle_api_events))
        .route("/api/secrets", get(crate::dashboard::handle_api_secrets))
        .route("/api/allowlist", get(crate::dashboard::handle_api_allowlist))
        // ─── New interactive routes ───
        .route("/api/secrets/seal", post(crate::dashboard::handle_seal_secret))
        .route("/api/secrets/:provider", delete(crate::dashboard::handle_delete_secret))
        .route("/api/allowlist/add", post(crate::dashboard::handle_add_allowlist))
        .route("/api/allowlist/:exe_hash", delete(crate::dashboard::handle_remove_allowlist))
        .route("/api/agents", get(crate::dashboard::handle_api_agents))
        .route("/api/panic", post(crate::dashboard::handle_panic))
        .route("/api/config", get(crate::dashboard::handle_get_config))
        .route("/api/config/update", post(crate::dashboard::handle_update_config))
        .route("/api/config/policy", get(crate::dashboard::handle_get_policy))
        .route("/api/config/policy/update", post(crate::dashboard::handle_update_policy))
        .route("/api/stats/spend", get(crate::dashboard::handle_spend_stats))
        .route("/api/stats/threats", get(crate::dashboard::handle_threat_stats))
        // ─── DLP routes ───
        .route("/api/dlp/stats", get(crate::dashboard::handle_dlp_stats))
        .route("/api/dlp/findings", get(crate::dashboard::handle_dlp_findings))
        .route("/api/dlp/config", get(crate::dashboard::handle_dlp_config))
        // ─── Proxy catch-all ───
        .route("/v1/*path", any(handle_proxy))
        .with_state(state.clone());

    // ─── HTTP listener (port 8888) ───
    let http_app = app.clone().into_make_service_with_connect_info::<SocketAddr>();
    let http_listener = tokio::net::TcpListener::bind(PROXY_ADDR).await?;
    info!("✅ Raypher HTTP proxy listening on {}", PROXY_ADDR);

    // ─── HTTPS listener (port 8889) ───
    let tls_handle = start_tls_listener(app.clone(), state.clone());

    // Run both concurrently — HTTP is primary, TLS is best-effort
    tokio::select! {
        res = axum::serve(http_listener, http_app) => {
            if let Err(e) = res {
                error!("HTTP proxy error: {}", e);
            }
        }
        _ = tls_handle => {
            warn!("TLS listener exited");
        }
    }
    Ok(())
}
// ── TLS Listener ──────────────────────────────────────────────

/// Start a TLS listener on :8889 using the generated CA certificate.
/// This is best-effort — if TLS setup fails, the proxy continues HTTP-only.
async fn start_tls_listener(
    app: Router,
    state: Arc<ProxyState>,
) {
    use tokio_rustls::TlsAcceptor;
    use rustls::ServerConfig;
    use rustls_pemfile;

    // Generate or load CA
    let db_ref = match &state.db {
        Some(db) => db,
        None => {
            warn!("TLS listener skipped: no database available");
            return;
        }
    };

    let db = db_ref.lock().unwrap();
    let tls_mgr = tls::TlsManager::new(&db, "localhost-proxy");
    drop(db);

    let _ca = match &tls_mgr.ca {
        Some(ca) => ca,
        None => {
            warn!("TLS listener skipped: no CA certificate generated");
            return;
        }
    };

    // Generate a cert for localhost
    let domain_cert = match tls_mgr.get_domain_cert("localhost") {
        Some(cert) => cert,
        None => {
            warn!("TLS listener skipped: failed to generate localhost cert");
            return;
        }
    };

    // Build rustls ServerConfig
    // rustls_pemfile v2: certs() returns an iterator of Result<CertificateDer>
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut domain_cert.cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        warn!("TLS listener skipped: no certificates parsed from PEM");
        return;
    }

    let key = match rustls_pemfile::private_key(&mut domain_cert.key_pem.as_bytes()) {
        Ok(Some(key)) => key,
        _ => {
            warn!("TLS listener skipped: failed to parse key PEM");
            return;
        }
    };

    let tls_config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
    {
        Ok(config) => config,
        Err(e) => {
            warn!("TLS listener skipped: failed to build ServerConfig: {}", e);
            return;
        }
    };

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Bind TLS listener
    let listener = match tokio::net::TcpListener::bind(PROXY_TLS_ADDR).await {
        Ok(l) => l,
        Err(e) => {
            warn!("TLS listener skipped: failed to bind {}: {}", PROXY_TLS_ADDR, e);
            return;
        }
    };

    info!("🔒 Raypher HTTPS proxy listening on {}", PROXY_TLS_ADDR);

    // Accept loop
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("TLS accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move {
                            let response = tower::ServiceExt::oneshot(app, req).await;
                            response
                        }
                    });
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        warn!("TLS connection error from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    warn!("TLS handshake error from {}: {}", addr, e);
                }
            }
        });
    }
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
    let mut block_allowlist = false;
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
                        block_allowlist = true;
                    }
                }
            }
        }
    }

    if block_allowlist {
        log_proxy_event(
            &state.db,
            "PROXY_BLOCKED",
            &addr,
            uri.path(),
            Severity::Critical,
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // ── Step 4: Collect body and detect provider ───────────────
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    // Parse body as JSON for provider detection and DLP
    let body_json = serde_json::from_slice::<serde_json::Value>(&body_bytes).ok();

    // Detect provider: header > host > model name > default(openai)
    let provider_header = headers
        .get("x-raypher-provider")
        .and_then(|v| v.to_str().ok());
    let original_host = headers
        .get("x-original-host")
        .and_then(|v| v.to_str().ok());
    let provider = installer::detect_provider(
        provider_header,
        original_host,
        body_json.as_ref(),
    );

    let route = installer::get_provider_route(provider)
        .unwrap_or(&installer::PROVIDERS[0]); // Fallback to OpenAI

    info!(
        provider = provider,
        target = route.base_url,
        "Provider detected"
    );
 
    // ── Step 4b: Policy Check (Budget & Routing) ───────────────
    let policy = state.policy.get();
    let mut budget_exceeded = false;
    let mut block_request = false;
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let budget_status = crate::policy::check_budget(&policy, &db);
            if budget_status.is_exceeded() {
                budget_exceeded = true;
                warn!("Budget exceeded: {:?}", budget_status);
                
                if policy.budget.action_on_exceed == crate::policy::BudgetAction::Block {
                    block_request = true;
                }
            }
        }
    }

    if block_request {
        log_proxy_event(
            &state.db,
            "BUDGET_BLOCKED",
            &addr,
            uri.path(),
            Severity::Critical,
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Apply model routing (e.g. downgrade if budget exceeded)
    let mut body_json_mut = body_json.clone();
    let mut model_was_routed = false;
    if let Some(ref mut json) = body_json_mut {
        let routed_model = if let Some(model) = json["model"].as_str() {
            let routed = crate::policy::route_model(&policy, model, budget_exceeded);
            if routed != model {
                info!("Model routed: {} -> {}", model, routed);
                Some(routed)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(new_model) = routed_model {
            json["model"] = serde_json::json!(new_model);
            model_was_routed = true;
        }
    }

    // ── Step 5: DLP Scan (Request Body) ────────────────────────
    let mut final_body = if model_was_routed {
        serde_json::to_vec(&body_json_mut.unwrap()).unwrap_or_else(|_| body_bytes.to_vec())
    } else {
        body_bytes.to_vec()
    };

    if let Some(ref body_str) = String::from_utf8(final_body.clone()).ok() {
        // Use default action from policy for initial scan
        let dlp_result = dlp::scan(
            body_str,
            &crate::policy::DlpAction::Redact, // We'll always scan, but decide action later
            &[],  // Custom patterns loaded from policy in future
            &policy.dlp.exclusions,
        );

        if !dlp_result.findings.is_empty() {
            // Determine strictest action
            let mut strictest_action = crate::policy::DlpAction::Alert;
            for finding in &dlp_result.findings {
                let action = policy.dlp.action_for_category(finding.category.as_str());
                match action {
                    crate::policy::DlpAction::Block => strictest_action = crate::policy::DlpAction::Block,
                    crate::policy::DlpAction::Redact if strictest_action != crate::policy::DlpAction::Block => 
                        strictest_action = crate::policy::DlpAction::Redact,
                    _ => {}
                }
            }

            info!(
                findings = dlp_result.findings.len(),
                strictest_action = ?strictest_action,
                "DLP: Sensitive data detected in request"
            );

            // Log DLP event
            if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    let details = serde_json::json!({
                        "direction": "request",
                        "findings_count": dlp_result.findings.len(),
                        "categories": dlp_result.findings.iter()
                            .map(|f| f.category.as_str())
                            .collect::<Vec<_>>(),
                        "action": format!("{:?}", strictest_action).to_lowercase(),
                    });
                    let event = Event {
                        event_type: "DLP_DETECTION".to_string(),
                        details_json: details.to_string(),
                        severity: if strictest_action == crate::policy::DlpAction::Block { Severity::Critical } else { Severity::Warning },
                    };
                    let _ = db.log_event(&event);
                }
            }

            match strictest_action {
                crate::policy::DlpAction::Block => return Err(StatusCode::FORBIDDEN),
                crate::policy::DlpAction::Redact => {
                    if dlp_result.was_modified {
                        final_body = dlp_result.clean_payload.into_bytes();
                    }
                }
                _ => {} // Alert/Allow just continues
            }
        }
    }

    // ── Step 6: Unseal API key and build outbound request ──────
    let real_key = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            secrets::unseal_key(&db, provider).ok()
        } else {
            None
        }
    } else {
        None
    };

    let target_url = format!(
        "{}{}",
        route.base_url,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(uri.path())
    );

    let mut outbound = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &target_url,
    );

    // Copy headers (skip proxy-internal headers)
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "host"
            || name_str == "connection"
            || name_str == "x-raypher-token"
            || name_str == "x-raypher-provider"
            || name_str == "x-original-host"
            || name_str == "authorization"
            || name_str == "x-api-key"
            || name_str == "x-goog-api-key"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            outbound = outbound.header(name.as_str(), v);
        }
    }

    // Inject the correct auth header for this provider
    if let Some(ref key) = real_key {
        let auth_value = format!("{}{}", route.auth_prefix, key);
        outbound = outbound.header(route.auth_header, auth_value);
    } else {
        // Fallback: pass through original auth if present
        if let Some(auth) = headers.get("authorization") {
            if let Ok(v) = auth.to_str() {
                outbound = outbound.header("Authorization", v);
            }
        }
    }

    // Send the request with (possibly DLP-cleaned) body
    let response = outbound
        .body(final_body)
        .send()
        .await
        .map_err(|e| {
            error!("Proxy forward error to {}: {}", route.base_url, e);
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

    // ── Step 6.5: Spend Tracking ───────────────────────────────
    if status.is_success() {
        if let Some(ref db_mutex) = state.db {
            if let Ok(db) = db_mutex.lock() {
                let model = body_json.as_ref()
                    .and_then(|j| j.get("model"))
                    .and_then(|m| m.as_str());
                
                let usage_json = serde_json::from_slice::<serde_json::Value>(&resp_body).ok();
                let tokens = usage_json.as_ref()
                    .and_then(|u| u.get("usage"))
                    .and_then(|us| us.get("total_tokens"))
                    .and_then(|t| t.as_i64());
                
                let cost = 0.01; // Constant for testing
                let _ = db.log_spend(provider, model, cost, tokens);
            }
        }
    }

    // ── Step 7: DLP Scan (Response Body) ────────────────────────
    let mut final_resp_body = resp_body.clone();
    if let Ok(resp_str) = std::str::from_utf8(&resp_body) {
        let dlp_result = dlp::scan(
            resp_str,
            &crate::policy::DlpAction::Redact,
            &[],
            &[],
        );
        if !dlp_result.findings.is_empty() {
            info!(
                findings = dlp_result.findings.len(),
                "DLP: Sensitive data detected in response"
            );

            // Log to database
            if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    for f in &dlp_result.findings {
                        let _ = db.log_dlp_finding(
                            "Inbound",
                            &f.category,
                            &f.pattern_name,
                            "Redact",
                            Some(&f.matched_text),
                            Some(provider),
                        );
                    }

                    // Also log a dashboard event
                    let event = Event {
                        event_type: "DLP_BLOCK".to_string(),
                        details_json: serde_json::json!({
                            "findings": dlp_result.findings.len(),
                            "provider": provider,
                            "action": "Redact"
                        }).to_string(),
                        severity: Severity::Critical,
                    };
                    let _ = db.log_event(&event);
                }
            }

            if dlp_result.was_modified {
                final_resp_body = dlp_result.clean_payload.into();
            }
        }
    }

    // ── Step 8: Spend tracking — per-model cost estimation ─────
    if status.is_success() {
        if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&resp_body) {
            if let Some(usage) = resp_json.get("usage") {
                let total_tokens = usage.get("total_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                let model = resp_json.get("model").and_then(|v| v.as_str()).unwrap_or("unknown");
                // Per-model cost estimation
                let cost_per_1k = match model {
                    m if m.contains("gpt-4-turbo") => 0.01,
                    m if m.contains("gpt-4") => 0.03,
                    m if m.contains("gpt-3.5") => 0.0005,
                    m if m.contains("claude-3-opus") => 0.015,
                    m if m.contains("claude-3-sonnet") => 0.003,
                    m if m.contains("claude-3-haiku") => 0.00025,
                    m if m.contains("gemini") => 0.001,
                    _ => 0.001,
                };
                let cost = (total_tokens as f64 / 1000.0) * cost_per_1k;
                if let Some(ref db_mutex) = state.db {
                    if let Ok(db) = db_mutex.lock() {
                        let _ = db.log_spend(provider, Some(model), cost, Some(total_tokens));
                    }
                }
            }
        }
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    builder
        .body(Body::from(final_resp_body))
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
    db: &Option<Arc<Mutex<Database>>>,
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
