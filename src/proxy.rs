// ──────────────────────────────────────────────────────────────
//  Raypher — Localhost Proxy (The Vault)
//  Listens on 127.0.0.1:8888, intercepts API calls from AI agents,
//  verifies the caller PID/exe hash, injects real API keys from
//  the TPM vault, and forwards requests to the target API.
// ──────────────────────────────────────────────────────────────

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post, delete},
    Router,
};
use crate::policy::DlpAction;
use tracing::{info, warn, error};

use crate::database::{Database, Event, Severity};
use crate::secrets;
use crate::installer;
use crate::dlp;
use crate::tls;
use crate::ssrf;
use crate::jailbreak;

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
    /// Active HTTP listen address
    pub http_addr: SocketAddr,
    /// Active TLS listen address
    pub tls_addr: SocketAddr,
    // ── Phase 5: Security Hardening ────────────────────────────
    /// Per-agent rate limiting: agent_hash → (request_count, window_start)
    pub agent_rate_limits: Arc<Mutex<HashMap<String, (u64, Instant)>>>,
    /// Session token binding: token → first PID that used it (prevents token theft)
    pub token_pid_map: Arc<Mutex<HashMap<String, u32>>>,
}

/// Default proxy listen address — NEVER bind to 0.0.0.0
const PROXY_ADDR: &str = "127.0.0.1:8888";
/// HTTPS proxy listen address
const PROXY_TLS_ADDR: &str = "127.0.0.1:8889";

// ── Public Interface ───────────────────────────────────────────

/// Start the proxy server using default configuration.
pub async fn start_proxy(with_tray: bool) -> Result<(), Box<dyn std::error::Error>> {
    let db = match Database::init() {
        Ok(db) => Some(Arc::new(Mutex::new(db))),
        Err(_) => None,
    };
    let http_addr: SocketAddr = PROXY_ADDR.parse()?;
    let tls_addr: SocketAddr = PROXY_TLS_ADDR.parse()?;
    start_proxy_engine(db, http_addr, tls_addr, with_tray).await
}

/// Start the proxy engine with specific database and addresses.
pub async fn start_proxy_engine(
    db: Option<Arc<Mutex<Database>>>,
    http_addr: SocketAddr,
    tls_addr: SocketAddr,
    with_tray: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls CryptoProvider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    info!("Starting Raypher proxy on {}", http_addr);

    // Build reqwest client with connection pooling (Keep-Alive)
    let http_client = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(120))
        .build()?;


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
        http_addr,
        tls_addr,
        // Phase 5: Security hardening
        agent_rate_limits: Arc::new(Mutex::new(HashMap::new())),
        token_pid_map: Arc::new(Mutex::new(HashMap::new())),
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
        // ─── Phase 5: DLP custom pattern CRUD ───
        .route("/api/dlp/patterns", get(crate::dashboard::handle_get_dlp_patterns))
        .route("/api/dlp/patterns", post(crate::dashboard::handle_add_dlp_pattern))
        .route("/api/dlp/patterns/:name", delete(crate::dashboard::handle_delete_dlp_pattern))
        .route("/api/discovery", get(crate::dashboard::handle_api_discovery))
        .route("/api/merkle/status", get(crate::dashboard::handle_api_merkle_status))
        // ─── Proxy catch-all ───
        .route("/v1/*path", any(handle_proxy))
        .route("/v1beta/*path", any(handle_proxy))
        .fallback(any(|method: Method, uri: Uri| async move {
            warn!("UNMATCHED REQUEST: {} {}", method, uri);
            StatusCode::NOT_FOUND
        }))
        .with_state(state.clone());

    // ─── HTTP listener ───
    let http_app = app.clone().into_make_service_with_connect_info::<SocketAddr>();
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    info!("✅ Raypher HTTP proxy listening on {}", http_addr);

    // ─── HTTPS listener ───
    let tls_handle = start_tls_listener(app.clone(), state.clone(), tls_addr);

    // ─── Phase 4 background tasks ───
    let policy_snap = state.policy.get();
    
    // 1. Shadow AI Discovery loop
    if policy_snap.phase4.shadow_discovery_enabled {
        let state_clone = state.clone();
        tokio::spawn(async move {
            info!("Shadow AI Discovery background task started");
            loop {
                let interval = state_clone.policy.get().phase4.shadow_discovery_interval_secs;
                tokio::time::sleep(Duration::from_secs(interval)).await;
                let _ = crate::discovery::run_full_scan();
            }
        });
    }

    // 2. System Tray (auto-launch with proxy)
    // Runs in a standard thread because tray-icon needs a run loop on some platforms
    let tray_handle = if with_tray {
        Some(std::thread::spawn(|| {
            crate::tray::start_tray(|| {
                warn!("PANIC: Kill-All requested from tray - SHUTTING DOWN PROXY");
                std::process::exit(1);
            });
        }))
    } else {
        None
    };

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
    
    // Attempt to join tray thread if proxy stops (though we usually exit above)
    if let Some(handle) = tray_handle {
        let _ = handle.join();
    }
    Ok(())
}
// ── TLS Listener ──────────────────────────────────────────────

/// Start a TLS listener on :8889 using the generated CA certificate.
/// This is best-effort — if TLS setup fails, the proxy continues HTTP-only.
async fn start_tls_listener(
    app: Router,
    state: Arc<ProxyState>,
    tls_addr: SocketAddr,
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
    let listener: tokio::net::TcpListener = match tokio::net::TcpListener::bind(tls_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("TLS listener skipped: failed to bind {}: {}", tls_addr, e);
            return;
        }
    };

    info!("🔒 Raypher HTTPS proxy listening on {}", tls_addr);

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
    info!(">>> PROXY REQUEST RECEIVED: {} {} (from {})", method, uri, addr);
    let start = std::time::Instant::now();

    // ── Step 1: Identify the calling process ───────────────────
    let caller_port = addr.port();
    let caller_pid = get_pid_from_port(caller_port);

    // ── Step 2: Resolve agent identity ────────────────────────
    let (caller_exe, agent_name, agent_hash) = {
        let exe = caller_pid.and_then(|p| get_exe_path_for_pid(p));
        let cmd_for_resolve: Vec<String> = vec![];
        let name = if let Some(ref exe_path) = exe {
            let bin_name = std::path::Path::new(exe_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            crate::scanner::resolve_agent_name(bin_name, &cmd_for_resolve)
        } else {
            "Unknown Agent".to_string()
        };
        let hash = exe.as_deref().map(|e| {
            use sha2::{Sha256, Digest};
            let mut h = Sha256::new();
            h.update(e.as_bytes());
            format!("{:x}", h.finalize())[..16].to_string()
        }).unwrap_or_else(|| format!("pid-{}", caller_pid.unwrap_or(0)));
        (exe, name, hash)
    };

    // ── Step 3: Register/update agent in registry ─────────────
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            crate::agent_registry::register_or_update(
                &db,
                &agent_hash,
                &agent_name,
                caller_exe.as_deref(),
            );
        }
    }

    // ── Step 4: Verify caller against allow-list ───────────────
    let mut is_authorized_by_exe = false;
    if let Some(pid) = caller_pid {
        if let Some(ref db_mutex) = state.db {
            if let Ok(db) = db_mutex.lock() {
                let exe_info = get_exe_path_for_pid(pid);
                if let Some(ref exe) = exe_info {
                    if secrets::is_allowed(&db, exe) {
                        is_authorized_by_exe = true;
                    }
                }
            }
        }
    }

    // ── Step 5: Extract and check the Raypher token ─────────────
    let raypher_token = headers
        .get("x-raypher-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if raypher_token.is_empty() && !is_authorized_by_exe {
        warn!(
            client = %addr,
            agent = %agent_name,
            "Request rejected: Neither X-Raypher-Token present nor executable in allow-list"
        );

        log_proxy_event(
            &state,
            "PROXY_UNAUTHORIZED",
            &addr,
            uri.path(),
            Severity::Warning,
            Some(&agent_hash),
            Some(&agent_name),
        );

        return Err(StatusCode::UNAUTHORIZED);
    }


    // ── Phase 5: Per-agent rate limiting (60 req/min max) ──────
    {
        let mut rate_limits = state.agent_rate_limits.lock().unwrap();
        let entry = rate_limits
            .entry(agent_hash.clone())
            .or_insert((0u64, Instant::now()));
        if entry.1.elapsed() >= Duration::from_secs(60) {
            // Reset window
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
            if entry.0 > 60 {
                warn!(agent = %agent_name, "Rate limit exceeded — blocking request");
                log_proxy_event(
                    &state,
                    "RATE_LIMIT_EXCEEDED",
                    &addr,
                    uri.path(),
                    Severity::Warning,
                    Some(&agent_hash),
                    Some(&agent_name),
                );
                return Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    "Rate limit exceeded — try again in 60 seconds\n",
                ).into_response());
            }
        }
    }

    // ── Phase 5: Session token binding (prevent token theft) ───
    // The first PID to use a token claims it; all others are rejected.
    if !raypher_token.is_empty() {
        if let Some(pid) = caller_pid {
            let mut token_map = state.token_pid_map.lock().unwrap();
            let owner_pid = token_map.entry(raypher_token.to_string()).or_insert(pid);
            if *owner_pid != pid {
                warn!(
                    pid = pid,
                    owner = owner_pid,
                    "Token hijack detected — token already bound to different PID"
                );
                log_proxy_event(
                    &state,
                    "TOKEN_HIJACK_BLOCKED",
                    &addr,
                    uri.path(),
                    Severity::Critical,
                    Some(&agent_hash),
                    Some(&agent_name),
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    info!(
        client = %addr,
        pid = ?caller_pid,
        agent = %agent_name,
        path = uri.path(),
        "Proxy request received"
    );



    // ── Step 3c: SSRF Shield — Host Header Check ────────────────
    // Prevent host-header injection attacks where an adversarial agent
    // spoofs "Host: 169.254.169.254" to redirect the proxy to an internal
    // cloud metadata service or other internal network resource.
    //
    // IMPORTANT: We intentionally skip this check when the Host header is
    // the proxy's own listen address (127.0.0.1:288xx) — legitimate clients
    // connecting to a local proxy always send their target as Host.
    {
        let policy_snap = state.policy.get();
        if policy_snap.phase4.ssrf_shield_enabled {
            if let Some(host_hdr) = headers.get("host").and_then(|v| v.to_str().ok()) {
                // Strip port from host header (e.g. "169.254.169.254:80" → "169.254.169.254")
                let host_only = host_hdr.split(':').next().unwrap_or(host_hdr);
                let port_str  = host_hdr.split(':').nth(1).unwrap_or("");

                // Skip SSRF check for the proxy's own loopback listen sockets.
                // (Bypass SSRF check if request targets Raypher's own ports.)
                let is_proxy_self = (host_only == "127.0.0.1" || host_only == "localhost")
                    && (port_str == state.http_addr.port().to_string() 
                        || port_str == state.tls_addr.port().to_string() 
                        || port_str.is_empty());

                if !is_proxy_self {
                    if let ssrf::SsrfVerdict::Block { reason } = ssrf::check_host(host_only) {
                        warn!(
                            host = host_hdr,
                            reason = %reason,
                            "SSRF blocked: Host header targets internal address"
                        );
                        log_proxy_event(
                            &state,
                            "SSRF_HOST_BLOCKED",
                            &addr,
                            &format!("SSRF shield (Host header): {}", reason),
                            Severity::Critical,
                            Some(&agent_hash),
                            Some(&agent_name),
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        }
    }

    // ── Step 3b: Temporal Policy Check ─────────────────────────
    // Deny requests outside allowed work hours / on blocked weekends.
    {
        let policy_snap = state.policy.get();
        if !crate::policy::check_time_restriction(&policy_snap) {
            eprintln!("DEBUG: temporal check BLOCKED");
            warn!(
                client = %addr,
                "Request denied — outside allowed time window"
            );
            log_proxy_event(
                &state,
                "TIME_RESTRICTED",
                &addr,
                "AI access blocked: outside work hours or on restricted day",
                Severity::Warning,
                Some(&agent_hash),
                Some(&agent_name),
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // ── Step 4: Collect body and detect provider ───────────────
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;

    // Parse body as JSON for provider detection and DLP
    let body_json = serde_json::from_slice::<serde_json::Value>(&body_bytes).ok();

    // Detect provider: proprietary headers > raypher header > host > model name > default(openai)
    let goog_key = headers.get("x-goog-api-key");
    let anthropic_key = headers.get("x-api-key");
    let azure_key = headers.get("api-key");

    let provider_header = headers
        .get("x-raypher-provider")
        .and_then(|v| v.to_str().ok());
    let original_host = headers
        .get("x-original-host")
        .and_then(|v| v.to_str().ok());

    let has_google_query = uri.query().map(|q| q.contains("key=")).unwrap_or(false);

    let provider = if goog_key.is_some() || (has_google_query && original_host.map(|h| h.contains("google")).unwrap_or(true)) {
        "google"
    } else if anthropic_key.is_some() {
        "anthropic"
    } else if azure_key.is_some() {
        "azure"
    } else {
        installer::detect_provider(
            provider_header,
            original_host,
            body_json.as_ref(),
        )
    };

    let route = installer::get_provider_route(provider)
        .unwrap_or(&installer::PROVIDERS[0]); // Fallback to OpenAI

    info!(
        provider = provider,
        upstream_url = route.base_url,
        "Provider detected"
    );

    // ── Step 4a: Domain Whitelist Check ────────────────────────
    // Extract the upstream hostname and check against the policy whitelist/blocklist.
    // This enforces that AI agents can only call approved API providers.
    if let Ok(parsed_url) = url::Url::parse(route.base_url) {
        if let Some(upstream_host) = parsed_url.host_str() {
            let policy_snap = state.policy.get();
            if !crate::policy::check_domain(&policy_snap, upstream_host) {
                eprintln!("DEBUG: domain check BLOCKED: {}", upstream_host);
                warn!(
                    domain = upstream_host,
                    provider = provider,
                    "Request denied — domain not in policy whitelist"
                );
                log_proxy_event(
                    &state,
                    "DOMAIN_BLOCKED",
                    &addr,
                    &format!("Blocked: destination '{}' not allowed by policy", upstream_host),
                    Severity::Critical,
                    Some(&agent_hash),
                    Some(&agent_name),
                );
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    // ── Step 4a-2: SSRF Shield ──────────────────────────────────
    // Block any request whose target resolves to a private/internal address.
    // This prevents AI agents from pivoting into the internal network.
    {
        let ssrf_check = ssrf::check_url(route.base_url);
        if let ssrf::SsrfVerdict::Block { reason } = ssrf_check {
            warn!(
                url = route.base_url,
                reason = %reason,
                "SSRF blocked: request targets internal address"
            );
            log_proxy_event(
                &state,
                "SSRF_BLOCKED",
                &addr,
                &format!("SSRF shield: {}", reason),
                Severity::Critical,
                Some(&agent_hash),
                Some(&agent_name),
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

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
            &state,
            "BUDGET_BLOCKED",
            &addr,
            uri.path(),
            Severity::Critical,
            Some(&agent_hash),
            Some(&agent_name),
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // ── Step 4b-2: Runtime limit check ─────────────────────────
    {
        let policy_snap = state.policy.get();
        let max_runtime = policy_snap.budget.max_runtime_minutes;
        if max_runtime > 0 {
            let exceeded = if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    crate::agent_registry::is_runtime_exceeded(&db, &agent_hash, max_runtime)
                } else { false }
            } else { false };

            if exceeded {
                warn!(
                    agent = %agent_name,
                    max_runtime_minutes = max_runtime,
                    "Runtime limit exceeded — blocking request"
                );
                log_proxy_event(
                    &state,
                    "RUNTIME_EXCEEDED",
                    &addr,
                    uri.path(),
                    Severity::Warning,
                    Some(&agent_hash),
                    Some(&agent_name),
                );
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
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

    // ── Step 4c: Jailbreak / Prompt Injection Filter ───────────
    // Scan message content for known prompt injection patterns.
    if let Some(ref json) = body_json {
        let prompt_text = jailbreak::extract_prompt_text(json);
        let block_medium = policy.phase4.block_medium_jailbreak;
        let jb_verdict = jailbreak::scan(&prompt_text, block_medium);
        if jb_verdict.is_blocked() {
            if let jailbreak::JailbreakVerdict::Blocked { ref matches } = jb_verdict {
                warn!(
                    patterns = matches.len(),
                    first = %matches[0].pattern_name,
                    "Jailbreak/prompt injection blocked"
                );
                log_proxy_event(
                    &state,
                    "JAILBREAK_BLOCKED",
                    &addr,
                    &format!("Prompt injection detected: {}", matches[0].pattern_name),
                    Severity::Critical,
                    Some(&agent_hash),
                    Some(&agent_name),
                );
            }
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    // ── Step 5: DLP Scan (Request Body) ────────────────────────
    let mut final_body = if model_was_routed {
        serde_json::to_vec(&body_json_mut.unwrap()).unwrap_or_else(|_| body_bytes.to_vec())
    } else {
        body_bytes.to_vec()
    };

    if let Some(ref body_str) = String::from_utf8(final_body.clone()).ok() {
        let dlp_result = dlp::scan(
            body_str,
            &policy.dlp.default_action,
            &policy.phase4.custom_dlp_patterns, // Phase 4: use custom patterns from policy
            &policy.dlp.exclusions,
            policy.dlp.entropy_threshold,
        );

        if !dlp_result.findings.is_empty() {
            let mut strictest_action = DlpAction::Alert;
            for finding in &dlp_result.findings {
                // Custom patterns use the policy default_action; built-in patterns
                // use per-category action overrides (falling back to default_action).
                let action = if finding.category == "custom" {
                    policy.dlp.default_action.clone()
                } else {
                    policy.dlp.action_for_category(finding.category.as_str()).clone()
                };
                match action {
                    DlpAction::Block => strictest_action = DlpAction::Block,
                    DlpAction::Redact if strictest_action != DlpAction::Block =>
                        strictest_action = DlpAction::Redact,
                    _ => {}
                }
            }

            info!(findings = dlp_result.findings.len(), action = ?strictest_action, "DLP: Sensitive data in request");
 
            if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    for f in &dlp_result.findings {
                        let _ = db.log_dlp_finding("Outbound", &f.category, &f.pattern_name, &format!("{:?}", strictest_action), Some(&f.matched_text), Some(provider));
                    }
                }
            }

            let event_type = match strictest_action {
                DlpAction::Block => "DLP_BLOCKED",
                _ => "DLP_MATCHED",
            };

            log_proxy_event(
                &state,
                event_type,
                &addr,
                &format!("DLP scan detected {} findings", dlp_result.findings.len()),
                Severity::Critical,
                Some(&agent_hash),
                Some(&agent_name),
            );

            match strictest_action {
                DlpAction::Block => {
                    return Err(StatusCode::FORBIDDEN);
                }
                DlpAction::Redact if dlp_result.was_modified => final_body = dlp_result.clean_payload.into_bytes(),
                _ => {}
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

    let pq_str = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(uri.path());
    let mut final_pq = pq_str.to_string();

    // ── Gemini Query Parameter Trap ──
    // Google SDKs often put the API key in the URL (?key=...). 
    // If we leave it there (even a dummy key), it overrides our injected header.
    if provider == "google" {
        // Upgrade /v1 to /v1beta for advanced features (systemInstruction, tools)
        if final_pq.starts_with("/v1/") {
            final_pq = final_pq.replacen("/v1/", "/v1beta/", 1);
            info!("Upgrading Gemini endpoint: /v1 -> /v1beta");
        }

        if let Some(pos) = final_pq.find('?') {
            let (path, query_with_q) = final_pq.split_at(pos);
            let query = &query_with_q[1..]; // skip '?'
            
            let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .filter(|(k, _)| k != "key")
                .collect();
            
            if params.is_empty() {
                final_pq = path.to_string();
            } else {
                let encoded: String = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(params)
                    .finish();
                final_pq = format!("{}?{}", path, encoded);
            }
        }
    }

    let target_url = format!("{}{}", route.base_url, final_pq);

    let mut outbound = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::POST),
        &target_url,
    );

    // Copy headers (skip proxy-internal headers)
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str == "host"
            || name_str == "connection"
            || name_str == "content-length"
            || name_str == "transfer-encoding"
            || name_str == "x-raypher-token"
            || name_str == "x-raypher-provider"
            || name_str == "x-original-host"
            || name_str == "authorization"
            || name_str == "x-api-key"
            || name_str == "x-goog-api-key"
            || name_str == "api-key"
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

    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let details = serde_json::json!({
                "path": uri.path(),
                "outbound_path": final_pq,
                "method": method.as_str(),
                "caller_pid": caller_pid,
                "provider": provider,
                "agent": &agent_name,
            });
            let event = Event {
                event_type: "PROXY_ATTEMPT".to_string(),
                details_json: details.to_string(),
                severity: Severity::Info,
            };
            let _ = db.log_event(&event);
        }
    }

    // Send the request with (possibly DLP-cleaned) body
    let body_len = final_body.len();
    let response_res = outbound
        .header("content-length", body_len.to_string())
        .body(final_body)
        .send()
        .await;

    let elapsed = start.elapsed();

    let response = match response_res {
        Ok(resp) => resp,
        Err(e) => {
            error!(path = uri.path(), provider = provider, "Proxy forward error: {}", e);
            if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    let _ = db.log_event(&Event {
                        event_type: "PROXY_ERROR".to_string(),
                        details_json: serde_json::json!({
                            "error": e.to_string(),
                            "provider": provider,
                        }).to_string(),
                        severity: Severity::Warning,
                    });
                }
            }
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

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
                "agent": &agent_name,
            });
            let event = Event {
                event_type: "PROXY_FORWARD".to_string(),
                details_json: details.to_string(),
                severity: Severity::Info,
            };
            let _ = db.log_event(&event);
            // Update agent registry: clean request = slow trust recovery
            crate::agent_registry::record_event(&db, &agent_hash, "PROXY_FORWARD");
        }
    }

    // ── Build the response back to the caller ──────────────────
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let resp_headers = response.headers().clone();
    let resp_body = response.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    // ── Step 7: DLP Scan (Response Body) ────────────────────────
    let mut final_resp_body = resp_body.clone();
    if let Ok(resp_str) = std::str::from_utf8(&resp_body) {
        let dlp_result = dlp::scan(
            resp_str,
            &policy.dlp.default_action,
            &policy.phase4.custom_dlp_patterns, // Phase 4: custom patterns on responses too
            &policy.dlp.exclusions,
            policy.dlp.entropy_threshold,
        );
        if !dlp_result.findings.is_empty() {
            if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    for f in &dlp_result.findings {
                        let _ = db.log_dlp_finding("Inbound", &f.category, &f.pattern_name, "Redact", Some(&f.matched_text), Some(provider));
                    }
                }
            }
            log_proxy_event(
                &state,
                "DLP_RESPONSE_REDACTED",
                &addr,
                uri.path(),
                Severity::Warning,
                Some(&agent_hash),
                Some(&agent_name),
            );
            if dlp_result.was_modified {
                final_resp_body = dlp_result.clean_payload.into();
            }
        }
    }

    // ── Step 8: Advanced Spend Tracking ────────────────────────
    if status.is_success() {
        if let Some(ref db_mutex) = state.db {
            if let Ok(db) = db_mutex.lock() {
                let model = body_json.as_ref().and_then(|j| j.get("model")).and_then(|m| m.as_str()).unwrap_or("unknown");
                let usage = serde_json::from_slice::<serde_json::Value>(&resp_body).ok();
                let tokens_in = usage.as_ref().and_then(|u| u.get("usage")).and_then(|us| us.get("prompt_tokens")).and_then(|t| t.as_u64()).unwrap_or(0) as u32;
                let tokens_out = usage.as_ref().and_then(|u| u.get("usage")).and_then(|us| us.get("completion_tokens")).and_then(|t| t.as_u64()).unwrap_or(0) as u32;
                
                let agent_hash = caller_pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string());
                let _ = db.record_spend(&agent_hash, provider, model, tokens_in, tokens_out);
            }
        }
    }
      let mut builder = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip length-related headers as we've buffered and potentially modified the body
        if name_str == "content-length" || name_str == "transfer-encoding" {
            continue;
        }
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

/// Log a proxy event to the audit ledger (SQLite + Merkle)
fn log_proxy_event(
    state: &ProxyState,
    event_type: &str,
    addr: &SocketAddr,
    path: &str,
    severity: Severity,
    agent_hash: Option<&str>,
    agent_name: Option<&str>,
) {
    let policy = state.policy.get();
    let details = serde_json::json!({
        "client": addr.to_string(),
        "path": path,
        "agent": agent_name.unwrap_or("unknown"),
    });
    let details_str = details.to_string();

    // 1. Log to SQLite (if available)
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let event = Event {
                event_type: event_type.to_string(),
                details_json: details_str.clone(),
                severity,
            };
            let _ = db.log_event(&event);

            // 2. Update agent trust score for bad events
            if let Some(hash) = agent_hash {
                crate::agent_registry::record_event(&db, hash, event_type);
            }
        }
    }

    // 3. Append to Merkle-Chained Ledger (if enabled)
    if policy.phase4.merkle_ledger_enabled {
        let ledger_path = &policy.phase4.merkle_ledger_path;
        if let Err(e) = crate::merkle::append_to_ledger(ledger_path, event_type, &details_str) {
            error!("FAILED to append to Merkle ledger: {}", e);
        }
    }
}
