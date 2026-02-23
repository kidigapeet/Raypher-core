// ──────────────────────────────────────────────────────────────
//  Raypher — Command Center Dashboard
//  Interactive web dashboard served from the proxy.
//  Features: Live Stream, Mission Control, Vault, Intel, Settings
// ──────────────────────────────────────────────────────────────

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse},
    http::StatusCode,
    Json,
};
use serde::{Deserialize};
use std::sync::{Arc};

use crate::proxy::ProxyState;
use crate::policy;
use crate::secrets;
use crate::scanner;
use crate::config::RaypherConfig;

// ── Query / Request Types ──────────────────────────────────────

#[derive(Deserialize)]
pub struct EventsQuery {
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
pub struct SealRequest {
    pub provider: String,
    pub key: String,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
    pub label: Option<String>,
}

fn default_secret_type() -> String { "api_key".to_string() }

#[derive(Deserialize)]
pub struct AllowlistRequest {
    pub exe_path: String,
}

#[derive(Deserialize)]
pub struct PanicRequest {
    pub pids: Vec<u32>,
}

// ── Existing Read Handlers ─────────────────────────────────────

/// GET /dashboard — Serves the full HTML dashboard page
pub async fn handle_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// GET /api/status — System status overview
pub async fn handle_api_status(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let (event_count, secret_count, allowed_count) = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            (
                db.event_count().unwrap_or(0),
                db.list_secrets().map(|s| s.len() as i64).unwrap_or(0),
                db.list_allow_list().map(|a| a.len() as i64).unwrap_or(0),
            )
        } else {
            (0, 0, 0)
        }
    } else {
        (0, 0, 0)
    };

    let fingerprint = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            db.get_fingerprint().unwrap_or_else(|_| "unknown".to_string())
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime_secs,
        "event_count": event_count,
        "secret_count": secret_count,
        "allowed_count": allowed_count,
        "fingerprint": fingerprint,
    });

    (StatusCode::OK, Json(body))
}

/// GET /api/events — Recent audit events
pub async fn handle_api_events(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<EventsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50);

    let events = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            db.recent_events(limit).unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let events_json: Vec<serde_json::Value> = events
        .iter()
        .map(|(id, ts, etype, details, severity)| {
            // Parse details JSON for description generation
            let details_val: serde_json::Value = serde_json::from_str(details)
                .unwrap_or_else(|_| serde_json::json!({}));
            let description = crate::event_descriptions::describe_event(etype, &details_val);
            let formatted_time = crate::event_descriptions::format_iso_timestamp(ts);
            serde_json::json!({
                "id": id,
                "timestamp": ts,
                "formatted_time": formatted_time,
                "event_type": etype,
                "description": description,
                "details": details,
                "severity": severity,
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "events": events_json })))
}

/// GET /api/secrets — List sealed providers
pub async fn handle_api_secrets(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let secrets = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            db.list_secrets().unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let secrets_json: Vec<serde_json::Value> = secrets
        .iter()
        .map(|(provider, created, secret_type, label)| {
            serde_json::json!({
                "provider": provider,
                "created_at": created,
                "status": "sealed",
                "secret_type": secret_type,
                "label": label.as_deref().unwrap_or(provider)
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "secrets": secrets_json })))
}

/// GET /api/allowlist — List authorized executables
pub async fn handle_api_allowlist(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let entries = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            db.list_allow_list().unwrap_or_default()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let entries_json: Vec<serde_json::Value> = entries
        .iter()
        .map(|(path, hash, name)| {
            serde_json::json!({
                "exe_path": path,
                "exe_hash": hash,
                "friendly_name": name,
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "allowlist": entries_json })))
}

// ── New Interactive Handlers ───────────────────────────────────

/// POST /api/secrets/seal — Seal a new API key
pub async fn handle_seal_secret(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<SealRequest>,
) -> impl IntoResponse {
    if req.provider.is_empty() || req.key.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Provider and key are required"})));
    }

    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            match secrets::seal_key(&db, &req.provider, &req.secret_type, req.label.as_deref(), &req.key) {
                Ok(()) => {
                    return (StatusCode::OK, Json(serde_json::json!({"status": "sealed", "provider": req.provider})));
                }
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Seal failed: {}", e)})));
                }
            }
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"})))
}

/// DELETE /api/secrets/:provider — Delete a sealed key
pub async fn handle_delete_secret(
    State(state): State<Arc<ProxyState>>,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            match db.delete_secret(&provider) {
                Ok(()) => {
                    return (StatusCode::OK, Json(serde_json::json!({"status": "deleted", "provider": provider})));
                }
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)})));
                }
            }
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"})))
}

/// POST /api/allowlist/add — Add an executable to the allow list
pub async fn handle_add_allowlist(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<AllowlistRequest>,
) -> impl IntoResponse {
    if req.exe_path.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "exe_path is required"})));
    }

    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            match secrets::allow_process(&db, &req.exe_path) {
                Ok(()) => {
                    return (StatusCode::OK, Json(serde_json::json!({"status": "allowed", "exe_path": req.exe_path})));
                }
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)})));
                }
            }
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"})))
}

/// DELETE /api/allowlist/:exe_hash — Remove from allow list
pub async fn handle_remove_allowlist(
    State(state): State<Arc<ProxyState>>,
    Path(exe_hash): Path<String>,
) -> impl IntoResponse {
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            match db.remove_from_allow_list(&exe_hash) {
                Ok(()) => {
                    return (StatusCode::OK, Json(serde_json::json!({"status": "removed"})));
                }
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)})));
                }
            }
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"})))
}

/// GET /api/agents — Scan for AI-related processes
pub async fn handle_api_agents(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let results = scanner::scan_for_ai();

    let agents_json: Vec<serde_json::Value> = results
        .iter()
        .map(|p| {
            // Look up trust score from agent registry
            let trust_score = if let Some(ref db_mutex) = state.db {
                if let Ok(db) = db_mutex.lock() {
                    // Use the exe binary name as a crude hash for lookup
                    let hash = format!("name-{}", p.friendly_name.to_lowercase().replace(' ', "-"));
                    crate::agent_registry::get_trust_score(&db, &hash)
                } else {
                    crate::trust_score::INITIAL_TRUST
                }
            } else {
                crate::trust_score::INITIAL_TRUST
            };
            let trust_label = crate::trust_score::score_label(trust_score);

            serde_json::json!({
                "pid": p.pid,
                "name": p.name,
                "friendly_name": p.friendly_name,
                "exe_path": "",
                "risk_level": p.risk_level,
                "risk_reason": p.risk_reason,
                "memory_mb": p.memory_usage / (1024 * 1024),
                "cmd": p.cmd.join(" "),
                "process_count": p.process_count,
                "child_pids": p.child_pids,
                "trust_score": trust_score,
                "trust_label": trust_label.as_str(),
                "trust_color": trust_label.color(),
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({ "agents": agents_json })))
}

/// GET /api/discovery — Full Shadow AI Discovery scan
pub async fn handle_api_discovery(
    State(_state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let assets = crate::discovery::run_full_scan();
    (StatusCode::OK, Json(serde_json::json!({ "assets": assets })))
}

/// POST /api/panic — Emergency kill processes
pub async fn handle_panic(
    State(state): State<Arc<ProxyState>>,
    Json(req): Json<PanicRequest>,
) -> impl IntoResponse {
    let mut killed = vec![];
    let mut failed = vec![];

    for pid in &req.pids {
        if *pid < 100 {
            failed.push(serde_json::json!({"pid": pid, "error": "System process — cannot kill"}));
            continue;
        }
        let result = crate::killer::kill_process_tree(*pid);
        if result.success {
            killed.push(*pid);
        } else {
            failed.push(serde_json::json!({"pid": pid, "error": result.error.unwrap_or_default()}));
        }
    }

    // Log to audit ledger
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let event = crate::database::Event {
                event_type: "PANIC_DASHBOARD".to_string(),
                details_json: serde_json::json!({"killed": killed, "failed": failed}).to_string(),
                severity: crate::database::Severity::Critical,
            };
            let _ = db.log_event(&event);
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"killed": killed, "failed": failed})))
}

/// GET /api/config — Read current config
pub async fn handle_get_config(
    State(_state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let config = RaypherConfig::load();
    (StatusCode::OK, Json(serde_json::json!({
        "proxy": {
            "listen_addr": config.proxy.listen_addr,
            "listen_port": config.proxy.listen_port,
            "upstream": config.proxy.default_upstream,
            "rate_limit": config.proxy.rate_limit,
        },
        "watchtower": {
            "scan_interval": config.watchtower.scan_interval_secs,
            "alert_threshold": config.watchtower.alert_threshold,
        },
        "updater": {
            "enabled": config.updater.enabled,
            "check_interval": config.updater.check_interval_hours,
        },
        "logging": {
            "log_level": config.logging.level,
            "log_dir": config.logging.log_dir,
            "retention": config.logging.retention_days,
        }
    })))
}

/// POST /api/config/update — Update config
pub async fn handle_update_config(
    State(_state): State<Arc<ProxyState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Load current config, merge updates, and save
    let mut config = RaypherConfig::load();

    if let Some(proxy) = body.get("proxy") {
        if let Some(v) = proxy.get("rate_limit").and_then(|v| v.as_u64()) {
            config.proxy.rate_limit = v as u32;
        }
        if let Some(v) = proxy.get("upstream").and_then(|v| v.as_str()) {
            config.proxy.default_upstream = v.to_string();
        }
    }
    if let Some(wt) = body.get("watchtower") {
        if let Some(v) = wt.get("scan_interval").and_then(|v| v.as_u64()) {
            config.watchtower.scan_interval_secs = v;
        }
        if let Some(v) = wt.get("alert_threshold").and_then(|v| v.as_str()) {
            config.watchtower.alert_threshold = v.to_string();
        }
    }
    if let Some(log) = body.get("logging") {
        if let Some(v) = log.get("log_level").and_then(|v| v.as_str()) {
            config.logging.level = v.to_string();
        }
        if let Some(v) = log.get("retention").and_then(|v| v.as_u64()) {
            config.logging.retention_days = v as u32;
        }
    }

    // Save config to file
    let config_path = RaypherConfig::config_path();
    let config_toml = toml::to_string(&config).unwrap_or_default();
    match std::fs::write(&config_path, config_toml) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "saved"}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))),
    }
}

/// GET /api/config/policy — Get guardrails policy
pub async fn handle_get_policy(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let policy_config = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            policy::load_policy(&db)
        } else {
            policy::PolicyConfig::default()
        }
    } else {
        policy::PolicyConfig::default()
    };

    (StatusCode::OK, Json(serde_json::json!(policy_config)))
}

/// POST /api/config/policy/update — Update guardrails policy
pub async fn handle_update_policy(
    State(state): State<Arc<ProxyState>>,
    Json(policy_config): Json<policy::PolicyConfig>,
) -> impl IntoResponse {
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            match policy::save_policy(&db, &policy_config) {
                Ok(()) => {
                    return (StatusCode::OK, Json(serde_json::json!({"status": "saved"})));
                }
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e})));
                }
            }
        }
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"})))
}

/// GET /api/stats/spend — Daily spend stats with breakdowns
pub async fn handle_spend_stats(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            let daily_spend = db.get_daily_spend().unwrap_or(0.0);
            let policy_config = policy::load_policy(&db);
            let budget_limit = policy_config.daily_budget_limit;

            let hourly: Vec<serde_json::Value> = db.get_hourly_spend().unwrap_or_default()
                .iter().map(|(h, c)| serde_json::json!({"hour": h, "cost": c})).collect();
            let daily: Vec<serde_json::Value> = db.get_weekly_spend().unwrap_or_default()
                .iter().map(|(d, c)| serde_json::json!({"day": d, "cost": c})).collect();
            let providers: Vec<serde_json::Value> = db.get_provider_spend().unwrap_or_default()
                .iter().map(|(p, c)| serde_json::json!({"provider": p, "cost": c})).collect();

            return (StatusCode::OK, Json(serde_json::json!({
                "daily_spend": daily_spend,
                "budget_limit": budget_limit,
                "percentage": if budget_limit > 0.0 { (daily_spend / budget_limit * 100.0).min(100.0) } else { 0.0 },
                "hourly_breakdown": hourly,
                "daily_breakdown": daily,
                "provider_breakdown": providers,
            })));
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "daily_spend": 0.0,
        "budget_limit": 50.0,
        "percentage": 0.0,
        "hourly_breakdown": [],
        "daily_breakdown": [],
        "provider_breakdown": [],
    })))
}

/// GET /api/stats/threats — Threat/event stats
pub async fn handle_threat_stats(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let (by_severity, by_type) = if let Some(ref db_mutex) = state.db {
        if let Ok(db) = db_mutex.lock() {
            (
                db.get_threat_counts().unwrap_or_default(),
                db.get_events_by_type().unwrap_or_default(),
            )
        } else {
            (vec![], vec![])
        }
    } else {
        (vec![], vec![])
    };

    let severity_json: Vec<serde_json::Value> = by_severity.iter()
        .map(|(s, c)| serde_json::json!({"severity": s, "count": c}))
        .collect();

    let type_json: Vec<serde_json::Value> = by_type.iter()
        .map(|(t, c)| serde_json::json!({"event_type": t, "count": c}))
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "by_severity": severity_json,
        "by_type": type_json,
    })))
}

// ── DLP Panel Handlers ────────────────────────────────────────

/// GET /api/dlp/stats — DLP detection stats by category
pub async fn handle_dlp_stats(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };

    let db = db_lock.lock().unwrap();

    let stats = db.get_dlp_stats().unwrap_or_default();
    let total: i64 = stats.iter().map(|(_, c)| c).sum();

    let categories: Vec<serde_json::Value> = stats.into_iter().map(|(cat, count)| {
        serde_json::json!({"category": cat, "count": count})
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "total_findings": total,
        "by_category": categories,
    })))
}

/// GET /api/dlp/findings — Recent DLP findings feed
pub async fn handle_dlp_findings(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<EventsQuery>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };

    let db = db_lock.lock().unwrap();
    let limit = params.limit.unwrap_or(50).min(200) as usize;

    let findings = db.get_recent_dlp_findings(limit).unwrap_or_default();
    let items: Vec<serde_json::Value> = findings.into_iter().map(|(ts, dir, cat, pattern, action, snippet, provider)| {
        serde_json::json!({
            "timestamp": ts,
            "direction": dir,
            "category": cat,
            "pattern_name": pattern,
            "action_taken": action,
            "snippet": snippet,
            "provider": provider,
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "count": items.len(),
        "findings": items,
    })))
}

/// GET /api/dlp/config — DLP configuration (from policy)
pub async fn handle_dlp_config(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };

    let db = db_lock.lock().unwrap();
    let policy = policy::load_policy(&db);

    // Return DLP config including custom patterns
    (StatusCode::OK, Json(serde_json::json!({
        "dlp_action": "redact",
        "enabled_categories": ["api_keys", "financial", "pii", "crypto_material"],
        "built_in_patterns": 11,
        "entropy_detection": true,
        "entropy_threshold": 4.5,
        "custom_patterns": policy.phase4.custom_dlp_patterns,
    })))
}

/// GET /api/dlp/patterns — List all custom DLP patterns
pub async fn handle_get_dlp_patterns(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };
    let db = db_lock.lock().unwrap();
    let policy = policy::load_policy(&db);
    (StatusCode::OK, Json(serde_json::json!({
        "patterns": policy.phase4.custom_dlp_patterns
    })))
}

/// POST /api/dlp/patterns — Add a custom DLP pattern
pub async fn handle_add_dlp_pattern(
    State(state): State<Arc<ProxyState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };

    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "name is required"}))),
    };
    let pattern_str = match body.get("pattern").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "pattern is required"}))),
    };
    let severity_str = body.get("severity").and_then(|v| v.as_str()).unwrap_or("Medium");
    let severity = match severity_str.to_lowercase().as_str() {
        "critical" => crate::dlp::DlpSeverity::Critical,
        "high"     => crate::dlp::DlpSeverity::High,
        "low"      => crate::dlp::DlpSeverity::Low,
        _          => crate::dlp::DlpSeverity::Medium,
    };
    let redact_to = body.get("redact_to").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Validate regex compiles
    if let Err(e) = regex::Regex::new(&pattern_str) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("Invalid regex: {}", e)
        })));
    }

    let new_pattern = crate::dlp::CustomPattern {
        name: name.clone(),
        pattern: pattern_str,
        severity,
        redact_to,
    };

    let db = db_lock.lock().unwrap();
    let mut policy_config = policy::load_policy(&db);

    // Remove existing pattern with same name if present
    policy_config.phase4.custom_dlp_patterns.retain(|p| p.name != name);
    policy_config.phase4.custom_dlp_patterns.push(new_pattern);

    match policy::save_policy(&db, &policy_config) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "added", "name": name}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))),
    }
}

/// DELETE /api/dlp/patterns/:name — Remove a custom DLP pattern by name
pub async fn handle_delete_dlp_pattern(
    State(state): State<Arc<ProxyState>>,
    Path(pattern_name): Path<String>,
) -> impl IntoResponse {
    let db_lock = match &state.db {
        Some(db) => db,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Database unavailable"}))),
    };
    let db = db_lock.lock().unwrap();
    let mut policy_config = policy::load_policy(&db);
    let before = policy_config.phase4.custom_dlp_patterns.len();
    policy_config.phase4.custom_dlp_patterns.retain(|p| p.name != pattern_name);
    let removed = before - policy_config.phase4.custom_dlp_patterns.len();
    match policy::save_policy(&db, &policy_config) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ok", "removed": removed}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))),
    }
}

/// GET /api/merkle/status — Merkle-chained ledger integrity status
pub async fn handle_api_merkle_status(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    use crate::merkle;

    let policy = state.policy.get();
    let ledger_path = policy.phase4.merkle_ledger_path.clone();

    if !std::path::Path::new(&ledger_path).exists() {
        return (StatusCode::OK, Json(serde_json::json!({
            "status": "empty",
            "entry_count": 0,
            "valid": true,
            "message": "Ledger file not yet created. Events will be recorded when the proxy handles requests.",
            "last_entries": [],
        })));
    }

    let content = match std::fs::read_to_string(&ledger_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Failed to read ledger: {}", e)
        }))),
    };

    let entries: Vec<merkle::MerkleEntry> = content
        .lines()
        .filter_map(merkle::entry_from_ndjson)
        .collect();

    let entry_count = entries.len();
    let (valid, error_msg) = match merkle::verify_chain(&entries) {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.to_string())),
    };

    // Return the last 10 entries for display
    let last_entries: Vec<serde_json::Value> = entries.iter().rev().take(10).map(|e| {
        let details_val: serde_json::Value = serde_json::from_str(&e.details)
            .unwrap_or_else(|_| serde_json::json!({}));
        let description = crate::event_descriptions::describe_event(&e.event, &details_val);
        let formatted_time = crate::event_descriptions::format_unix_timestamp(e.timestamp);
        serde_json::json!({
            "seq": e.seq,
            "event": e.event,
            "description": description,
            "details": e.details,
            "timestamp": e.timestamp,
            "formatted_time": formatted_time,
            "hash_short": &e.own_hash[..8],
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "status": if valid { "verified" } else { "corrupt" },
        "entry_count": entry_count,
        "valid": valid,
        "ledger_path": ledger_path,
        "error": error_msg,
        "last_entries": last_entries,
    })))
}

// ── The Dashboard SPA ──────────────────────────────────────────
// The entire dashboard UI is embedded as a single const string.
// This is served at GET /dashboard.

const DASHBOARD_HTML: &str = include_str!("dashboard_spa.html");

