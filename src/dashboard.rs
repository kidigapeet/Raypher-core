// ──────────────────────────────────────────────────────────────
//  Raypher — Status Dashboard (Phase 2.5)
//  Lightweight web dashboard served from the existing proxy.
//  Queries SQLite for live data, auto-refreshes every 5 seconds.
// ──────────────────────────────────────────────────────────────

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    http::StatusCode,
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::database::Database;
use crate::proxy::ProxyState;

// ── Query Parameters ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct EventsQuery {
    pub limit: Option<u32>,
}

// ── Route Handlers ─────────────────────────────────────────────

/// GET /dashboard — Serves the full HTML dashboard page
pub async fn handle_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// GET /api/status — Service health, version, uptime, counts
pub async fn handle_api_status(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let uptime_secs = state.start_time.elapsed().as_secs();

    let (event_count, secret_count, allow_count, fingerprint) = match &state.db {
        Some(db_mutex) => {
            let db = db_mutex.lock().unwrap();
            let events = db.event_count().unwrap_or(0);
            let secrets = db.list_secrets().map(|s| s.len() as i64).unwrap_or(0);
            let allowed = db.list_allow_list().map(|a| a.len() as i64).unwrap_or(0);

            // Try to get the machine fingerprint from machine_info table
            let fp = db.get_fingerprint().unwrap_or_else(|_| "Not registered".to_string());

            (events, secrets, allowed, fp)
        }
        None => (0, 0, 0, "Database unavailable".to_string()),
    };

    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "uptime_seconds": uptime_secs,
        "uptime_display": format_uptime(uptime_secs),
        "total_events": event_count,
        "sealed_secrets": secret_count,
        "allowed_apps": allow_count,
        "fingerprint": fingerprint,
    });

    (StatusCode::OK, axum::Json(body))
}

/// GET /api/events?limit=50 — Recent audit events
pub async fn handle_api_events(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<EventsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200);

    let events = match &state.db {
        Some(db_mutex) => {
            let db = db_mutex.lock().unwrap();
            match db.recent_events(limit) {
                Ok(rows) => rows
                    .into_iter()
                    .map(|(id, ts, event_type, details, severity)| {
                        serde_json::json!({
                            "id": id,
                            "timestamp": ts,
                            "event_type": event_type,
                            "details": details,
                            "severity": severity,
                        })
                    })
                    .collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    (StatusCode::OK, axum::Json(serde_json::json!(events)))
}

/// GET /api/secrets — List sealed providers (names + dates only, never key data)
pub async fn handle_api_secrets(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let secrets = match &state.db {
        Some(db_mutex) => {
            let db = db_mutex.lock().unwrap();
            match db.list_secrets() {
                Ok(rows) => rows
                    .into_iter()
                    .map(|(provider, created)| {
                        serde_json::json!({
                            "provider": provider,
                            "created_at": created,
                        })
                    })
                    .collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    (StatusCode::OK, axum::Json(serde_json::json!(secrets)))
}

/// GET /api/allowlist — Authorized executables
pub async fn handle_api_allowlist(
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    let allowed = match &state.db {
        Some(db_mutex) => {
            let db = db_mutex.lock().unwrap();
            match db.list_allow_list() {
                Ok(rows) => rows
                    .into_iter()
                    .map(|(path, hash, name)| {
                        serde_json::json!({
                            "exe_path": path,
                            "exe_hash": hash,
                            "friendly_name": name,
                        })
                    })
                    .collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    (StatusCode::OK, axum::Json(serde_json::json!(allowed)))
}

// ── Helpers ────────────────────────────────────────────────────

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

// ── Embedded Dashboard HTML ────────────────────────────────────

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Raypher — Status Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        /* ── Reset & Base ────────────────────────── */
        *, *::before, *::after {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #060a13;
            --bg-secondary: #0c1220;
            --bg-card: rgba(15, 23, 42, 0.6);
            --bg-card-hover: rgba(20, 30, 55, 0.7);
            --border: rgba(56, 97, 251, 0.15);
            --border-hover: rgba(56, 97, 251, 0.35);
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --accent-purple: #8b5cf6;
            --glow-blue: rgba(59, 130, 246, 0.15);
            --glow-green: rgba(16, 185, 129, 0.15);
            --glow-amber: rgba(245, 158, 11, 0.15);
            --glow-red: rgba(239, 68, 68, 0.15);
            --radius: 16px;
            --radius-sm: 10px;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ── Animated Background ─────────────────── */
        body::before {
            content: '';
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(ellipse at 20% 50%, rgba(59, 130, 246, 0.06) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 20%, rgba(139, 92, 246, 0.04) 0%, transparent 50%),
                        radial-gradient(ellipse at 50% 80%, rgba(6, 182, 212, 0.03) 0%, transparent 50%);
            animation: bgShift 20s ease-in-out infinite alternate;
            z-index: 0;
        }

        @keyframes bgShift {
            0% { transform: translate(0, 0); }
            100% { transform: translate(-5%, -3%); }
        }

        /* ── Layout ──────────────────────────────── */
        .container {
            position: relative;
            z-index: 1;
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 32px;
        }

        /* ── Header ──────────────────────────────── */
        .header {
            text-align: center;
            margin-bottom: 48px;
        }

        .header-brand {
            display: inline-flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 12px;
        }

        .header-logo {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: 800;
            color: white;
            box-shadow: 0 4px 24px rgba(59, 130, 246, 0.3);
        }

        .header h1 {
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            background: linear-gradient(135deg, #e2e8f0, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-sub {
            font-size: 0.95rem;
            color: var(--text-secondary);
            margin-top: 6px;
        }

        .header-badges {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 16px;
            flex-wrap: wrap;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 14px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 100px;
            font-size: 0.78rem;
            font-weight: 500;
            color: var(--text-secondary);
            backdrop-filter: blur(12px);
        }

        .badge .dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }

        .dot-green { background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }
        .dot-blue { background: var(--accent-blue); }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* ── Stats Grid ──────────────────────────── */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 28px 24px;
            backdrop-filter: blur(20px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            border-radius: var(--radius) var(--radius) 0 0;
        }

        .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan)); }
        .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--accent-green), #34d399); }
        .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent-purple), #a78bfa); }
        .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue)); }

        .stat-card:hover {
            background: var(--bg-card-hover);
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .stat-icon {
            font-size: 1.6rem;
            margin-bottom: 14px;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            line-height: 1;
            margin-bottom: 6px;
            font-family: 'JetBrains Mono', monospace;
        }

        .stat-label {
            font-size: 0.82rem;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        /* ── Panel Grid ──────────────────────────── */
        .panels-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 32px;
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            backdrop-filter: blur(20px);
            overflow: hidden;
            transition: border-color 0.3s;
        }

        .panel:hover {
            border-color: var(--border-hover);
        }

        .panel-full {
            grid-column: 1 / -1;
        }

        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 24px 16px;
            border-bottom: 1px solid var(--border);
        }

        .panel-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.95rem;
            font-weight: 600;
        }

        .panel-count {
            font-size: 0.75rem;
            font-weight: 500;
            color: var(--text-muted);
            background: rgba(100, 116, 139, 0.15);
            padding: 3px 10px;
            border-radius: 100px;
        }

        .panel-body {
            padding: 0;
            max-height: 420px;
            overflow-y: auto;
        }

        .panel-body::-webkit-scrollbar {
            width: 6px;
        }

        .panel-body::-webkit-scrollbar-track {
            background: transparent;
        }

        .panel-body::-webkit-scrollbar-thumb {
            background: rgba(100, 116, 139, 0.3);
            border-radius: 3px;
        }

        /* ── Event Rows ──────────────────────────── */
        .event-row {
            display: grid;
            grid-template-columns: 100px 160px 1fr 80px;
            gap: 16px;
            padding: 14px 24px;
            border-bottom: 1px solid rgba(56, 97, 251, 0.06);
            font-size: 0.83rem;
            align-items: center;
            transition: background 0.2s;
        }

        .event-row:hover {
            background: rgba(59, 130, 246, 0.04);
        }

        .event-row:last-child {
            border-bottom: none;
        }

        .event-id {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: var(--text-muted);
        }

        .event-type {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            font-size: 0.78rem;
            color: var(--accent-cyan);
        }

        .event-details {
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 0.8rem;
        }

        .severity-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 3px 10px;
            border-radius: 100px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .severity-info {
            background: var(--glow-blue);
            color: var(--accent-blue);
        }

        .severity-warning {
            background: var(--glow-amber);
            color: var(--accent-amber);
        }

        .severity-critical {
            background: var(--glow-red);
            color: var(--accent-red);
        }

        /* ── List Items (secrets, allowlist) ──────── */
        .list-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 24px;
            border-bottom: 1px solid rgba(56, 97, 251, 0.06);
            transition: background 0.2s;
        }

        .list-item:hover {
            background: rgba(59, 130, 246, 0.04);
        }

        .list-item:last-child {
            border-bottom: none;
        }

        .list-item-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .list-item-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }

        .icon-secret {
            background: var(--glow-green);
        }

        .icon-app {
            background: var(--glow-blue);
        }

        .list-item-name {
            font-weight: 600;
            font-size: 0.9rem;
        }

        .list-item-meta {
            font-size: 0.78rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            margin-top: 2px;
        }

        .list-item-right {
            font-size: 0.78rem;
            color: var(--text-muted);
            text-align: right;
        }

        /* ── Fingerprint Bar ─────────────────────── */
        .fingerprint-bar {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px 24px;
            margin-bottom: 32px;
            backdrop-filter: blur(20px);
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .fp-label {
            font-size: 0.82rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }

        .fp-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            color: var(--accent-cyan);
            word-break: break-all;
            flex: 1;
        }

        /* ── Empty State ─────────────────────────── */
        .empty-state {
            padding: 40px 24px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .empty-state-icon {
            font-size: 2rem;
            margin-bottom: 8px;
            opacity: 0.5;
        }

        /* ── Footer ──────────────────────────────── */
        .footer {
            text-align: center;
            padding: 24px 0;
            color: var(--text-muted);
            font-size: 0.78rem;
        }

        .footer-live {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        /* ── Responsive ──────────────────────────── */
        @media (max-width: 1100px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 24px 16px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .panels-grid {
                grid-template-columns: 1fr;
            }

            .event-row {
                grid-template-columns: 1fr;
                gap: 4px;
            }

            .fingerprint-bar {
                flex-direction: column;
                align-items: flex-start;
            }
        }

        /* ── Loading shimmer ─────────────────────── */
        @keyframes shimmer {
            0% { opacity: 0.5; }
            50% { opacity: 1; }
            100% { opacity: 0.5; }
        }

        .loading {
            animation: shimmer 1.5s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-brand">
                <div class="header-logo">R</div>
                <h1>RAYPHER</h1>
            </div>
            <p class="header-sub">Status Dashboard — Phase 2.5</p>
            <div class="header-badges">
                <span class="badge"><span class="dot dot-green"></span> Service Running</span>
                <span class="badge" id="badge-version"><span class="dot dot-blue"></span> v—</span>
                <span class="badge" id="badge-uptime">⏱ —</span>
            </div>
        </header>

        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📋</div>
                <div class="stat-value" id="stat-events">—</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🔐</div>
                <div class="stat-value" id="stat-secrets">—</div>
                <div class="stat-label">Sealed Secrets</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">✅</div>
                <div class="stat-value" id="stat-apps">—</div>
                <div class="stat-label">Allowed Apps</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⏱</div>
                <div class="stat-value" id="stat-uptime">—</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>

        <!-- Fingerprint Bar -->
        <div class="fingerprint-bar">
            <span class="fp-label">🧬 TPM Fingerprint</span>
            <span class="fp-value" id="fingerprint">Loading...</span>
        </div>

        <!-- Panels -->
        <div class="panels-grid">
            <!-- Audit Log (full width) -->
            <div class="panel panel-full">
                <div class="panel-header">
                    <span class="panel-title">📋 Audit Log</span>
                    <span class="panel-count" id="log-count">0 events</span>
                </div>
                <div class="panel-body" id="events-body">
                    <div class="empty-state loading">
                        <div class="empty-state-icon">📋</div>
                        Loading events...
                    </div>
                </div>
            </div>

            <!-- Sealed Secrets -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">🔐 Sealed Secrets</span>
                    <span class="panel-count" id="secrets-count">0</span>
                </div>
                <div class="panel-body" id="secrets-body">
                    <div class="empty-state loading">
                        <div class="empty-state-icon">🔐</div>
                        Loading...
                    </div>
                </div>
            </div>

            <!-- Allowed Apps -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">✅ Allowed Apps</span>
                    <span class="panel-count" id="apps-count">0</span>
                </div>
                <div class="panel-body" id="apps-body">
                    <div class="empty-state loading">
                        <div class="empty-state-icon">✅</div>
                        Loading...
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="footer">
            <span class="footer-live">
                <span class="dot dot-green" style="width:6px;height:6px;display:inline-block;border-radius:50%;"></span>
                Auto-refreshing every 5 seconds
            </span>
            &nbsp;·&nbsp; Raypher Labs &nbsp;·&nbsp; Powered by Rust
        </footer>
    </div>

    <script>
        // ── API Fetch Helpers ──────────────────────
        const API_BASE = window.location.origin;

        async function fetchJSON(path) {
            try {
                const res = await fetch(API_BASE + path);
                return await res.json();
            } catch (e) {
                console.error('Fetch error:', path, e);
                return null;
            }
        }

        // ── Render Functions ───────────────────────
        function renderStatus(data) {
            if (!data) return;

            document.getElementById('badge-version').innerHTML =
                '<span class="dot dot-blue"></span> v' + data.version;
            document.getElementById('badge-uptime').textContent = '⏱ ' + data.uptime_display;

            document.getElementById('stat-events').textContent = data.total_events.toLocaleString();
            document.getElementById('stat-secrets').textContent = data.sealed_secrets;
            document.getElementById('stat-apps').textContent = data.allowed_apps;
            document.getElementById('stat-uptime').textContent = data.uptime_display;
            document.getElementById('fingerprint').textContent = data.fingerprint;
        }

        function renderEvents(data) {
            const body = document.getElementById('events-body');
            const count = document.getElementById('log-count');

            if (!data || data.length === 0) {
                body.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📋</div>No events recorded yet.<br>Run a scan or seal a secret to generate events.</div>';
                count.textContent = '0 events';
                return;
            }

            count.textContent = data.length + ' events';

            body.innerHTML = data.map(e => {
                const sevClass = e.severity === 'Critical' ? 'severity-critical'
                    : e.severity === 'Warning' ? 'severity-warning'
                    : 'severity-info';

                // Shorten timestamp
                const ts = e.timestamp || '';
                const shortTs = ts.length > 19 ? ts.substring(0, 19).replace('T', ' ') : ts;

                // Try to extract meaningful detail
                let detail = e.details || '';
                try {
                    const parsed = JSON.parse(detail);
                    detail = Object.entries(parsed)
                        .map(([k, v]) => k + ': ' + (typeof v === 'string' ? v : JSON.stringify(v)))
                        .join(' · ');
                } catch(_) {}

                return '<div class="event-row">' +
                    '<span class="event-id">#' + e.id + ' · ' + shortTs.split(' ')[1] + '</span>' +
                    '<span class="event-type">' + e.event_type + '</span>' +
                    '<span class="event-details" title="' + detail.replace(/"/g, '&quot;') + '">' + detail + '</span>' +
                    '<span class="severity-badge ' + sevClass + '">' + e.severity + '</span>' +
                    '</div>';
            }).join('');
        }

        function renderSecrets(data) {
            const body = document.getElementById('secrets-body');
            const count = document.getElementById('secrets-count');

            if (!data || data.length === 0) {
                body.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔐</div>No secrets sealed yet.<br>Use: raypher seal --provider openai</div>';
                count.textContent = '0';
                return;
            }

            count.textContent = data.length;

            body.innerHTML = data.map(s => {
                const shortDate = (s.created_at || '').substring(0, 10);
                return '<div class="list-item">' +
                    '<div class="list-item-left">' +
                        '<div class="list-item-icon icon-secret">🔑</div>' +
                        '<div>' +
                            '<div class="list-item-name">' + s.provider + '</div>' +
                            '<div class="list-item-meta">TPM-sealed</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="list-item-right">' + shortDate + '</div>' +
                    '</div>';
            }).join('');
        }

        function renderAllowList(data) {
            const body = document.getElementById('apps-body');
            const count = document.getElementById('apps-count');

            if (!data || data.length === 0) {
                body.innerHTML = '<div class="empty-state"><div class="empty-state-icon">✅</div>No apps authorized yet.<br>Use: raypher allow --exe-path /path/to/binary</div>';
                count.textContent = '0';
                return;
            }

            count.textContent = data.length;

            body.innerHTML = data.map(a => {
                const name = a.friendly_name || a.exe_path.split(/[\\/]/).pop();
                const shortHash = a.exe_hash.substring(0, 12) + '...';
                return '<div class="list-item">' +
                    '<div class="list-item-left">' +
                        '<div class="list-item-icon icon-app">📦</div>' +
                        '<div>' +
                            '<div class="list-item-name">' + name + '</div>' +
                            '<div class="list-item-meta">' + shortHash + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="list-item-right" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + a.exe_path + '">' + a.exe_path + '</div>' +
                    '</div>';
            }).join('');
        }

        // ── Refresh Loop ───────────────────────────
        async function refresh() {
            const [status, events, secrets, allowlist] = await Promise.all([
                fetchJSON('/api/status'),
                fetchJSON('/api/events?limit=50'),
                fetchJSON('/api/secrets'),
                fetchJSON('/api/allowlist'),
            ]);

            renderStatus(status);
            renderEvents(events);
            renderSecrets(secrets);
            renderAllowList(allowlist);
        }

        // Initial load + auto-refresh
        refresh();
        setInterval(refresh, 5000);
    </script>
</body>
</html>
"##;
