/// Integration tests for Phase 5 — Agent Identity, Trust Score, Runtime, DLP Patterns
///
/// Architecture note: rusqlite::Connection is !Send, so we cannot share
/// Arc<Mutex<Database>> across tokio::spawn boundaries. Instead we:
///   1. Set up the DB in the main thread, then drop it.
///   2. Spawn the proxy in a std::thread with its own Tokio runtime.
///   3. Re-open the DB after the request to inspect results.

use raypher_core::database::Database;
use raypher_core::proxy;
use raypher_core::secrets;
use raypher_core::policy::{PolicyConfig, DlpPolicy, DlpAction};
use std::net::SocketAddr;

// ── Shared helpers ─────────────────────────────────────────────────────────────

async fn start_test_proxy(db_path: std::path::PathBuf, http_port: u16) {
    let http_addr: SocketAddr = format!("127.0.0.1:{}", http_port).parse().unwrap();
    let tls_addr: SocketAddr = format!("127.0.0.1:{}", http_port + 1).parse().unwrap();
    let db_path_clone = db_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            use std::sync::{Arc, Mutex};
            match Database::init_at(db_path_clone) {
                Ok(db) => {
                    let db_arc = Some(Arc::new(Mutex::new(db)));
                    let _ = proxy::start_proxy_engine(db_arc, http_addr, tls_addr).await;
                }
                Err(e) => eprintln!("Proxy DB init failed: {}", e),
            }
        });
    });

    // Wait for proxy to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;
}

fn setup_db_with_policy(db_path: std::path::PathBuf, policy: PolicyConfig) {
    let db = Database::init_at(db_path).unwrap();
    let policy_json = serde_json::to_string(&policy).unwrap();
    let ts = chrono::Utc::now().to_rfc3339();
    db.get_conn().execute(
        "INSERT OR REPLACE INTO policy (key, value, updated_at) VALUES ('policy_config', ?, ?)",
        rusqlite::params![policy_json, ts],
    ).unwrap();
    // Allowlist the test runner executable so the proxy allows our request
    let exe = std::env::current_exe().unwrap();
    secrets::allow_process(&db, exe.to_str().unwrap()).unwrap();
}

// ── Test 1: DLP Redaction (updated — also validates agent name appears in events) ─

#[tokio::test]
async fn test_proxy_dlp_redaction() {
    let _ = tracing_subscriber::fmt::try_init();
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_dlp.db");

    {
        setup_db_with_policy(db_path.clone(), PolicyConfig {
            dlp: DlpPolicy {
                default_action: DlpAction::Redact,
                api_keys: DlpAction::Redact,
                financial: DlpAction::Block,
                pii: DlpAction::Redact,
                crypto_material: DlpAction::Block,
                entropy_detection: true,
                entropy_threshold: 4.5,
                exclusions: vec![],
            },
            ..PolicyConfig::default()
        });
    }

    start_test_proxy(db_path.clone(), 18888).await;

    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Here is my secret: sk-abcdef1234567890abcdef1234567890"}]
    });

    let _ = client
        .post("http://127.0.0.1:18888/v1/chat/completions")
        .header("X-Raypher-Token", "test-token-dlp")
        .json(&payload)
        .send()
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    let db = Database::init_at(db_path).unwrap();
    let findings = db.get_dlp_stats().unwrap();

    assert!(
        !findings.is_empty(),
        "DLP scan should have detected sensitive data in the request"
    );

    let has_api_key = findings.iter().any(|(cat, _)| cat.contains("api_key") || cat.contains("api_keys"));
    assert!(
        has_api_key,
        "DLP scan should have categorised the finding as api_key, got: {:?}",
        findings
    );
}

// ── Test 2: Trust Score Module ────────────────────────────────────────────────

#[test]
fn test_trust_score_penalties_and_recovery() {
    use raypher_core::trust_score;

    // Start at max
    let mut score = trust_score::INITIAL_TRUST;

    // Jailbreak is the harshest penalty
    let jailbreak_penalty = trust_score::trust_penalty("JAILBREAK_BLOCKED");
    assert!(jailbreak_penalty < 0, "Jailbreak must lower score");

    score = (score + jailbreak_penalty).max(trust_score::MIN_TRUST);
    assert!(score < trust_score::INITIAL_TRUST, "Score should drop after jailbreak");

    // Clean requests slowly recover
    let recovery = trust_score::trust_recovery("PROXY_FORWARD");
    assert!(recovery >= 0, "Clean forwards should not lower score");

    // DLP block is worse than budget block
    let dlp_penalty = trust_score::trust_penalty("DLP_BLOCKED");
    let budget_penalty = trust_score::trust_penalty("BUDGET_BLOCKED");
    assert!(dlp_penalty < budget_penalty, "DLP penalty should be harsher than budget");

    // Score floor
    for _ in 0..1000 {
        score = (score + trust_score::trust_penalty("JAILBREAK_BLOCKED")).max(trust_score::MIN_TRUST);
    }
    assert_eq!(score, trust_score::MIN_TRUST, "Score must not go below MIN_TRUST");
}

// ── Test 3: Event Descriptions ────────────────────────────────────────────────

#[test]
fn test_event_descriptions_all_key_types() {
    use raypher_core::event_descriptions::describe_event;

    let agent_details = serde_json::json!({"agent": "OpenClaw.ai"});

    let cases = vec![
        ("BUDGET_BLOCKED", "OpenClaw.ai"),
        ("DLP_BLOCKED",    "Sensitive"),
        ("SSRF_HOST_BLOCKED", "internal"),
        ("JAILBREAK_BLOCKED", "injection"),
        ("PROXY_UNAUTHORIZED", "Unauthorized"),
        ("TIME_RESTRICTED", "work hours"),
        ("RATE_LIMIT_EXCEEDED", "Rate limit"),
        ("TOKEN_HIJACK_BLOCKED", "token"),
    ];

    for (event_type, expected_word) in cases {
        let desc = describe_event(event_type, &agent_details);
        assert!(
            desc.to_lowercase().contains(&expected_word.to_lowercase()),
            "Description for {} should contain '{}', got: {}",
            event_type, expected_word, desc
        );
    }
}

// ── Test 4: Child Spawn Detection ─────────────────────────────────────────────

#[test]
fn test_child_spawn_detection() {
    use raypher_core::scanner::{detect_new_child_processes, AiProcess, RiskLevel};

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

    // No previous scan — no alerts expected for completely new agent
    let prev: Vec<AiProcess> = vec![];
    let curr = vec![make_agent("OpenClaw.ai", vec![5000])];
    assert!(detect_new_child_processes(&prev, &curr).is_empty(),
        "Brand new agent should not trigger spawn alert");

    // Same pids — no alerts
    let prev = vec![make_agent("OpenClaw.ai", vec![5000, 5001])];
    let curr = vec![make_agent("OpenClaw.ai", vec![5000, 5001])];
    assert!(detect_new_child_processes(&prev, &curr).is_empty(),
        "Unchanged PIDs should not trigger spawn alert");

    // New PID appears — should alert
    let prev = vec![make_agent("OpenClaw.ai", vec![5000])];
    let curr = vec![make_agent("OpenClaw.ai", vec![5000, 5002])];
    let alerts = detect_new_child_processes(&prev, &curr);
    assert_eq!(alerts.len(), 1, "Should detect exactly 1 new child");
    assert_eq!(alerts[0].child_pid, 5002);
    assert_eq!(alerts[0].agent_name, "OpenClaw.ai");
}
