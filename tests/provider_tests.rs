use raypher_core::database::Database;
use raypher_core::proxy;
use raypher_core::secrets;
use raypher_core::policy::PolicyConfig;
use std::net::SocketAddr;
use std::time::Duration;

async fn start_test_proxy(db_path: std::path::PathBuf, port: u16) {
    let http_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let tls_addr: SocketAddr = format!("127.0.0.1:{}", port + 1).parse().unwrap();
    let db_path_clone = db_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            use std::sync::{Arc, Mutex};
            if let Ok(db) = Database::init_at(db_path_clone) {
                let db_arc = Some(Arc::new(Mutex::new(db)));
                let _ = proxy::start_proxy_engine(db_arc, http_addr, tls_addr).await;
            }
        });
    });

    tokio::time::sleep(Duration::from_millis(1500)).await;
}

#[tokio::test]
async fn test_provider_detection_headers() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_providers.db");
    let port = 38888;

    {
        let db = Database::init_at(db_path.clone()).unwrap();
        let mut policy = PolicyConfig::default();
        policy.allowed_domains = vec![];
        let policy_json = serde_json::to_string(&policy).unwrap();
        db.get_conn().execute(
            "INSERT OR REPLACE INTO policy (key, value, updated_at) VALUES ('policy_config', ?, CURRENT_TIMESTAMP)",
            rusqlite::params![policy_json],
        ).unwrap();
        
        let exe = std::env::current_exe().unwrap();
        secrets::allow_process(&db, exe.to_str().unwrap()).unwrap();
    }

    start_test_proxy(db_path.clone(), port).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/test", port);

    let cases = vec![
        ("x-goog-api-key", "google"),
        ("x-api-key",      "anthropic"),
        ("api-key",        "azure"),
    ];

    for (header, expected_provider) in cases {
        let _ = client.post(&url)
            .header("X-Raypher-Token", "test")
            .header(header, "dummy-key")
            .json(&serde_json::json!({"model": "test"}))
            .send()
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = Database::init_at(db_path.clone()).unwrap();
        let events = db.recent_events(10).unwrap();
        let attempt_event = events.iter().find(|e| e.2 == "PROXY_ATTEMPT").expect("No PROXY_ATTEMPT event found");
        let details: serde_json::Value = serde_json::from_str(&attempt_event.3).unwrap();
        
        assert_eq!(details["provider"], expected_provider, "Header '{}' should detect provider '{}'", header, expected_provider);
    }
}

#[tokio::test]
async fn test_provider_detection_host() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_host.db");
    let port = 39888;

    {
        let db = Database::init_at(db_path.clone()).unwrap();
        let mut policy = PolicyConfig::default();
        policy.allowed_domains = vec![];
        let policy_json = serde_json::to_string(&policy).unwrap();
        db.get_conn().execute(
            "INSERT OR REPLACE INTO policy (key, value, updated_at) VALUES ('policy_config', ?, CURRENT_TIMESTAMP)",
            rusqlite::params![policy_json],
        ).unwrap();
        
        let exe = std::env::current_exe().unwrap();
        secrets::allow_process(&db, exe.to_str().unwrap()).unwrap();
    }

    start_test_proxy(db_path.clone(), port).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/test", port);

    let cases = vec![
        ("api.mistral.ai",   "mistral"),
        ("api.groq.com",     "groq"),
        ("api.cohere.ai",    "cohere"),
        ("api.deepseek.com", "deepseek"),
    ];

    for (host, expected_provider) in cases {
        let _ = client.post(&url)
            .header("X-Raypher-Token", "test")
            .header("X-Original-Host", host)
            .json(&serde_json::json!({"model": "test"}))
            .send()
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = Database::init_at(db_path.clone()).unwrap();
        let events = db.recent_events(10).unwrap();
        let attempt_event = events.iter().find(|e| e.2 == "PROXY_ATTEMPT").expect("No PROXY_ATTEMPT event found");
        let details: serde_json::Value = serde_json::from_str(&attempt_event.3).unwrap();
        
        assert_eq!(details["provider"], expected_provider, "Host '{}' should detect provider '{}'", host, expected_provider);
    }
}

#[tokio::test]
async fn test_provider_detection_model() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_model.db");
    let port = 37888;

    {
        let db = Database::init_at(db_path.clone()).unwrap();
        let mut policy = PolicyConfig::default();
        policy.allowed_domains = vec![];
        let policy_json = serde_json::to_string(&policy).unwrap();
        db.get_conn().execute(
            "INSERT OR REPLACE INTO policy (key, value, updated_at) VALUES ('policy_config', ?, CURRENT_TIMESTAMP)",
            rusqlite::params![policy_json],
        ).unwrap();
        
        let exe = std::env::current_exe().unwrap();
        secrets::allow_process(&db, exe.to_str().unwrap()).unwrap();
    }

    start_test_proxy(db_path.clone(), port).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/test", port);

    let cases = vec![
        ("claude-3-opus", "anthropic"),
        ("gemini-1.5-pro", "google"),
        ("mistral-large", "mistral"),
    ];

    for (model, expected_provider) in cases {
        let _ = client.post(&url)
            .header("X-Raypher-Token", "test")
            .json(&serde_json::json!({"model": model}))
            .send()
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = Database::init_at(db_path.clone()).unwrap();
        let events = db.recent_events(10).unwrap();
        let attempt_event = events.iter().find(|e| e.2 == "PROXY_ATTEMPT").expect("No PROXY_ATTEMPT event found");
        let details: serde_json::Value = serde_json::from_str(&attempt_event.3).unwrap();
        
        assert_eq!(details["provider"], expected_provider, "Model '{}' should detect provider '{}'", model, expected_provider);
    }
}
#[tokio::test]
async fn test_gemini_url_scrubbing() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_gemini_scrub.db");
    let port = 36888;

    {
        let db = Database::init_at(db_path.clone()).unwrap();
        let mut policy = PolicyConfig::default();
        policy.allowed_domains = vec![];
        let policy_json = serde_json::to_string(&policy).unwrap();
        db.get_conn().execute(
            "INSERT OR REPLACE INTO policy (key, value, updated_at) VALUES ('policy_config', ?, CURRENT_TIMESTAMP)",
            rusqlite::params![policy_json],
        ).unwrap();
        
        let exe = std::env::current_exe().unwrap();
        secrets::allow_process(&db, exe.to_str().unwrap()).unwrap();
    }

    start_test_proxy(db_path.clone(), port).await;

    let client = reqwest::Client::new();
    // Simulate a request with ?key= dummy key
    let url = format!("http://127.0.0.1:{}/v1/models/gemini-1.5-pro:generateContent?key=dummy-google-key", port);

    let _ = client.post(&url)
        .header("X-Raypher-Token", "test")
        .header("x-goog-api-key", "dummy-google-key")
        .json(&serde_json::json!({}))
        .send()
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let db = Database::init_at(db_path.clone()).unwrap();
    let events = db.recent_events(10).unwrap();
    let attempt_event = events.iter().find(|e| e.2 == "PROXY_ATTEMPT").expect("No PROXY_ATTEMPT event found");
    let details: serde_json::Value = serde_json::from_str(&attempt_event.3).unwrap();
    
    let outbound_path = details["outbound_path"].as_str().unwrap();
    assert!(!outbound_path.contains("key="), "Outbound path should not contain 'key=': {}", outbound_path);
    assert!(outbound_path.contains("/v1/models/gemini-1.5-pro:generateContent"), "Outbound path should still contain the endpoint: {}", outbound_path);
}
