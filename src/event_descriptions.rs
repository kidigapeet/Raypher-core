// ──────────────────────────────────────────────────────────────
//  Raypher — Plain English Event Descriptions (Phase 5)
//  Translates machine event codes into human-readable summaries
//  for the Dashboard audit log.
// ──────────────────────────────────────────────────────────────

/// Translate a raw event_type code + details JSON into a plain English sentence.
/// This is used by the dashboard to display friendly audit log entries.
pub fn describe_event(event_type: &str, details: &serde_json::Value) -> String {
    let agent = details
        .get("agent")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "unknown")
        .unwrap_or("An AI agent");

    let path = details
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("/v1/chat/completions");

    let provider = details
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("AI provider");

    let reason = details
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("policy violation");

    match event_type {
        // ── Successful Proxy Forwards ───────────────────────────
        "PROXY_FORWARD" => {
            let status = details.get("status").and_then(|v| v.as_u64()).unwrap_or(200);
            let latency = details.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(0);
            let key_injected = details.get("key_injected").and_then(|v| v.as_bool()).unwrap_or(false);
            let key_note = if key_injected { " API key was injected from the Vault." } else { "" };
            format!(
                "{} made an AI request to {} via {}. Completed in {}ms with status {}.{}",
                agent, path, provider, latency, status, key_note
            )
        }

        // ── Budget Controls ─────────────────────────────────────
        "BUDGET_BLOCKED" => {
            format!(
                "{} was blocked — the daily spending limit has been reached. No API request was sent.",
                agent
            )
        }
        "RUNTIME_EXCEEDED" => {
            format!(
                "{} was blocked — the maximum allowed runtime for this agent session has been exceeded.",
                agent
            )
        }

        // ── Data Loss Prevention ────────────────────────────────
        "DLP_BLOCKED" => {
            let count = details
                .get("findings")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            format!(
                "Sensitive data detected in outbound request from {}. {} finding(s) triggered a block — the request was NOT sent.",
                agent, count
            )
        }
        "DLP_MATCHED" => {
            let count = details
                .get("findings")
                .and_then(|v| v.as_u64())
                .unwrap_or(1);
            format!(
                "Sensitive data detected in outbound request from {}. {} finding(s) were automatically redacted before the request was sent.",
                agent, count
            )
        }
        "DLP_RESPONSE_REDACTED" => {
            format!(
                "Sensitive data found in the AI's response to {}. The data was automatically redacted before it reached the agent.",
                agent
            )
        }

        // ── SSRF Shield ─────────────────────────────────────────
        "SSRF_HOST_BLOCKED" => {
            format!(
                "Network attack blocked: {} tried to reach an internal or reserved IP address ({}). This is a potential Server-Side Request Forgery attack.",
                agent, reason
            )
        }

        // ── Jailbreak / Prompt Injection ────────────────────────
        "JAILBREAK_BLOCKED" => {
            let pattern = details
                .get("pattern")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown pattern");
            format!(
                "Prompt injection / jailbreak attempt blocked for {}. Matched pattern: '{}'. The request was not sent.",
                agent, pattern
            )
        }

        // ── Access Control ──────────────────────────────────────
        "PROXY_UNAUTHORIZED" => {
            format!(
                "Unauthorized request from {} — the Raypher security token was missing. Access denied.",
                agent
            )
        }
        "PROXY_BLOCKED" => {
            format!(
                "{} is not in the Agent Allow List. Its executable could not be verified. Access denied.",
                agent
            )
        }

        // ── Time Restrictions ───────────────────────────────────
        "TIME_RESTRICTED" => {
            format!(
                "Request from {} was blocked — AI access is only allowed during configured work hours.",
                agent
            )
        }

        // ── Emergency Actions ───────────────────────────────────
        "PANIC_DASHBOARD" => {
            let killed: Vec<String> = details
                .get("killed")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_u64()).map(|p| p.to_string()).collect())
                .unwrap_or_default();
            if killed.is_empty() {
                "Emergency kill was triggered from the Dashboard. No processes were terminated.".to_string()
            } else {
                format!("Emergency kill triggered from the Dashboard. Agent processes killed: {}.", killed.join(", "))
            }
        }

        // ── Security Alerts ─────────────────────────────────────
        "CHILD_SPAWN_ALERT" => {
            let child = details
                .get("child_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown process");
            format!(
                "Warning: {} spawned an unexpected child process '{}'. This may indicate runaway or malicious agent behavior.",
                agent, child
            )
        }
        "RATE_LIMIT_EXCEEDED" => {
            format!(
                "Rate limit exceeded: {} sent too many requests in a short period. Requests are being throttled.",
                agent
            )
        }
        "TOKEN_HIJACK_BLOCKED" => {
            format!(
                "Security alert: A different process tried to use {}'s Raypher token. Possible token theft attempt — request blocked.",
                agent
            )
        }

        // ── System Events ───────────────────────────────────────
        "PROXY_START" => "Raypher proxy started and is now protecting all AI traffic.".to_string(),
        "IDENTITY_STORED" => "Hardware identity (Silicon ID) was recorded and stored in the audit ledger.".to_string(),

        // ── Fallback ────────────────────────────────────────────
        _ => format!("System event: {} from {}.", event_type.replace('_', " ").to_lowercase(), agent),
    }
}

/// Format a Unix timestamp (seconds since epoch) into a human-readable string.
/// Example output: "Sat, 22 Feb 2026 — 15:17:43 UTC"
pub fn format_unix_timestamp(unix_secs: u64) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    let d = UNIX_EPOCH + Duration::from_secs(unix_secs);
    // Use chrono for clean formatting
    if let Ok(elapsed) = d.duration_since(UNIX_EPOCH) {
        let dt = chrono::DateTime::<chrono::Utc>::from(UNIX_EPOCH + elapsed);
        dt.format("%a, %d %b %Y — %H:%M:%S UTC").to_string()
    } else {
        "Unknown time".to_string()
    }
}

/// Format an ISO 8601 timestamp string into a human-readable string.
/// Example: "2026-02-22T15:17:43.123Z" → "Sat, 22 Feb 2026 — 15:17:43 UTC"
pub fn format_iso_timestamp(ts: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        dt.with_timezone(&chrono::Utc)
            .format("%a, %d %b %Y — %H:%M:%S UTC")
            .to_string()
    } else {
        ts.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_forward_description() {
        let details = serde_json::json!({
            "agent": "OpenClaw.ai",
            "path": "/v1/chat/completions",
            "provider": "openai",
            "status": 200,
            "latency_ms": 342,
            "key_injected": true,
        });
        let desc = describe_event("PROXY_FORWARD", &details);
        assert!(desc.contains("OpenClaw.ai"));
        assert!(desc.contains("342ms"));
        assert!(desc.contains("Vault"));
    }

    #[test]
    fn test_budget_blocked_description() {
        let details = serde_json::json!({"agent": "OpenClaw.ai"});
        let desc = describe_event("BUDGET_BLOCKED", &details);
        assert!(desc.contains("OpenClaw.ai"));
        assert!(desc.contains("spending limit"));
    }

    #[test]
    fn test_dlp_blocked_description() {
        let details = serde_json::json!({"agent": "OpenClaw.ai", "findings": 3});
        let desc = describe_event("DLP_BLOCKED", &details);
        assert!(desc.contains("3 finding"));
    }

    #[test]
    fn test_unknown_event_falls_back() {
        let details = serde_json::json!({"agent": "MyAgent"});
        let desc = describe_event("SOME_CUSTOM_EVENT", &details);
        assert!(desc.contains("some custom event"));
    }

    #[test]
    fn test_format_iso_timestamp() {
        let ts = "2026-02-22T15:17:43Z";
        let formatted = format_iso_timestamp(ts);
        assert!(formatted.contains("2026"));
        assert!(formatted.contains("Feb"));
    }
}
