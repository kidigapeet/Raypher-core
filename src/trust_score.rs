// ──────────────────────────────────────────────────────────────
//  Raypher — Agent Trust Score Engine (Phase 5)
//  Computes a dynamic credit-score-style trust score per agent.
//  Starting at 850, bad events lower it; clean ops slowly raise it.
//  Range: 300 (minimum, never "zero trust") to 850 (maximum).
// ──────────────────────────────────────────────────────────────

/// The trust score an agent starts with on first registration.
pub const INITIAL_TRUST: i32 = 850;

/// The minimum score an agent can reach (floor — never zero trust).
pub const MIN_TRUST: i32 = 300;

/// The maximum score an agent can reach.
pub const MAX_TRUST: i32 = 850;

/// How to label a trust score range for display.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustLabel {
    HighTrust,   // 750–850 — green
    Good,        // 650–749 — light green
    Moderate,    // 550–649 — yellow
    Caution,     // 450–549 — orange
    Low,         // 300–449 — red
}

impl TrustLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLabel::HighTrust => "High Trust",
            TrustLabel::Good      => "Good",
            TrustLabel::Moderate  => "Moderate",
            TrustLabel::Caution   => "Caution",
            TrustLabel::Low       => "Low",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            TrustLabel::HighTrust => "#22c55e",  // green-500
            TrustLabel::Good      => "#84cc16",  // lime-500
            TrustLabel::Moderate  => "#eab308",  // yellow-500
            TrustLabel::Caution   => "#f97316",  // orange-500
            TrustLabel::Low       => "#ef4444",  // red-500
        }
    }
}

/// Get the label for a trust score.
pub fn score_label(score: i32) -> TrustLabel {
    match score {
        750..=850 => TrustLabel::HighTrust,
        650..=749 => TrustLabel::Good,
        550..=649 => TrustLabel::Moderate,
        450..=549 => TrustLabel::Caution,
        _         => TrustLabel::Low,
    }
}

/// How many points a bad event deducts from the trust score.
/// Returns a negative number.
pub fn trust_penalty(event_type: &str) -> i32 {
    match event_type {
        // Critical security violations — heavy penalty
        "JAILBREAK_BLOCKED"  => -100,   // Tried to hijack the agent
        "SSRF_HOST_BLOCKED"  => -75,    // Tried to reach internal network
        "PROXY_BLOCKED"      => -40,    // Executable not in allow list

        // Data integrity violations
        "DLP_BLOCKED"        => -50,    // Tried to send sensitive data
        "DLP_RESPONSE_REDACTED" => -15, // AI tried to return sensitive data

        // Access control violations
        "PROXY_UNAUTHORIZED" => -30,    // Missing auth token
        "RATE_LIMIT_EXCEEDED" => -20,   // Too many requests

        // Budget violations (softer penalty — policy, not malice)
        "BUDGET_BLOCKED"     => -10,
        "RUNTIME_EXCEEDED"   => -5,

        // Suspicious behavior alerts
        "CHILD_SPAWN_ALERT"  => -25,    // Agent spawned unexpected processes

        // All other events — no penalty
        _ => 0,
    }
}

/// How many points a clean event recovers.
/// Returns a positive number.
pub fn trust_recovery(event_type: &str) -> i32 {
    match event_type {
        "PROXY_FORWARD" => 1,   // Each successful clean request recovers 1 point
        _ => 0,
    }
}

/// Compute the new trust score after an event, clamped to [MIN_TRUST, MAX_TRUST].
pub fn apply_event(current_score: i32, event_type: &str) -> i32 {
    let delta = trust_penalty(event_type) + trust_recovery(event_type);
    (current_score + delta).clamp(MIN_TRUST, MAX_TRUST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_score_is_max() {
        assert_eq!(INITIAL_TRUST, MAX_TRUST);
    }

    #[test]
    fn test_jailbreak_lowers_score() {
        let score = apply_event(850, "JAILBREAK_BLOCKED");
        assert_eq!(score, 750);
    }

    #[test]
    fn test_clean_requests_recover_score() {
        let score_after_penalty = apply_event(850, "JAILBREAK_BLOCKED"); // 750
        let score_after_recovery = apply_event(score_after_penalty, "PROXY_FORWARD"); // 751
        assert_eq!(score_after_recovery, 751);
    }

    #[test]
    fn test_floor_is_min_trust_not_zero() {
        let mut score = 300;
        // Many bad events should not go below MIN_TRUST
        for _ in 0..100 {
            score = apply_event(score, "JAILBREAK_BLOCKED");
        }
        assert_eq!(score, MIN_TRUST);
    }

    #[test]
    fn test_ceiling_is_max_trust() {
        let mut score = MAX_TRUST;
        for _ in 0..100 {
            score = apply_event(score, "PROXY_FORWARD");
        }
        assert_eq!(score, MAX_TRUST);
    }

    #[test]
    fn test_score_label() {
        assert_eq!(score_label(850), TrustLabel::HighTrust);
        assert_eq!(score_label(700), TrustLabel::Good);
        assert_eq!(score_label(600), TrustLabel::Moderate);
        assert_eq!(score_label(500), TrustLabel::Caution);
        assert_eq!(score_label(300), TrustLabel::Low);
    }
}
