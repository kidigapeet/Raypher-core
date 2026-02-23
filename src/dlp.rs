// ──────────────────────────────────────────────────────────────
//  Raypher — DLP Scanner (Phase 3: The Content Filter)
//  Scans request and response bodies for sensitive data:
//  API keys, credit cards, SSNs, emails, private keys, etc.
//  Supports regex + Shannon entropy + Luhn validation.
// ──────────────────────────────────────────────────────────────

use regex::Regex;
use tracing::warn;
use serde::{Deserialize, Serialize};
use crate::policy::DlpAction;

// ── Data Types ─────────────────────────────────────────────────

/// A single DLP finding — one detected piece of sensitive data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpFinding {
    pub category: String,
    pub pattern_name: String,
    pub severity: DlpSeverity,
    pub full_match: String,      // Internal use for redaction
    pub matched_text: String,   // Truncated for safety — for logging/UI
    pub position: usize,
}

/// Severity levels for DLP findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DlpSeverity {
    Critical,   // API keys, private keys
    High,       // Credit cards, SSNs
    Medium,     // Emails, phone numbers
    Low,        // General PII patterns
}


/// Result of a DLP scan.
#[derive(Debug, Clone)]
pub struct DlpScanResult {
    pub findings: Vec<DlpFinding>,
    pub clean_payload: String,
    pub was_modified: bool,
}

/// A custom DLP pattern loaded from policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
    pub severity: DlpSeverity,
    pub redact_to: Option<String>,
}

// ── Built-in Patterns ──────────────────────────────────────────

/// A compiled DLP pattern with metadata.
struct CompiledPattern {
    name: &'static str,
    category: &'static str,
    severity: DlpSeverity,
    regex: Regex,
    redact_to: &'static str,
    validator: Option<fn(&str) -> bool>,
}

/// Build all the built-in DLP patterns (compiled once, reused).
fn build_builtin_patterns() -> Vec<CompiledPattern> {
    vec![
        // ── API Keys ──
        CompiledPattern {
            name: "OpenAI API Key",
            category: "api_key",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(),
            redact_to: "[REDACTED-OPENAI-KEY]",
            validator: None,
        },
        CompiledPattern {
            name: "Anthropic API Key",
            category: "api_key",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap(),
            redact_to: "[REDACTED-ANTHROPIC-KEY]",
            validator: None,
        },
        CompiledPattern {
            name: "Google API Key",
            category: "api_key",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"AIza[A-Za-z0-9_-]{35}").unwrap(),
            redact_to: "[REDACTED-GOOGLE-KEY]",
            validator: None,
        },
        CompiledPattern {
            name: "AWS Access Key",
            category: "api_key",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"AKIA[A-Z0-9]{16}").unwrap(),
            redact_to: "[REDACTED-AWS-KEY]",
            validator: None,
        },
        CompiledPattern {
            name: "GitHub Token",
            category: "api_key",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"gh[ps]_[A-Za-z0-9_]{36,}").unwrap(),
            redact_to: "[REDACTED-GITHUB-TOKEN]",
            validator: None,
        },
        CompiledPattern {
            name: "Generic Bearer Token",
            category: "api_key",
            severity: DlpSeverity::High,
            regex: Regex::new(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}").unwrap(),
            redact_to: "[REDACTED-BEARER-TOKEN]",
            validator: None,
        },

        // ── Financial PII ──
        CompiledPattern {
            name: "Credit Card Number",
            category: "financial",
            severity: DlpSeverity::High,
            regex: Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap(),
            redact_to: "[REDACTED-CREDIT-CARD]",
            validator: Some(luhn_check),
        },

        // ── Personal PII ──
        CompiledPattern {
            name: "US Social Security Number",
            category: "pii",
            severity: DlpSeverity::High,
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            redact_to: "[REDACTED-SSN]",
            validator: Some(ssn_validator),
        },
        CompiledPattern {
            name: "Email Address",
            category: "pii",
            severity: DlpSeverity::Medium,
            regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
            redact_to: "[REDACTED-EMAIL]",
            validator: None,
        },
        CompiledPattern {
            name: "US Phone Number",
            category: "pii",
            severity: DlpSeverity::Medium,
            regex: Regex::new(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
            redact_to: "[REDACTED-PHONE]",
            validator: Some(phone_validator),
        },

        // ── Cryptographic Material ──
        CompiledPattern {
            name: "Private Key Block",
            category: "crypto",
            severity: DlpSeverity::Critical,
            regex: Regex::new(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap(),
            redact_to: "[REDACTED-PRIVATE-KEY]",
            validator: None,
        },
    ]
}

// ── Core Scanner ───────────────────────────────────────────────

/// Scan a payload for sensitive data using built-in + custom patterns.
///
/// # Arguments
/// * `payload` — The request or response body as a string
/// * `action` — What to do with findings (Redact / Block / Alert)
/// * `custom_patterns` — Additional regex patterns from policy.yaml
/// * `exclusions` — Strings to whitelist (e.g., test data)
pub fn scan(
    payload: &str,
    action: &DlpAction,
    custom_patterns: &[CustomPattern],
    exclusions: &[String],
    entropy_threshold: f64,
) -> DlpScanResult {
    let patterns = build_builtin_patterns();
    let mut findings = Vec::new();
    let mut clean = payload.to_string();
    let mut was_modified = false;

    // ── Built-in pattern scan ──
    for pattern in &patterns {
        for mat in pattern.regex.find_iter(payload) {
            let matched = mat.as_str();

            // Check exclusions
            if exclusions.iter().any(|ex| matched.contains(ex.as_str())) {
                continue;
            }

            // Run validator if present (e.g., Luhn for credit cards)
            if let Some(validator) = pattern.validator {
                if !validator(matched) {
                    continue;
                }
            }

            // Record finding
            findings.push(DlpFinding {
                category: pattern.category.to_string(),
                pattern_name: pattern.name.to_string(),
                severity: pattern.severity.clone(),
                full_match: matched.to_string(),
                matched_text: truncate_match(matched),
                position: mat.start(),
            });

            // Apply action
            if *action == DlpAction::Redact {
                clean = clean.replace(matched, pattern.redact_to);
                was_modified = true;
            }
        }
    }

    // ── Custom pattern scan ──
    for custom in custom_patterns {
        if let Ok(re) = Regex::new(&custom.pattern) {
            for mat in re.find_iter(payload) {
                let matched = mat.as_str();

                if exclusions.iter().any(|ex| matched.contains(ex.as_str())) {
                    continue;
                }

                findings.push(DlpFinding {
                    category: "custom".to_string(),
                    pattern_name: custom.name.clone(),
                    severity: custom.severity.clone(),
                    full_match: matched.to_string(),
                    matched_text: truncate_match(matched),
                    position: mat.start(),
                });

                if *action == DlpAction::Redact {
                    let redact_to = custom.redact_to
                        .as_deref()
                        .unwrap_or("[REDACTED-CUSTOM]");
                    clean = clean.replace(matched, redact_to);
                    was_modified = true;
                }
            }
        }
    }

    // ── Shannon Entropy Check ──
    // Scan for high-entropy strings that might be unknown tokens/passwords
    let entropy_findings = scan_high_entropy(payload, exclusions, entropy_threshold);
    for ef in entropy_findings {
        // Only add if not already caught by regex patterns
        let already_found = findings.iter().any(|f| {
            f.position == ef.position
        });
        if !already_found {
            if *action == DlpAction::Redact {
                clean = clean.replace(&ef.full_match, "[REDACTED-HIGH-ENTROPY]");
                was_modified = true;
            }
            findings.push(ef);
        }
    }

    if !findings.is_empty() {
        warn!(
            findings = findings.len(),
            action = ?action,
            "DLP scan detected sensitive content"
        );
    }

    DlpScanResult {
        findings,
        clean_payload: clean,
        was_modified,
    }
}

// ── Entropy Analysis ───────────────────────────────────────────

/// Calculate Shannon entropy of a string.
/// High entropy (>4.5 for 20+ char strings) often indicates tokens/secrets.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Scan for high-entropy substrings that might be unknown secrets.
fn scan_high_entropy(payload: &str, exclusions: &[String], threshold: f64) -> Vec<DlpFinding> {
    let mut findings = Vec::new();

    // Look for long alphanumeric strings (potential tokens)
    let token_re = Regex::new(r"[A-Za-z0-9_\-]{32,}").unwrap();

    for mat in token_re.find_iter(payload) {
        let candidate = mat.as_str();

        // Skip exclusions
        if exclusions.iter().any(|ex| candidate.contains(ex.as_str())) {
            continue;
        }

        let entropy = shannon_entropy(candidate);

        // High entropy threshold: default 4.5 bits per character (configurable)
        if entropy > threshold {
            findings.push(DlpFinding {
                category: "entropy".to_string(),
                pattern_name: "High-Entropy String".to_string(),
                severity: DlpSeverity::High,
                full_match: candidate.to_string(),
                matched_text: truncate_match(candidate),
                position: mat.start(),
            });
        }
    }

    findings
}

// ── Validators ─────────────────────────────────────────────────

/// Luhn algorithm check for credit card numbers.
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Validate SSN format (reject obvious test patterns like 000-00-0000).
fn ssn_validator(ssn: &str) -> bool {
    let parts: Vec<&str> = ssn.split('-').collect();
    if parts.len() != 3 {
        return false;
    }

    let area = parts[0];
    let group = parts[1];
    let serial = parts[2];

    // Invalid patterns per SSA rules
    if area == "000" || area == "666" || area.starts_with("9") {
        return false;
    }
    if group == "00" {
        return false;
    }
    if serial == "0000" {
        return false;
    }

    true
}

/// Validate US Phone Number (exclude common false positives).
fn phone_validator(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    
    // Ignore common internal IDs that look like phone numbers
    // (e.g. starting with 1703 - common AWS Northern Virginia prefix)
    if digits.starts_with("1703") || digits.starts_with("703") {
        return false;
    }
    
    // Most phone numbers don't start with 0 or 1 (at the area code level)
    if digits.len() == 10 && (digits.starts_with("0") || digits.starts_with("1")) {
        return false; 
    }

    true
}

// ── Utilities ──────────────────────────────────────────────────

/// Truncate a matched string for safe logging (never log full secrets).
fn truncate_match(s: &str) -> String {
    if s.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &s[..4], &s[s.len()-4..])
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // Mastercard test
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("9999999999999999")); // Luhn fails (sum % 10 != 0)
    }

    #[test]
    fn test_luhn_all_zeros_valid() {
        // All-zeros is mathematically Luhn-valid (sum=0, 0%10=0)
        // but the credit card regex won't match it (starts with 0)
        assert!(luhn_check("0000000000000000"));
    }

    #[test]
    fn test_ssn_validator() {
        assert!(ssn_validator("123-45-6789"));
        assert!(!ssn_validator("000-45-6789")); // Invalid area
        assert!(!ssn_validator("666-45-6789")); // Invalid area
        assert!(!ssn_validator("123-00-6789")); // Invalid group
    }

    #[test]
    fn test_entropy() {
        let low = shannon_entropy("aaaaaaaaaa");
        let high = shannon_entropy("sk-proj-aB3cD4eF5gH6iJ7kL8mN9");
        assert!(low < 1.0);
        assert!(high > 3.0);
    }

    #[test]
    fn test_scan_openai_key() {
        let payload = "My key is sk-proj-aB3cD4eF5gH6iJ7kL8mN9oP0qR1 and that's it";
        let result = scan(payload, &DlpAction::Redact, &[], &[]);
        assert!(!result.findings.is_empty());
        assert!(result.was_modified);
        assert!(!result.clean_payload.contains("sk-proj-"));
    }

    #[test]
    fn test_scan_email() {
        let payload = "Contact me at john.doe@example.com for details";
        let result = scan(payload, &DlpAction::Redact, &[], &[]);
        assert!(result.findings.iter().any(|f| f.category == "pii"));
    }

    #[test]
    fn test_scan_exclusion() {
        let payload = "Test card: 4111111111111111";
        let result = scan(
            payload,
            &DlpAction::Redact,
            &[],
            &["4111111111111111".to_string()],
        );
        // Should be excluded
        assert!(result.findings.iter().all(|f| f.category != "financial"));
    }

    #[test]
    fn test_custom_pattern() {
        let payload = "Working on project_phoenix deadline";
        let custom = vec![CustomPattern {
            name: "Internal Project".to_string(),
            pattern: r"(?i)\bproject[_\s]?phoenix\b".to_string(),
            severity: DlpSeverity::Medium,
            redact_to: Some("[REDACTED-INTERNAL]".to_string()),
        }];
        let result = scan(payload, &DlpAction::Redact, &custom, &[]);
        assert!(result.findings.iter().any(|f| f.pattern_name == "Internal Project"));
        assert!(result.clean_payload.contains("[REDACTED-INTERNAL]"));
    }
}
