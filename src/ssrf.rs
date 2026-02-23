// ──────────────────────────────────────────────────────────────
//  Raypher — SSRF Shield (Phase 4)
//  Prevents Server-Side Request Forgery by blocking any outbound
//  request that targets private, loopback, or link-local IP ranges
//  and reserved hostnames. AI agents must never be able to pivot
//  from the proxy into the internal network.
// ──────────────────────────────────────────────────────────────

use std::net::IpAddr;
use tracing::warn;

/// Result of an SSRF check.
#[derive(Debug, PartialEq)]
pub enum SsrfVerdict {
    /// Request is safe to forward.
    Allow,
    /// Request targets a private / internal address — block it.
    Block { reason: String },
}

/// Check whether a hostname or URL is attempting SSRF.
///
/// # What is blocked
/// - Loopback: `127.x.x.x`, `::1`
/// - RFC-1918 private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
/// - Link-local: `169.254.0.0/16`, `fe80::/10`
/// - Reserved: `0.0.0.0/8`, `100.64.0.0/10` (CGNAT)
/// - Internal hostnames: `localhost`, `metadata.google.internal`,
///   `169.254.169.254` (AWS IMDS), `*.local`, `*.internal`
///
/// # Arguments
/// * `host` — The hostname or IP address from the request URL (no port).
pub fn check_host(host: &str) -> SsrfVerdict {
    let host_lower = host.to_lowercase();

    // ── Blocked hostname patterns ─────────────────────────────
    if host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower == "metadata.google.internal"
        || host_lower == "169.254.169.254"
        || host_lower == "fd00:ec2::254"
    {
        warn!(host = host, "SSRF blocked: reserved hostname");
        return SsrfVerdict::Block {
            reason: format!("Reserved internal hostname: {}", host),
        };
    }

    // ── Try to parse as IP and check ranges ───────────────────
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = is_blocked_ip(ip) {
            warn!(host = host, reason = %reason, "SSRF blocked: private/reserved IP");
            return SsrfVerdict::Block { reason };
        }
    }

    SsrfVerdict::Allow
}

/// Check a full URL string for SSRF risk.
/// Extracts the host portion and delegates to `check_host`.
pub fn check_url(url: &str) -> SsrfVerdict {
    // Minimal host extraction — strip scheme, port, and path
    let stripped = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Handle IPv6 literals: [::1]:8080 → ::1
    let host = if stripped.starts_with('[') {
        stripped
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(stripped)
    } else {
        // hostname:port/path → hostname
        stripped.split('/').next().unwrap_or(stripped)
                .split(':').next().unwrap_or(stripped)
    };

    check_host(host)
}

// ── IP Range Checks ────────────────────────────────────────────

fn is_blocked_ip(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            // Loopback: 127.0.0.0/8
            if octets[0] == 127 {
                return Some(format!("{} is loopback (127.0.0.0/8)", ip));
            }
            // Unspecified: 0.0.0.0/8
            if octets[0] == 0 {
                return Some(format!("{} is unspecified (0.0.0.0/8)", ip));
            }
            // RFC-1918 private: 10.0.0.0/8
            if octets[0] == 10 {
                return Some(format!("{} is RFC-1918 private (10.0.0.0/8)", ip));
            }
            // RFC-1918 private: 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return Some(format!("{} is RFC-1918 private (172.16.0.0/12)", ip));
            }
            // RFC-1918 private: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return Some(format!("{} is RFC-1918 private (192.168.0.0/16)", ip));
            }
            // Link-local: 169.254.0.0/16 (also AWS IMDS)
            if octets[0] == 169 && octets[1] == 254 {
                return Some(format!("{} is link-local / cloud metadata (169.254.0.0/16)", ip));
            }
            // CGNAT shared: 100.64.0.0/10
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Some(format!("{} is CGNAT shared range (100.64.0.0/10)", ip));
            }
            // Broadcast
            if v4.is_broadcast() {
                return Some(format!("{} is broadcast", ip));
            }
            None
        }
        IpAddr::V6(v6) => {
            // Loopback ::1
            if v6.is_loopback() {
                return Some(format!("{} is IPv6 loopback (::1)", ip));
            }
            // Unspecified ::
            if v6.is_unspecified() {
                return Some(format!("{} is IPv6 unspecified (::)", ip));
            }
            // Link-local: fe80::/10
            let segments = v6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return Some(format!("{} is IPv6 link-local (fe80::/10)", ip));
            }
            // Unique local: fc00::/7
            if (segments[0] & 0xfe00) == 0xfc00 {
                return Some(format!("{} is IPv6 unique-local (fc00::/7)", ip));
            }
            None
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localhost_blocked() {
        assert_eq!(
            check_host("localhost"),
            SsrfVerdict::Block { reason: "Reserved internal hostname: localhost".to_string() }
        );
    }

    #[test]
    fn test_loopback_ip_blocked() {
        assert!(matches!(check_host("127.0.0.1"), SsrfVerdict::Block { .. }));
    }

    #[test]
    fn test_rfc1918_blocked() {
        assert!(matches!(check_host("10.0.0.1"), SsrfVerdict::Block { .. }));
        assert!(matches!(check_host("172.16.0.1"), SsrfVerdict::Block { .. }));
        assert!(matches!(check_host("192.168.1.100"), SsrfVerdict::Block { .. }));
    }

    #[test]
    fn test_aws_imds_blocked() {
        assert!(matches!(check_host("169.254.169.254"), SsrfVerdict::Block { .. }));
        assert!(matches!(check_url("http://169.254.169.254/latest/meta-data/"), SsrfVerdict::Block { .. }));
    }

    #[test]
    fn test_dot_local_blocked() {
        assert!(matches!(check_host("myserver.local"), SsrfVerdict::Block { .. }));
        assert!(matches!(check_host("prod-db.internal"), SsrfVerdict::Block { .. }));
    }

    #[test]
    fn test_public_ip_allowed() {
        assert_eq!(check_host("8.8.8.8"), SsrfVerdict::Allow);
        assert_eq!(check_host("api.openai.com"), SsrfVerdict::Allow);
    }

    #[test]
    fn test_url_parsing() {
        assert!(matches!(
            check_url("https://192.168.0.1/internal-api"),
            SsrfVerdict::Block { .. }
        ));
        assert_eq!(
            check_url("https://api.anthropic.com/v1/messages"),
            SsrfVerdict::Allow
        );
    }

    #[test]
    fn test_ipv6_loopback_blocked() {
        assert!(matches!(check_host("::1"), SsrfVerdict::Block { .. }));
    }

    #[test]
    fn test_ipv6_link_local_blocked() {
        assert!(matches!(check_host("fe80::1"), SsrfVerdict::Block { .. }));
    }
}
