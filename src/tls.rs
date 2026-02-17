// ──────────────────────────────────────────────────────────────
//  Raypher — TLS Certificate Authority (Phase 3: The Foundation)
//  Generates a machine-local Root CA, installs it in the OS
//  Trust Store, and creates per-domain certificates on-the-fly
//  for transparent HTTPS interception.
// ──────────────────────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{info, warn, error};

use crate::database::Database;

// ── Data Types ─────────────────────────────────────────────────

/// Holds the CA certificate and private key PEM data.
#[derive(Debug, Clone)]
pub struct CaCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

/// A cached domain certificate with its private key.
#[derive(Debug, Clone)]
pub struct DomainCert {
    pub cert_pem: String,
    pub key_pem: String,
}

/// The TLS manager — generates CA certs, caches domain certs.
pub struct TlsManager {
    pub ca: Option<CaCertificate>,
    domain_cache: Mutex<HashMap<String, DomainCert>>,
}

impl TlsManager {
    /// Create a new TLS manager, loading or generating the CA certificate.
    pub fn new(db: &Database, machine_fingerprint: &str) -> Self {
        let ca = match load_or_generate_ca(db, machine_fingerprint) {
            Ok(ca) => {
                info!("TLS CA loaded successfully");
                Some(ca)
            }
            Err(e) => {
                error!("Failed to initialize TLS CA: {}", e);
                None
            }
        };

        TlsManager {
            ca,
            domain_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get (or generate + cache) a domain certificate for TLS interception.
    pub fn get_domain_cert(&self, domain: &str) -> Option<DomainCert> {
        let ca = self.ca.as_ref()?;

        // Check cache first
        if let Ok(cache) = self.domain_cache.lock() {
            if let Some(cached) = cache.get(domain) {
                return Some(cached.clone());
            }
        }

        // Generate a new domain cert
        match generate_domain_cert(domain, &ca.cert_pem, &ca.key_pem) {
            Ok(cert) => {
                if let Ok(mut cache) = self.domain_cache.lock() {
                    cache.insert(domain.to_string(), cert.clone());
                }
                Some(cert)
            }
            Err(e) => {
                error!("Failed to generate cert for {}: {}", domain, e);
                None
            }
        }
    }

    /// Install the CA into the OS Trust Store.
    pub fn install_ca(&self) -> Result<(), Box<dyn std::error::Error>> {
        match &self.ca {
            Some(ca) => install_ca_to_trust_store(&ca.cert_pem),
            None => Err("No CA certificate available".into()),
        }
    }

    /// Remove the CA from the OS Trust Store.
    pub fn uninstall_ca(&self) -> Result<(), Box<dyn std::error::Error>> {
        remove_ca_from_trust_store()
    }
}

// ── CA Generation ──────────────────────────────────────────────

/// Load existing CA from database, or generate a new one.
fn load_or_generate_ca(
    db: &Database,
    machine_fingerprint: &str,
) -> Result<CaCertificate, Box<dyn std::error::Error>> {
    // Try to load from database
    if let Ok(Some(cert_pem)) = db.get_policy("tls_ca_cert") {
        if let Ok(Some(key_pem)) = db.get_policy("tls_ca_key") {
            info!("Loaded existing CA certificate from database");
            return Ok(CaCertificate { cert_pem, key_pem });
        }
    }

    // Generate new CA
    info!("Generating new machine-local Root CA...");
    let ca = generate_root_ca(machine_fingerprint)?;

    // Store in database (encrypted at rest via SQLite encryption)
    db.store_policy("tls_ca_cert", &ca.cert_pem)
        .map_err(|e| format!("Failed to store CA cert: {}", e))?;
    db.store_policy("tls_ca_key", &ca.key_pem)
        .map_err(|e| format!("Failed to store CA key: {}", e))?;

    info!("Root CA generated and stored in database");
    Ok(ca)
}

/// Generate a new Raypher Root CA certificate using rcgen.
/// The CA is unique per machine — the TPM fingerprint is embedded in the Subject.
fn generate_root_ca(
    machine_fingerprint: &str,
) -> Result<CaCertificate, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, IsCa, BasicConstraints};

    let mut params = CertificateParams::default();

    // Distinguished Name — identifies this specific machine's CA
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Raypher Local Security CA");
    dn.push(DnType::OrganizationName, "Raypher AI Security");
    let fp_short = if machine_fingerprint.len() >= 16 {
        &machine_fingerprint[..16]
    } else {
        machine_fingerprint
    };
    dn.push(DnType::OrganizationalUnitName, &format!("Machine: {}", fp_short));
    params.distinguished_name = dn;

    // Mark as a Certificate Authority
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    // Validity: 10 years
    let now = chrono::Utc::now();
    params.not_before = rcgen::date_time_ymd(now.year() as i32, now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd((now.year() + 10) as i32, now.month() as u8, now.day() as u8);

    // Generate key pair and self-sign
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok(CaCertificate {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Generate a per-domain certificate signed by the Root CA.
fn generate_domain_cert(
    domain: &str,
    _ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<DomainCert, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // Parse CA key for signing
    let ca_key = KeyPair::from_pem(ca_key_pem)?;

    // Re-create the CA cert params so we can use it to sign
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Raypher Local Security CA");
    ca_dn.push(DnType::OrganizationName, "Raypher AI Security");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Create domain cert params
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    // Short validity: 30 days
    let now = chrono::Utc::now();
    params.not_before = rcgen::date_time_ymd(now.year() as i32, now.month() as u8, now.day() as u8);
    let later = now + chrono::Duration::days(30);
    params.not_after = rcgen::date_time_ymd(later.year() as i32, later.month() as u8, later.day() as u8);

    // Generate domain key pair and sign with CA
    let domain_key = KeyPair::generate()?;
    let domain_cert = params.signed_by(&domain_key, &ca_cert, &ca_key)?;

    Ok(DomainCert {
        cert_pem: domain_cert.pem(),
        key_pem: domain_key.serialize_pem(),
    })
}

// ── Trust Store Management ─────────────────────────────────────

/// Install the Root CA into the OS Trust Store.
pub fn install_ca_to_trust_store(cert_pem: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let temp_path = std::env::temp_dir().join("raypher_ca.crt");
        std::fs::write(&temp_path, cert_pem)?;

        let output = std::process::Command::new("certutil")
            .args(["-addstore", "Root", &temp_path.to_string_lossy()])
            .output()?;

        let _ = std::fs::remove_file(&temp_path);

        if output.status.success() {
            info!("Root CA installed in Windows Trust Store");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("certutil failed: {}", stderr).into())
        }
    }

    #[cfg(target_os = "linux")]
    {
        let ca_path = "/usr/local/share/ca-certificates/raypher-local-ca.crt";
        std::fs::write(ca_path, cert_pem)?;

        let output = std::process::Command::new("update-ca-certificates")
            .output()?;

        if output.status.success() {
            info!("Root CA installed in Linux Trust Store");
            Ok(())
        } else {
            Err("update-ca-certificates failed".into())
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        warn!("Trust store installation not implemented for this OS");
        Ok(())
    }
}

/// Remove the Raypher CA from the OS Trust Store.
pub fn remove_ca_from_trust_store() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("certutil")
            .args(["-delstore", "Root", "Raypher Local Security CA"])
            .output()?;

        if output.status.success() {
            info!("Root CA removed from Windows Trust Store");
        } else {
            warn!("CA may not have been in trust store (already removed?)");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let ca_path = "/usr/local/share/ca-certificates/raypher-local-ca.crt";
        let _ = std::fs::remove_file(ca_path);

        let _ = std::process::Command::new("update-ca-certificates")
            .output();

        info!("Root CA removed from Linux Trust Store");
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        warn!("Trust store removal not implemented for this OS");
        Ok(())
    }
}

// ── Chrono Year/Month/Day helpers ──────────────────────────────

/// Extension trait for accessing chrono date components.
trait DateComponents {
    fn year(&self) -> i32;
    fn month(&self) -> u32;
    fn day(&self) -> u32;
}

impl DateComponents for chrono::DateTime<chrono::Utc> {
    fn year(&self) -> i32 {
        chrono::Datelike::year(self)
    }
    fn month(&self) -> u32 {
        chrono::Datelike::month(self)
    }
    fn day(&self) -> u32 {
        chrono::Datelike::day(self)
    }
}
