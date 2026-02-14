// identity.rs — The "Hardware Handshake" (Silicon-Bound Identity)
// Reads a persistent TPM-backed key and returns a SHA-256 fingerprint.
// This fingerprint is unique to the physical machine and persists across reboots.

use sha2::{Sha256, Digest};

// ======================== WINDOWS MODE (REAL TPM) ========================
#[cfg(target_os = "windows")]
use windows::{
    core::*,
    Win32::Security::Cryptography::*,
};

/// The name of our persistent TPM-backed identity key.
#[cfg(target_os = "windows")]
const RAYPHER_KEY_NAME: PCWSTR = w!("RaypherIdentityKey");

/// Opens the Microsoft Platform Crypto Provider (TPM 2.0 interface).
/// Returns a handle to the provider, or an error if TPM is unavailable.
#[cfg(target_os = "windows")]
fn open_tpm_provider() -> Result<NCRYPT_PROV_HANDLE> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        )?;
    }
    Ok(provider)
}

/// Attempts to open an existing persistent key, or creates one if it doesn't exist.
/// The key lives inside the TPM — it persists across reboots and cannot be cloned.
#[cfg(target_os = "windows")]
fn open_or_create_key(provider: NCRYPT_PROV_HANDLE) -> Result<NCRYPT_KEY_HANDLE> {
    let mut key = NCRYPT_KEY_HANDLE::default();

    // Try to open an existing key first
    let open_result = unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            RAYPHER_KEY_NAME,
            CERT_KEY_SPEC(0),  // dwLegacyKeySpec
            NCRYPT_FLAGS(0),   // dwFlags
        )
    };

    if open_result.is_ok() {
        return Ok(key);
    }

    // Key doesn't exist yet — create a new persistent RSA-2048 key in the TPM
    unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            BCRYPT_RSA_ALGORITHM,
            RAYPHER_KEY_NAME,
            CERT_KEY_SPEC(0),  // dwLegacyKeySpec
            NCRYPT_FLAGS(0),
        )?;

        // Finalize the key — this commits it to the TPM's persistent storage
        NCryptFinalizeKey(key, NCRYPT_FLAGS(0))?;
    }

    Ok(key)
}

/// Exports the public portion of the TPM key as raw bytes.
#[cfg(target_os = "windows")]
fn export_public_key(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
    let blob_type = BCRYPT_RSAPUBLIC_BLOB;
    let mut size: u32 = 0;

    // First call: get the required buffer size
    unsafe {
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            blob_type,
            None,     // pParameterList
            None,     // pbOutput (null = query size)
            &mut size,
            NCRYPT_FLAGS(0),
        )?;
    }

    // Second call: export the actual key blob
    let mut buffer = vec![0u8; size as usize];
    unsafe {
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            blob_type,
            None,
            Some(&mut buffer),
            &mut size,
            NCRYPT_FLAGS(0),
        )?;
    }

    buffer.truncate(size as usize);
    Ok(buffer)
}

/// Frees an NCrypt handle (provider or key).
#[cfg(target_os = "windows")]
fn free_handle(handle: NCRYPT_HANDLE) {
    unsafe {
        let _ = NCryptFreeObject(handle);
    }
}

/// Returns the Silicon ID — a SHA-256 hash of the TPM-backed public key.
/// This value is:
///   - Unique to this physical machine
///   - Persistent across reboots
///   - Impossible to clone (private key never leaves the TPM chip)
///
/// If TPM is unavailable, falls back to a machine-specific ID with a warning.
#[cfg(target_os = "windows")]
pub fn get_silicon_id() -> String {
    match get_tpm_fingerprint() {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("  ⚠️  TPM unavailable: {}. Using fallback machine ID.", e);
            get_fallback_id()
        }
    }
}

/// Core TPM fingerprint logic — separated for clean error handling.
#[cfg(target_os = "windows")]
fn get_tpm_fingerprint() -> Result<String> {
    // Step 1: Open the Platform Crypto Provider (TPM interface)
    let provider = open_tpm_provider()?;

    // Step 2: Open or create our persistent identity key
    let key = match open_or_create_key(provider) {
        Ok(k) => k,
        Err(e) => {
            free_handle(NCRYPT_HANDLE(provider.0));
            return Err(e);
        }
    };

    // Step 3: Export the public key blob
    let public_bytes = match export_public_key(key) {
        Ok(bytes) => bytes,
        Err(e) => {
            free_handle(NCRYPT_HANDLE(key.0));
            free_handle(NCRYPT_HANDLE(provider.0));
            return Err(e);
        }
    };

    // Step 4: SHA-256 hash the public key → This is the Silicon ID
    let mut hasher = Sha256::new();
    hasher.update(&public_bytes);
    let hash = hasher.finalize();
    let hex_hash = hex::encode(hash);

    // Cleanup handles
    free_handle(NCRYPT_HANDLE(key.0));
    free_handle(NCRYPT_HANDLE(provider.0));

    Ok(hex_hash)
}

/// Fallback when TPM is not available — uses hostname + OS info.
/// This is NOT hardware-bound and is less secure, but keeps the app functional.
#[cfg(target_os = "windows")]
fn get_fallback_id() -> String {
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".to_string());

    let mut hasher = Sha256::new();
    hasher.update(format!("RAYPHER_FALLBACK:{}:{}", hostname, username));
    let hash = hasher.finalize();

    format!("FALLBACK_{}", hex::encode(hash))
}

// ======================== LINUX/MAC MODE (MOCK ID) ========================
#[cfg(not(target_os = "windows"))]
pub fn get_silicon_id() -> String {
    // On Linux/Mac, we return a deterministic mock ID for development environments.
    // Real TPM integration on Linux would use tss-esapi (future enhancement).
    eprintln!("  ⚠️  Non-Windows platform: using mock Silicon ID for development.");

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "dev".to_string());

    let mut hasher = Sha256::new();
    hasher.update(format!("RAYPHER_DEV_MOCK:{}", hostname));
    let hash = hasher.finalize();

    format!("MOCK_{}", hex::encode(hash))
}
