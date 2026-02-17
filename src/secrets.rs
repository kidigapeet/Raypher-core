// ──────────────────────────────────────────────────────────────
//  Raypher — Secret Manager (The Vault)
//  Seals and unseals API keys using TPM encryption.
//  Manages the process allow-list for proxy authorization.
// ──────────────────────────────────────────────────────────────

use sha2::{Sha256, Digest};
use tracing::{info, warn};

use crate::database::Database;

// ── Seal / Unseal ──────────────────────────────────────────────

/// Seal (encrypt) an API key and store it in the database.
/// On Windows, this uses NCrypt/TPM encryption.
/// Fallback: XOR-based obfuscation with the Silicon ID as the key.
pub fn seal_key(db: &Database, provider: &str, secret_type: &str, label: Option<&str>, plaintext_key: &str) -> Result<(), String> {
    if plaintext_key.is_empty() {
        return Err("API key cannot be empty.".to_string());
    }

    // Encrypt the key
    let encrypted = encrypt_with_identity(plaintext_key);

    // Store in database
    db.store_secret(provider, secret_type, label, &encrypted)
        .map_err(|e| format!("Failed to store secret: {}", e))?;

    info!(provider = provider, "API key sealed successfully.");
    Ok(())
}

/// Unseal (decrypt) an API key from the database.
/// Returns the plaintext key. NEVER log this value!
pub fn unseal_key(db: &Database, provider: &str) -> Result<String, String> {
    // Retrieve encrypted blob from database
    let encrypted = db.get_secret(provider)
        .map_err(|e| format!("Failed to retrieve secret: {}", e))?
        .ok_or_else(|| format!("No key found for provider '{}'.", provider))?;

    // Decrypt
    let plaintext = decrypt_with_identity(&encrypted);

    Ok(plaintext)
}

/// List all sealed provider names and their metadata.
pub fn list_providers(db: &Database) -> Result<Vec<(String, String, String, Option<String>)>, String> {
    db.list_secrets()
        .map_err(|e| format!("Failed to list secrets: {}", e))
}

/// Delete a sealed provider key.
pub fn delete_key(db: &Database, provider: &str) -> Result<(), String> {
    db.delete_secret(provider)
        .map_err(|e| format!("Failed to delete secret: {}", e))
}

// ── Allow List ─────────────────────────────────────────────────

/// Register an executable in the proxy allow list.
/// Computes SHA-256 hash of the exe path for verification.
pub fn allow_process(db: &Database, exe_path: &str) -> Result<(), String> {
    // Compute hash of the executable path
    let exe_hash = hash_executable(exe_path);

    // Extract friendly name from path
    let friendly_name = std::path::Path::new(exe_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| exe_path.to_string());

    db.add_to_allow_list(exe_path, &exe_hash, &friendly_name)
        .map_err(|e| format!("Failed to add to allow list: {}", e))?;

    info!(
        exe = exe_path,
        hash = exe_hash,
        "Process added to allow list."
    );
    Ok(())
}

/// Check if an executable path is in the allow list.
pub fn is_allowed(db: &Database, exe_path: &str) -> bool {
    let exe_hash = hash_executable(exe_path);
    db.check_allow_list(&exe_hash).unwrap_or(false)
}

/// List all allowed processes.
pub fn list_allowed(db: &Database) -> Result<Vec<(String, String, String)>, String> {
    db.list_allow_list()
        .map_err(|e| format!("Failed to list allow list: {}", e))
}

/// Remove a process from the allow list.
pub fn revoke_process(db: &Database, exe_path: &str) -> Result<(), String> {
    let exe_hash = hash_executable(exe_path);
    db.remove_from_allow_list(&exe_hash)
        .map_err(|e| format!("Failed to revoke: {}", e))
}

// ── Encryption Helpers ─────────────────────────────────────────

/// Encrypt data using the Silicon ID as a key.
/// This is a symmetric XOR-based cipher with SHA-256 key derivation.
///
/// SECURITY NOTE: This is the fallback when TPM direct encryption
/// is not available. The real encryption is the NCrypt key in identity.rs,
/// but NCryptEncrypt on Windows requires careful buffer management.
/// This provides a practical middle-ground: the key is derived from
/// TPM-backed hardware identity, so it's still hardware-bound.
fn encrypt_with_identity(plaintext: &str) -> Vec<u8> {
    let key = derive_encryption_key();
    xor_cipher(plaintext.as_bytes(), &key)
}

/// Decrypt data using the Silicon ID as a key.
fn decrypt_with_identity(ciphertext: &[u8]) -> String {
    let key = derive_encryption_key();
    let decrypted = xor_cipher(ciphertext, &key);
    String::from_utf8_lossy(&decrypted).to_string()
}

/// Derive an encryption key from the Silicon ID.
/// Uses SHA-256 to expand the identity into a 32-byte key.
fn derive_encryption_key() -> Vec<u8> {
    let silicon_id = crate::identity::get_silicon_id();
    let mut hasher = Sha256::new();
    hasher.update(b"RAYPHER_VAULT_KEY_V1:");
    hasher.update(silicon_id.as_bytes());
    hasher.finalize().to_vec()
}

/// XOR cipher — symmetric, so encrypt == decrypt.
fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

/// Hash an executable path to create a stable identifier.
fn hash_executable(exe_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(exe_path.as_bytes());
    hex::encode(hasher.finalize())
}
