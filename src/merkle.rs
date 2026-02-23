// ──────────────────────────────────────────────────────────────
//  Raypher — Merkle-Chained Audit Ledger (Phase 4)
//  Provides tamper-evidence for the audit log by chaining each
//  entry with the SHA-256 hash of the previous entry.
//  Any deletion or modification of a prior entry will cascade
//  as a verification failure in all subsequent entries.
// ──────────────────────────────────────────────────────────────

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Data Types ─────────────────────────────────────────────────

/// A single entry in the Merkle audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleEntry {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// The audit event type / description.
    pub event: String,
    /// Serialized event details (JSON string).
    pub details: String,
    /// SHA-256 hash of the *previous* entry's canonical form.
    /// For seq=0 this is the all-zeros hash (genesis block).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's own canonical form (prev_hash included).
    pub own_hash: String,
}

/// Error types for Merkle chain verification.
#[derive(Debug, PartialEq)]
pub enum MerkleError {
    /// A hash stored in an entry doesn't match recomputed value.
    HashMismatch { seq: u64, expected: String, actual: String },
    /// prev_hash of entry N+1 doesn't match own_hash of entry N.
    ChainBreak { at_seq: u64 },
    /// Chain is empty — nothing to verify.
    EmptyChain,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleError::HashMismatch { seq, expected, actual } =>
                write!(f, "Hash mismatch at seq={}: expected {} got {}", seq, &expected[..8], &actual[..8]),
            MerkleError::ChainBreak { at_seq } =>
                write!(f, "Chain break at seq={}: prev_hash doesn't match prior entry's own_hash", at_seq),
            MerkleError::EmptyChain =>
                write!(f, "Chain is empty — nothing to verify"),
        }
    }
}

// ── Genesis ────────────────────────────────────────────────────

/// The genesis hash — all-zeros, used as prev_hash for seq=0.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Entry Construction ─────────────────────────────────────────

/// Create a new Merkle entry.
///
/// # Arguments
/// * `seq` — Sequence number (must be unique and monotonically increasing).
/// * `event` — A short label like `"PROXY_FORWARD"`, `"DLP_BLOCK"`.
/// * `details` — Free-form JSON string with event details.
/// * `prev_hash` — `own_hash` of the immediately preceding entry.
///                 Pass `GENESIS_HASH` for the first entry.
pub fn create_entry(seq: u64, event: &str, details: &str, prev_hash: &str) -> MerkleEntry {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Compute own_hash over the canonical form of this entry's fields
    let own_hash = compute_hash(seq, timestamp, event, details, prev_hash);

    MerkleEntry {
        seq,
        timestamp,
        event: event.to_string(),
        details: details.to_string(),
        prev_hash: prev_hash.to_string(),
        own_hash,
    }
}

// ── Hashing ────────────────────────────────────────────────────

/// Compute the SHA-256 hash of a Merkle entry's canonical form.
///
/// Canonical form: `{seq}|{timestamp}|{event}|{details}|{prev_hash}`
/// Fields are separated by `|` — no quotes or escaping to keep it simple.
pub fn compute_hash(seq: u64, timestamp: u64, event: &str, details: &str, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}|{}|{}|{}", seq, timestamp, event, details, prev_hash).as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Recompute the hash for an existing entry (for verification).
pub fn recompute_hash(entry: &MerkleEntry) -> String {
    compute_hash(entry.seq, entry.timestamp, &entry.event, &entry.details, &entry.prev_hash)
}

// ── Verification ───────────────────────────────────────────────

/// Verify the integrity of the entire Merkle chain.
///
/// Checks:
/// 1. Every entry's `own_hash` matches its recomputed hash.
/// 2. Every entry's `prev_hash` matches the `own_hash` of the previous entry.
/// 3. The first entry's `prev_hash` is `GENESIS_HASH`.
///
/// # Returns
/// `Ok(())` if the chain is intact, `Err(MerkleError)` on first violation.
pub fn verify_chain(entries: &[MerkleEntry]) -> Result<(), MerkleError> {
    if entries.is_empty() {
        return Err(MerkleError::EmptyChain);
    }

    // Verify genesis
    if entries[0].prev_hash != GENESIS_HASH {
        return Err(MerkleError::ChainBreak { at_seq: 0 });
    }

    for (i, entry) in entries.iter().enumerate() {
        // 1. Verify own_hash integrity
        let expected = recompute_hash(entry);
        if expected != entry.own_hash {
            return Err(MerkleError::HashMismatch {
                seq: entry.seq,
                expected,
                actual: entry.own_hash.clone(),
            });
        }

        // 2. Verify chain linkage (prev_hash → prior own_hash)
        if i > 0 {
            let prior = &entries[i - 1];
            if entry.prev_hash != prior.own_hash {
                return Err(MerkleError::ChainBreak { at_seq: entry.seq });
            }
        }
    }

    Ok(())
}

/// Get the `own_hash` of the last entry in the chain.
/// Returns `GENESIS_HASH` if the chain is empty.
pub fn chain_tip(entries: &[MerkleEntry]) -> &str {
    entries.last().map(|e| e.own_hash.as_str()).unwrap_or(GENESIS_HASH)
}

// ── Serialization Helpers ──────────────────────────────────────

/// Serialize a chain entry to a single newline-delimited JSON record.
pub fn entry_to_ndjson(entry: &MerkleEntry) -> String {
    serde_json::to_string(entry).unwrap_or_else(|_| "{}".to_string())
}

/// Parse a chain entry from a newline-delimited JSON record.
pub fn entry_from_ndjson(line: &str) -> Option<MerkleEntry> {
    serde_json::from_str(line).ok()
}

/// Append a new event to the Merkle-chained audit ledger file.
///
/// This handles:
/// 1. Opening/Creating the ledger file.
/// 2. Reading the last line to get the previous hash and sequence number.
/// 3. Appending the new entry.
pub fn append_to_ledger(path: &str, event: &str, details: &str) -> Result<(), std::io::Error> {
    use std::fs::{OpenOptions, File};
    use std::io::{BufRead, BufReader, Write};

    let _file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // 1. Find the last entry to get seq and prev_hash
    let mut last_entry: Option<MerkleEntry> = None;
    let reader = BufReader::new(File::open(path)?);
    for line in reader.lines().map_while(Result::ok) {
        if let Some(entry) = entry_from_ndjson(&line) {
            last_entry = Some(entry);
        }
    }

    let (next_seq, prev_hash) = match last_entry {
        Some(e) => (e.seq + 1, e.own_hash),
        None => (0, GENESIS_HASH.to_string()),
    };

    // 2. Create and append the new entry
    let entry = create_entry(next_seq, event, details, &prev_hash);
    let json = entry_to_ndjson(&entry);
    
    let mut file = OpenOptions::new().append(true).open(path)?;
    writeln!(file, "{}", json)?;

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_chain(n: u64) -> Vec<MerkleEntry> {
        let mut chain = Vec::new();
        let mut prev = GENESIS_HASH.to_string();
        for i in 0..n {
            let entry = create_entry(i, "TEST_EVENT", &format!("{{\"i\":{}}}", i), &prev);
            prev = entry.own_hash.clone();
            chain.push(entry);
        }
        chain
    }

    #[test]
    fn test_single_entry_valid() {
        let chain = build_chain(1);
        assert!(verify_chain(&chain).is_ok());
    }

    #[test]
    fn test_chain_of_10_valid() {
        let chain = build_chain(10);
        assert!(verify_chain(&chain).is_ok());
    }

    #[test]
    fn test_empty_chain_error() {
        assert_eq!(verify_chain(&[]), Err(MerkleError::EmptyChain));
    }

    #[test]
    fn test_tamper_detection_own_hash() {
        let mut chain = build_chain(3);
        // Tamper with entry[1]'s event
        chain[1].event = "TAMPERED".to_string();
        let result = verify_chain(&chain);
        assert!(matches!(result, Err(MerkleError::HashMismatch { seq: 1, .. })));
    }

    #[test]
    fn test_tamper_detection_chain_break() {
        let mut chain = build_chain(3);
        // Simulate an attacker who replaces entry[1] with a fresh entry that
        // has a fabricated prev_hash (so own_hash check passes, but chain link fails).
        let fake_prev = "aabbccddaabbccddaabbccddaabbccdd\
                         aabbccddaabbccddaabbccddaabbccdd"
            .to_string();
        chain[1].prev_hash = fake_prev.clone();
        // Recompute own_hash with the fake prev_hash so HashMismatch won't fire.
        chain[1].own_hash = compute_hash(
            chain[1].seq,
            chain[1].timestamp,
            &chain[1].event,
            &chain[1].details,
            &fake_prev,
        );
        let result = verify_chain(&chain);
        assert!(
            matches!(result, Err(MerkleError::ChainBreak { at_seq: 1 })),
            "Expected ChainBreak at seq=1, got {:?}",
            result
        );
    }

    #[test]
    fn test_genesis_prev_hash() {
        let chain = build_chain(1);
        assert_eq!(chain[0].prev_hash, GENESIS_HASH);
    }

    #[test]
    fn test_ndjson_roundtrip() {
        let chain = build_chain(1);
        let json = entry_to_ndjson(&chain[0]);
        let parsed = entry_from_ndjson(&json).expect("Should parse");
        assert_eq!(parsed.seq, 0);
        assert_eq!(parsed.event, "TEST_EVENT");
    }
}
