//! DID creation and pairwise derivation.
//!
//! Supports `did:twin:z<hex>` format using Ed25519 keys.

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;

/// Info string for DID key derivation from master seed.
const INFO_DID_DERIVATION: &[u8] = b"sovereign:did-derivation";

/// Result of creating a new DID identity.
#[derive(Debug, Clone)]
pub struct DidIdentity {
    /// The DID string, e.g. `did:twin:z<64 hex chars>`
    pub did: String,
    /// The 32-byte Ed25519 seed (private key material)
    pub signing_seed: [u8; 32],
    /// The 32-byte Ed25519 public key
    pub public_key: [u8; 32],
}

/// Create a new random `did:twin:z<hex>` identity.
///
/// Generates a fresh random Ed25519 keypair and returns the DID plus key material.
pub fn create_did_twin() -> DidIdentity {
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).expect("Entropy source failed");

    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let public_key = signing_key.verifying_key();
    let pub_hex = hex::encode(public_key.to_bytes());
    let did = format!("did:twin:z{}", pub_hex);

    DidIdentity {
        did,
        signing_seed: seed_bytes,
        public_key: public_key.to_bytes(),
    }
}

/// Derive a deterministic `did:twin:z<hex>` from a master seed and a derivation context.
///
/// Used to create the "root" DID for a user from their master seed.
pub fn derive_did_from_seed(master_seed: &[u8], context: &[u8]) -> DidIdentity {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut derived = [0u8; 32];
    hk.expand(context, &mut derived)
        .expect("HKDF expansion failed for DID derivation");

    let signing_key = SigningKey::from_bytes(&derived);
    let public_key = signing_key.verifying_key();
    let pub_hex = hex::encode(public_key.to_bytes());
    let did = format!("did:twin:z{}", pub_hex);

    DidIdentity {
        did,
        signing_seed: derived,
        public_key: public_key.to_bytes(),
    }
}

/// Derive a deterministic pairwise DID for a specific B2B connection.
///
/// Given a master seed and a connection identifier (e.g., the B2B tenant's DID),
/// this produces a unique, deterministic DID that the user uses *only* for that
/// specific business relationship.
///
/// # Arguments
/// * `master_seed` - The user's 32-byte master seed
/// * `connection_id` - Unique identifier for the connection (e.g., B2B service DID)
///
/// # Returns
/// A `DidIdentity` containing the pairwise DID and its key material.
pub fn derive_pairwise_did(master_seed: &[u8], connection_id: &str) -> DidIdentity {
    // Two-stage derivation: master_seed → intermediate → pairwise
    // Stage 1: Derive a pairwise-specific intermediate key
    let context = format!("sovereign:pairwise:{}", connection_id);
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut pairwise_seed = [0u8; 32];
    hk.expand(context.as_bytes(), &mut pairwise_seed)
        .expect("HKDF expansion failed for pairwise derivation");

    // Stage 2: Create the DID from the pairwise seed
    let signing_key = SigningKey::from_bytes(&pairwise_seed);
    let public_key = signing_key.verifying_key();
    let pub_hex = hex::encode(public_key.to_bytes());
    let did = format!("did:twin:z{}", pub_hex);

    DidIdentity {
        did,
        signing_seed: pairwise_seed,
        public_key: public_key.to_bytes(),
    }
}

/// Create a service DID for a B2B tenant (no master seed required).
///
/// This is used when the Host runs in "Keyless Mode" — the tenant service
/// gets its own DID identity but does NOT hold any user keys.
pub fn create_service_did(tenant_id: &str) -> DidIdentity {
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).expect("Entropy source failed");

    // Mix in tenant_id for domain separation (but still random)
    let hk = Hkdf::<Sha256>::new(Some(tenant_id.as_bytes()), &seed_bytes);
    let mut service_seed = [0u8; 32];
    hk.expand(b"sovereign:service-did", &mut service_seed)
        .expect("HKDF expansion failed for service DID");

    let signing_key = SigningKey::from_bytes(&service_seed);
    let public_key = signing_key.verifying_key();
    let pub_hex = hex::encode(public_key.to_bytes());
    let did = format!("did:twin:z{}", pub_hex);

    DidIdentity {
        did,
        signing_seed: service_seed,
        public_key: public_key.to_bytes(),
    }
}

/// Extract the Ed25519 public key bytes from a `did:twin:z<hex>` string.
///
/// Returns `None` if the DID format is invalid.
pub fn parse_did_twin_pubkey(did: &str) -> Option<[u8; 32]> {
    if !did.starts_with("did:twin:z") || did.len() < 11 {
        return None;
    }
    let hex_part = &did[10..];
    let bytes = hex::decode(hex_part).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_did_twin_format() {
        let identity = create_did_twin();
        assert!(identity.did.starts_with("did:twin:z"));
        assert_eq!(identity.did.len(), 10 + 64); // "did:twin:z" + 64 hex chars
    }

    #[test]
    fn test_pairwise_did_is_deterministic() {
        let seed = [42u8; 32];
        let did1 = derive_pairwise_did(&seed, "hotel-a");
        let did2 = derive_pairwise_did(&seed, "hotel-a");
        assert_eq!(did1.did, did2.did);
        assert_eq!(did1.signing_seed, did2.signing_seed);
    }

    #[test]
    fn test_pairwise_dids_differ_per_connection() {
        let seed = [42u8; 32];
        let did_a = derive_pairwise_did(&seed, "hotel-a");
        let did_b = derive_pairwise_did(&seed, "hotel-b");
        assert_ne!(did_a.did, did_b.did);
        assert_ne!(did_a.signing_seed, did_b.signing_seed);
    }

    #[test]
    fn test_parse_did_twin_pubkey_roundtrip() {
        let identity = create_did_twin();
        let parsed = parse_did_twin_pubkey(&identity.did).unwrap();
        assert_eq!(parsed, identity.public_key);
    }

    #[test]
    fn test_parse_did_twin_pubkey_invalid() {
        assert!(parse_did_twin_pubkey("did:web:example.com").is_none());
        assert!(parse_did_twin_pubkey("did:twin:z123").is_none()); // too short
        assert!(parse_did_twin_pubkey("").is_none());
    }

    #[test]
    fn test_service_did_is_unique() {
        let did1 = create_service_did("tenant-1");
        let did2 = create_service_did("tenant-1");
        // Random component means each call produces a different DID
        assert_ne!(did1.did, did2.did);
    }

    #[test]
    fn test_derive_did_from_seed() {
        let seed = [99u8; 32];
        let did1 = derive_did_from_seed(&seed, INFO_DID_DERIVATION);
        let did2 = derive_did_from_seed(&seed, INFO_DID_DERIVATION);
        assert_eq!(did1.did, did2.did);
        assert!(did1.did.starts_with("did:twin:z"));
    }
}
