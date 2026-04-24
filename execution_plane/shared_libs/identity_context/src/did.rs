//! Centralized DID encoding/decoding utilities.
//!
//! All DID string parsing across the codebase should use these functions
//! instead of inline byte-offset slicing, which is fragile and error-prone.

/// Prefix for did:twin identities (hex-encoded Ed25519 pubkey after 'z').
pub const DID_TWIN_PREFIX: &str = "did:twin:z";

/// Prefix for did:peer identities (hex-encoded Ed25519 pubkey after 'z').
pub const DID_PEER_PREFIX: &str = "did:peer:z";

/// Expected length of a hex-encoded Ed25519 public key (32 bytes → 64 hex chars).
pub const ED25519_HEX_KEY_LEN: usize = 64;

/// Parse the Ed25519 public key bytes from a `did:twin:z<hex>` string.
///
/// Returns `None` if the DID doesn't have the expected prefix or the
/// hex portion is too short / invalid.
pub fn parse_twin_pubkey(did: &str) -> Option<[u8; 32]> {
    parse_did_pubkey(did, DID_TWIN_PREFIX)
}

/// Parse the Ed25519 public key bytes from a `did:peer:z<hex>` string.
///
/// Returns `None` if the DID doesn't have the expected prefix or the
/// hex portion is too short / invalid.
pub fn parse_peer_pubkey(did: &str) -> Option<[u8; 32]> {
    parse_did_pubkey(did, DID_PEER_PREFIX)
}

/// Parse the Ed25519 public key bytes from any DID with the given prefix.
///
/// Extracts the first 64 hex characters after `prefix` and decodes them
/// into a 32-byte array. Returns `None` on any failure.
fn parse_did_pubkey(did: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex_part = did.strip_prefix(prefix)?;
    if hex_part.len() < ED25519_HEX_KEY_LEN {
        return None;
    }
    let bytes = hex::decode(&hex_part[..ED25519_HEX_KEY_LEN]).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(arr)
}

/// Extract the hex-encoded public key string from a `did:twin:z` or `did:peer:z` DID.
///
/// Returns `None` if the DID doesn't match either prefix or is too short.
pub fn extract_hex_pubkey(did: &str) -> Option<&str> {
    let hex_part = did.strip_prefix(DID_TWIN_PREFIX)
        .or_else(|| did.strip_prefix(DID_PEER_PREFIX))?;
    if hex_part.len() >= ED25519_HEX_KEY_LEN {
        Some(&hex_part[..ED25519_HEX_KEY_LEN])
    } else {
        None
    }
}

/// Encode a 32-byte Ed25519 public key into a `did:twin:z<hex>` string.
pub fn encode_twin_did(pubkey: &[u8; 32]) -> String {
    format!("{}{}", DID_TWIN_PREFIX, hex::encode(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_twin_pubkey_valid() {
        let key = [0xab; 32];
        let did = encode_twin_did(&key);
        assert_eq!(parse_twin_pubkey(&did), Some(key));
    }

    #[test]
    fn test_parse_twin_pubkey_too_short() {
        assert_eq!(parse_twin_pubkey("did:twin:zabc"), None);
    }

    #[test]
    fn test_parse_twin_pubkey_wrong_prefix() {
        assert_eq!(parse_twin_pubkey("did:web:example.com"), None);
    }

    #[test]
    fn test_parse_peer_pubkey_valid() {
        let key = [0x42; 32];
        let did = format!("{}{}", DID_PEER_PREFIX, hex::encode(key));
        assert_eq!(parse_peer_pubkey(&did), Some(key));
    }

    #[test]
    fn test_extract_hex_pubkey() {
        let key = [0xff; 32];
        let did = encode_twin_did(&key);
        assert_eq!(extract_hex_pubkey(&did), Some(hex::encode(key).as_str()));
    }

    #[test]
    fn test_extract_hex_pubkey_peer() {
        let key = [0x01; 32];
        let did = format!("{}{}", DID_PEER_PREFIX, hex::encode(key));
        assert_eq!(extract_hex_pubkey(&did), Some(hex::encode(key).as_str()));
    }

    #[test]
    fn test_extract_hex_pubkey_unknown_prefix() {
        assert_eq!(extract_hex_pubkey("did:web:example.com"), None);
    }

    #[test]
    fn test_encode_twin_did_roundtrip() {
        let key = [0x13; 32];
        let did = encode_twin_did(&key);
        assert!(did.starts_with(DID_TWIN_PREFIX));
        assert_eq!(parse_twin_pubkey(&did), Some(key));
    }
}
