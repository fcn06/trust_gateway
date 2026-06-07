//! Shadow identity service — deterministic DID generation for Web2 users.
//!
//! Creates stable, tenant-scoped DIDs for external users identified by
//! phone numbers or email addresses. Uses HMAC to ensure the same external
//! identity always maps to the same DID within a tenant.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::Engine;

type HmacSha256 = Hmac<Sha256>;

/// Generate a deterministic shadow DID for a Web2 user.
///
/// The DID is derived from `HMAC(gateway_seed, tenant_id + normalized_identifier)`
/// ensuring:
/// - Same phone/email always produces the same DID within a tenant
/// - Different tenants produce different DIDs for the same phone/email
/// - The original phone/email cannot be recovered from the DID
pub fn generate_shadow_did(
    gateway_seed: &[u8],
    tenant_id: &str,
    identifier: &str,
    channel: &str,
) -> String {
    let normalized = normalize_identifier(identifier, channel);
    let input = format!("{}:{}", tenant_id, normalized);

    let mut mac = HmacSha256::new_from_slice(gateway_seed)
        .expect("HMAC can take any key size");
    mac.update(input.as_bytes());
    let result = mac.finalize();
    let hash_bytes = &result.into_bytes()[..16]; // Use first 16 bytes

    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash_bytes);
    format!("did:shadow:{}:{}", channel, encoded)
}

/// Normalize an identifier based on channel type.
fn normalize_identifier(identifier: &str, channel: &str) -> String {
    match channel {
        "sms" | "whatsapp" => {
            // Strip non-digit characters, ensure + prefix
            let digits: String = identifier.chars().filter(|c| c.is_ascii_digit()).collect();
            format!("+{}", digits)
        }
        "email" => identifier.to_lowercase().trim().to_string(),
        _ => identifier.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_did_deterministic() {
        let seed = b"test-gateway-seed-32bytes-long!!";
        let did1 = generate_shadow_did(seed, "tenant1", "+1234567890", "sms");
        let did2 = generate_shadow_did(seed, "tenant1", "+1234567890", "sms");
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_shadow_did_tenant_isolation() {
        let seed = b"test-gateway-seed-32bytes-long!!";
        let did_t1 = generate_shadow_did(seed, "tenant1", "+1234567890", "sms");
        let did_t2 = generate_shadow_did(seed, "tenant2", "+1234567890", "sms");
        assert_ne!(did_t1, did_t2);
    }

    #[test]
    fn test_phone_normalization() {
        let seed = b"test-gateway-seed-32bytes-long!!";
        let did1 = generate_shadow_did(seed, "t1", "+1 (234) 567-890", "sms");
        let did2 = generate_shadow_did(seed, "t1", "1234567890", "sms");
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_shadow_did_format() {
        let seed = b"test-gateway-seed-32bytes-long!!";
        let did = generate_shadow_did(seed, "t1", "+1234567890", "whatsapp");
        assert!(did.starts_with("did:shadow:whatsapp:"));
    }
}
