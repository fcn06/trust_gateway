use crate::did_resolver::DidResolver;
use crate::traits::{EngineError, NonceStore};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use trust_sdk::envelope::ServiceRequestEnvelope;

/// Verifies an incoming ServiceRequestEnvelope against audience, freshness, body digest, replay, and Ed25519 signature.
pub async fn verify_service_request_envelope(
    envelope: &ServiceRequestEnvelope,
    expected_audience: &str,
    raw_body: &[u8],
    nonce_store: &dyn NonceStore,
    did_resolver: &dyn DidResolver,
) -> Result<(), EngineError> {
    // 1. Audience verification
    if envelope.audience.trim_end_matches('/') != expected_audience.trim_end_matches('/') {
        return Err(EngineError::AuthError(format!(
            "Audience mismatch: expected '{}', got '{}'",
            expected_audience, envelope.audience
        )));
    }

    // 2. Freshness & TTL verification (OB-INV-07: max 30s TTL, 5s clock skew grace)
    let now = chrono::Utc::now().timestamp() as u64;
    let grace_secs = 5;

    if now + grace_secs < envelope.iat {
        return Err(EngineError::AuthError(format!(
            "Premature envelope: iat {} > now {}",
            envelope.iat, now
        )));
    }

    if now > envelope.exp + grace_secs {
        return Err(EngineError::AuthError(format!(
            "Expired envelope: exp {} < now {}",
            envelope.exp, now
        )));
    }

    let requested_ttl = envelope.exp.saturating_sub(envelope.iat);
    if requested_ttl > 30 {
        return Err(EngineError::AuthError(format!(
            "Envelope TTL {}s exceeds maximum allowed 30s",
            requested_ttl
        )));
    }

    // 3. Body SHA-256 integrity check
    let mut hasher = Sha256::new();
    hasher.update(raw_body);
    let computed_hash = format!("{:x}", hasher.finalize());

    if computed_hash != envelope.body_sha256.to_lowercase() {
        return Err(EngineError::AuthError(format!(
            "Body SHA-256 mismatch: expected '{}', computed '{}'",
            envelope.body_sha256, computed_hash
        )));
    }

    // 4. Replay protection (consume nonce via NonceStore)
    nonce_store
        .consume_nonce(&envelope.caller_did, &envelope.jti, 30)
        .await?;

    // 5. Cryptographic signature verification over RFC 8785 canonical envelope
    let pubkey_bytes = did_resolver
        .resolve_ed25519_key(&envelope.caller_did)
        .await?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        EngineError::AuthError(format!("Malformed Ed25519 public key from DID: {e}"))
    })?;

    envelope
        .verify_signature(&verifying_key)
        .map_err(|e| EngineError::AuthError(format!("Envelope signature verification failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_resolver::CachedDidResolver;
    use crate::local_adapters::memory_nonce::InMemoryNonceStore;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use trust_sdk::did::create_did_key_from_seed;

    #[tokio::test]
    async fn test_verify_envelope_full_lifecycle_and_negative_cases() {
        let seed = [33u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let identity = create_did_key_from_seed(seed);

        let did_resolver = Arc::new(CachedDidResolver::new());
        let nonce_store = Arc::new(InMemoryNonceStore::new());

        let raw_body = b"{\"action\": \"test_triage\"}";
        let mut hasher = Sha256::new();
        hasher.update(raw_body);
        let body_hash = format!("{:x}", hasher.finalize());

        let now = chrono::Utc::now().timestamp() as u64;
        let mut envelope = ServiceRequestEnvelope::new(
            &identity.did,
            "http://127.0.0.1:4015",
            "POST",
            "/v1/triage/evaluate",
            &body_hash,
            now,
            now + 25,
            "jti_mesh_001",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .unwrap();

        envelope.sign(&signing_key);

        // 1. Success verification
        let res = verify_service_request_envelope(
            &envelope,
            "http://127.0.0.1:4015",
            raw_body,
            nonce_store.as_ref(),
            did_resolver.as_ref(),
        )
        .await;
        assert!(res.is_ok());

        // 2. Replay rejection (same jti and caller_did)
        let replay_res = verify_service_request_envelope(
            &envelope,
            "http://127.0.0.1:4015",
            raw_body,
            nonce_store.as_ref(),
            did_resolver.as_ref(),
        )
        .await;
        assert!(matches!(replay_res, Err(EngineError::ReplayDetected(_))));

        // 3. Audience mismatch rejection
        let mut env_wrong_aud = envelope.clone();
        env_wrong_aud.jti = "jti_mesh_002".to_string();
        env_wrong_aud.sign(&signing_key);

        let aud_res = verify_service_request_envelope(
            &env_wrong_aud,
            "http://wrong-audience:8080",
            raw_body,
            nonce_store.as_ref(),
            did_resolver.as_ref(),
        )
        .await;
        assert!(matches!(aud_res, Err(EngineError::AuthError(_))));

        // 4. Body mismatch rejection
        let mut env_body_test = envelope.clone();
        env_body_test.jti = "jti_mesh_003".to_string();
        env_body_test.sign(&signing_key);

        let body_res = verify_service_request_envelope(
            &env_body_test,
            "http://127.0.0.1:4015",
            b"{\"tampered\": true}",
            nonce_store.as_ref(),
            did_resolver.as_ref(),
        )
        .await;
        assert!(matches!(body_res, Err(EngineError::AuthError(_))));
    }
}

