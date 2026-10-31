use crate::canonical::canonical_json;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("Envelope signature error: {0}")]
    SignatureError(String),
    #[error("Envelope verification failed")]
    VerificationFailed,
    #[error("TTL exceeds maximum allowed {max}s: requested {requested}s")]
    TtlExceeded { requested: u64, max: u64 },
    #[error("Envelope expired: exp {exp} < now {now}")]
    Expired { exp: u64, now: u64 },
    #[error("Envelope used before iat: iat {iat} > now {now}")]
    Premature { iat: u64, now: u64 },
    #[error("Audience mismatch: expected '{expected}', got '{actual}'")]
    AudienceMismatch { expected: String, actual: String },
    #[error("Body SHA-256 hash mismatch: expected '{expected}', computed '{actual}'")]
    BodyHashMismatch { expected: String, actual: String },
}

/// Zero-Trust Inter-Tier Service Request Envelope (OB-INV-07, OB-INV-11)
/// Strictly pure model with no async, networking, or database dependencies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRequestEnvelope {
    pub caller_did: String,
    pub audience: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub traceparent: String,
    #[serde(default)]
    pub signature: String,
}

impl ServiceRequestEnvelope {
    /// Construct a new unsigned envelope
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        caller_did: impl Into<String>,
        audience: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        body_sha256: impl Into<String>,
        iat: u64,
        exp: u64,
        jti: impl Into<String>,
        traceparent: impl Into<String>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = Self {
            caller_did: caller_did.into(),
            audience: audience.into(),
            method: method.into().to_uppercase(),
            path: path.into(),
            body_sha256: body_sha256.into().to_lowercase(),
            iat,
            exp,
            jti: jti.into(),
            traceparent: traceparent.into(),
            signature: String::new(),
        };

        // Enforce maximum 30 seconds TTL invariant
        envelope.validate_ttl(30)?;
        Ok(envelope)
    }

    /// Maximum TTL check (maximum 30 seconds)
    pub fn validate_ttl(&self, max_ttl_secs: u64) -> Result<(), EnvelopeError> {
        let requested = self.exp.saturating_sub(self.iat);
        if requested > max_ttl_secs {
            return Err(EnvelopeError::TtlExceeded {
                requested,
                max: max_ttl_secs,
            });
        }
        Ok(())
    }

    /// Canonical RFC 8785 representation of the signable envelope payload
    pub fn canonical_signable_payload(&self) -> String {
        let value = serde_json::json!({
            "caller_did": self.caller_did,
            "audience": self.audience,
            "method": self.method,
            "path": self.path,
            "body_sha256": self.body_sha256,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "traceparent": self.traceparent,
        });
        canonical_json(&value)
    }

    /// Sign the canonical envelope with a detached Ed25519 signature
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let payload = self.canonical_signable_payload();
        let sig = signing_key.sign(payload.as_bytes());
        self.signature = hex::encode(sig.to_bytes());
    }

    /// Verify the detached Ed25519 signature against a public key
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), EnvelopeError> {
        if self.signature.is_empty() {
            return Err(EnvelopeError::SignatureError("Empty signature".to_string()));
        }

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| EnvelopeError::SignatureError(format!("Invalid hex signature: {e}")))?;

        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| EnvelopeError::SignatureError(format!("Malformed Ed25519 signature: {e}")))?;

        let payload = self.canonical_signable_payload();
        verifying_key
            .verify(payload.as_bytes(), &sig)
            .map_err(|_| EnvelopeError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_envelope_sign_and_verify_roundtrip() {
        let seed = [77u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut envelope = ServiceRequestEnvelope::new(
            "did:key:z6Mku...test",
            "http://127.0.0.1:4015",
            "POST",
            "/v1/triage/evaluate",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            1000,
            1030,
            "jti_test_123",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .expect("Envelope creation must succeed");

        assert!(envelope.signature.is_empty());
        envelope.sign(&signing_key);
        assert!(!envelope.signature.is_empty());

        // Verification with correct key succeeds
        assert!(envelope.verify_signature(&verifying_key).is_ok());

        // Negative test 1: wrong key
        let wrong_key = SigningKey::from_bytes(&[88u8; 32]).verifying_key();
        assert_eq!(
            envelope.verify_signature(&wrong_key),
            Err(EnvelopeError::VerificationFailed)
        );

        // Negative test 2: tampered payload
        let mut tampered = envelope.clone();
        tampered.path = "/v1/triage/tampered".to_string();
        assert_eq!(
            tampered.verify_signature(&verifying_key),
            Err(EnvelopeError::VerificationFailed)
        );
    }

    #[test]
    fn test_service_envelope_enforces_max_30s_ttl() {
        let res = ServiceRequestEnvelope::new(
            "did:key:test",
            "http://127.0.0.1:4015",
            "POST",
            "/v1/triage/evaluate",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            1000,
            1031, // 31 seconds TTL -> must reject!
            "jti_over_ttl",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        );

        assert!(matches!(res, Err(EnvelopeError::TtlExceeded { requested: 31, max: 30 })));
    }
}

