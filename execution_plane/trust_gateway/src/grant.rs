// ─────────────────────────────────────────────────────────────
// ExecutionGrant JWT issuer
//
// WS1: Supports both Ed25519 asymmetric signing (recommended)
// and HMAC-SHA256 (legacy/backward-compat).
//
// Ed25519 separates signer (gateway, holds private key) from
// verifier (executor, holds public key only). This prevents
// executors from minting their own grants.
// ─────────────────────────────────────────────────────────────

use anyhow::Result;
use jwt_simple::prelude::*;
use trust_core::action::ActionRequest;
use trust_core::grant::{ExecutionGrant, GrantClearance, SignedGrant};

// ── Ed25519 Grant Issuer (WS1: Asymmetric) ─────────────────

/// Issues ExecutionGrant JWTs using Ed25519 asymmetric signing.
///
/// The gateway holds the private key (signer). Executors hold
/// only the public key (verifier) and cannot mint grants.
pub struct Ed25519GrantIssuer {
    key_pair: Ed25519KeyPair,
    kid: String,
}

impl Ed25519GrantIssuer {
    /// Create from a PEM-encoded Ed25519 private key.
    pub fn from_pem(pem: &str, kid: String) -> Result<Self> {
        let key_pair = Ed25519KeyPair::from_pem(pem)?;
        Ok(Self { key_pair, kid })
    }

    /// Generate a new random Ed25519 key pair (for dev/testing).
    pub fn generate(kid: String) -> Self {
        let key_pair = Ed25519KeyPair::generate();
        Self { key_pair, kid }
    }

    /// Export the public key as PEM (for distributing to executors).
    pub fn public_key_pem(&self) -> String {
        self.key_pair.public_key().to_pem()
    }

    /// Export the key pair as PEM (for persistence).
    pub fn key_pair_pem(&self) -> String {
        self.key_pair.to_pem()
    }

    /// Get the Key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Issue a short-lived ExecutionGrant for a specific action.
    pub fn issue(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> Result<SignedGrant> {
        let grant_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        let grant = ExecutionGrant {
            grant_id: grant_id.clone(),
            action_id: req.action_id.clone(),
            tenant_id: req.tenant_id.clone(),
            owner_did: req.actor.owner_did.clone(),
            requester_did: req.actor.requester_did.clone(),
            allowed_action: req.action.name.clone(),
            clearance,
            expires_at,
            kid: Some(self.kid.clone()),
        };

        // Build JWT claims with kid in the header
        let claims = Claims::with_custom_claims(
            grant.clone(),
            Duration::from_secs(ttl.as_secs()),
        )
        .with_issuer("trust_gateway")
        .with_subject(&req.action_id)
        .with_jwt_id(&grant_id);

        let token = self.key_pair.sign(claims)?;

        Ok(SignedGrant {
            token,
            claims: grant,
        })
    }
}

impl trust_core::traits::GrantIssuer for Ed25519GrantIssuer {
    fn issue_execution_grant(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> std::result::Result<SignedGrant, trust_core::errors::GrantError> {
        self.issue(req, clearance, ttl)
            .map_err(|e| trust_core::errors::GrantError::SigningFailed(e.to_string()))
    }
}

// ── HMAC Grant Issuer (Legacy/Backward-Compat) ─────────────

/// Issues ExecutionGrant JWTs using HMAC-SHA256.
///
/// Kept for backward compatibility. The same signing key must be
/// shared with connectors so they can validate the grant.
///
/// **Deprecated**: Use `Ed25519GrantIssuer` for new deployments.
pub struct HmacGrantIssuer {
    key: HS256Key,
}

impl HmacGrantIssuer {
    pub fn new(secret: &str) -> Self {
        Self {
            key: HS256Key::from_bytes(secret.as_bytes()),
        }
    }

    /// Issue a short-lived ExecutionGrant for a specific action.
    pub fn issue(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> Result<SignedGrant> {
        let grant_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl.as_secs() as i64;

        let grant = ExecutionGrant {
            grant_id: grant_id.clone(),
            action_id: req.action_id.clone(),
            tenant_id: req.tenant_id.clone(),
            owner_did: req.actor.owner_did.clone(),
            requester_did: req.actor.requester_did.clone(),
            allowed_action: req.action.name.clone(),
            clearance,
            expires_at,
            kid: None,
        };

        // Build JWT claims
        let claims = Claims::with_custom_claims(
            grant.clone(),
            Duration::from_secs(ttl.as_secs()),
        )
        .with_issuer("trust_gateway")
        .with_subject(&req.action_id)
        .with_jwt_id(&grant_id);

        let token = self.key.authenticate(claims)?;

        Ok(SignedGrant {
            token,
            claims: grant,
        })
    }

    /// Validate an ExecutionGrant JWT and return the claims.
    pub fn validate(&self, token: &str) -> Result<ExecutionGrant> {
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };
        let claims = self.key.verify_token::<ExecutionGrant>(token, Some(options))?;
        Ok(claims.custom)
    }
}

impl trust_core::traits::GrantIssuer for HmacGrantIssuer {
    fn issue_execution_grant(
        &self,
        req: &ActionRequest,
        clearance: GrantClearance,
        ttl: std::time::Duration,
    ) -> std::result::Result<SignedGrant, trust_core::errors::GrantError> {
        self.issue(req, clearance, ttl)
            .map_err(|e| trust_core::errors::GrantError::SigningFailed(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────
// Unit Tests — Grant Issuance (Security-Critical)
//
// These tests validate the cryptographic integrity of the
// ExecutionGrant JWT lifecycle. Grant forgery or validation
// bypass would constitute a full system compromise.
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use trust_core::action::{ActionDescriptor, ActionRequest, OperationKind};
    use trust_core::actor::{ActorContext, AuthLevel, SourceContext};
    use trust_core::grant::GrantClearance;
    use trust_core::traits::GrantIssuer;

    /// Build a deterministic ActionRequest for tests.
    fn test_action_request() -> ActionRequest {
        ActionRequest {
            action_id: "test-action-001".into(),
            tenant_id: "tenant-abc".into(),
            actor: ActorContext {
                owner_did: "did:twin:owner123".into(),
                requester_did: "did:twin:agent456".into(),
                user_did: None,
                session_jti: "session-jti-789".into(),
                auth_level: AuthLevel::Session,
            },
            source: SourceContext::ssi_agent(),
            action: ActionDescriptor {
                name: "google.calendar.event.create".into(),
                category: "scheduling".into(),
                resource: None,
                operation: OperationKind::Create,
                amount: None,
                arguments: serde_json::json!({"summary": "Test Event"}),
                tags: vec!["mutation".into()],
            },
        }
    }

    // ── Ed25519 Tests ───────────────────────────────────────

    #[test]
    fn ed25519_grant_round_trip() {
        let issuer = Ed25519GrantIssuer::generate("test-kid-1".into());
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::AutoApproved, ttl)
            .expect("Ed25519 issue should succeed");

        // Verify with the public key
        let pub_key = issuer.key_pair.public_key();
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };
        let verified = pub_key.verify_token::<ExecutionGrant>(&signed.token, Some(options))
            .expect("Ed25519 verification should succeed");

        assert_eq!(verified.custom.action_id, "test-action-001");
        assert_eq!(verified.custom.tenant_id, "tenant-abc");
        assert_eq!(verified.custom.allowed_action, "google.calendar.event.create");
    }

    #[test]
    fn ed25519_grant_rejects_tampered_token() {
        let issuer = Ed25519GrantIssuer::generate("test-kid-2".into());
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::HumanApproved, ttl)
            .expect("Ed25519 issue should succeed");

        // Tamper with the token (flip a character in the signature)
        let mut tampered = signed.token.clone();
        let bytes = unsafe { tampered.as_bytes_mut() };
        if let Some(last) = bytes.last_mut() {
            *last = if *last == b'A' { b'B' } else { b'A' };
        }

        let pub_key = issuer.key_pair.public_key();
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&["trust_gateway"])),
            ..Default::default()
        };
        let result = pub_key.verify_token::<ExecutionGrant>(&tampered, Some(options));
        assert!(result.is_err(), "Tampered Ed25519 token must be rejected");
    }

    #[test]
    fn ed25519_grant_different_key_rejects() {
        let issuer = Ed25519GrantIssuer::generate("kid-signer".into());
        let other = Ed25519GrantIssuer::generate("kid-other".into());
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::AutoApproved, ttl)
            .expect("Ed25519 issue should succeed");

        // Verify with a DIFFERENT public key — must fail
        let wrong_pub = other.key_pair.public_key();
        let result = wrong_pub.verify_token::<ExecutionGrant>(&signed.token, None);
        assert!(result.is_err(), "Ed25519 grant verified with wrong key must be rejected");
    }

    #[test]
    fn ed25519_grant_contains_correct_claims() {
        let issuer = Ed25519GrantIssuer::generate("kid-claims".into());
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(60);

        let signed = issuer.issue(&req, GrantClearance::ProofVerified, ttl)
            .expect("Ed25519 issue should succeed");

        let grant = &signed.claims;
        assert_eq!(grant.action_id, "test-action-001");
        assert_eq!(grant.tenant_id, "tenant-abc");
        assert_eq!(grant.owner_did, "did:twin:owner123");
        assert_eq!(grant.requester_did, "did:twin:agent456");
        assert_eq!(grant.allowed_action, "google.calendar.event.create");
        assert_eq!(grant.clearance, GrantClearance::ProofVerified);
        assert_eq!(grant.kid, Some("kid-claims".into()));
        assert!(!grant.grant_id.is_empty(), "grant_id must be generated");
        assert!(grant.expires_at > chrono::Utc::now().timestamp(), "expires_at must be in the future");
    }

    #[test]
    fn ed25519_pem_round_trip() {
        let issuer = Ed25519GrantIssuer::generate("kid-pem".into());
        let pem = issuer.key_pair_pem();

        // Re-create from PEM — must succeed
        let restored = Ed25519GrantIssuer::from_pem(&pem, "kid-pem".into())
            .expect("PEM round-trip should succeed");

        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);
        let signed = restored.issue(&req, GrantClearance::AutoApproved, ttl)
            .expect("Issue from restored key should succeed");

        // Verify with original public key
        let pub_key = issuer.key_pair.public_key();
        let result = pub_key.verify_token::<ExecutionGrant>(&signed.token, None);
        assert!(result.is_ok(), "Token from restored PEM key must verify with original public key");
    }

    // ── HMAC Tests ──────────────────────────────────────────

    #[test]
    fn hmac_grant_round_trip() {
        let issuer = HmacGrantIssuer::new("test-secret-32-bytes-minimum-ok!");
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::AutoApproved, ttl)
            .expect("HMAC issue should succeed");

        let validated = issuer.validate(&signed.token)
            .expect("HMAC validation with same key should succeed");

        assert_eq!(validated.action_id, "test-action-001");
        assert_eq!(validated.tenant_id, "tenant-abc");
    }

    #[test]
    fn hmac_grant_rejects_wrong_key() {
        let issuer = HmacGrantIssuer::new("correct-secret-key");
        let wrong = HmacGrantIssuer::new("wrong-secret-key!!");
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::HumanApproved, ttl)
            .expect("HMAC issue should succeed");

        let result = wrong.validate(&signed.token);
        assert!(result.is_err(), "HMAC grant validated with wrong key must be rejected");
    }

    #[test]
    fn hmac_grant_kid_is_none() {
        let issuer = HmacGrantIssuer::new("test-secret-32-bytes-minimum-ok!");
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let signed = issuer.issue(&req, GrantClearance::AutoApproved, ttl)
            .expect("HMAC issue should succeed");

        // HMAC grants don't carry a kid (symmetric — no key rotation)
        assert_eq!(signed.claims.kid, None);
    }

    // ── Trait Interface Tests ───────────────────────────────

    #[test]
    fn ed25519_trait_issue_succeeds() {
        let issuer = Ed25519GrantIssuer::generate("kid-trait".into());
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let result = issuer.issue_execution_grant(&req, GrantClearance::AutoApproved, ttl);
        assert!(result.is_ok(), "Ed25519 trait interface should succeed");
    }

    #[test]
    fn hmac_trait_issue_succeeds() {
        let issuer = HmacGrantIssuer::new("trait-test-secret");
        let req = test_action_request();
        let ttl = std::time::Duration::from_secs(30);

        let result = issuer.issue_execution_grant(&req, GrantClearance::ElevatedApproval, ttl);
        assert!(result.is_ok(), "HMAC trait interface should succeed");
    }
}
