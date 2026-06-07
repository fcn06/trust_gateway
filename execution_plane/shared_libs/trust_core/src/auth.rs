// ─────────────────────────────────────────────────────────────
// Auth Types — RawCredential, VerifiedJwt, TokenClass
//
// REC-3: Centralized Auth Verification Types
//
// These types establish the type-safe auth boundary:
// - RawCredential: All transport forms for incoming credentials
// - VerifiedJwt: Opaque proof of cryptographic verification
// - TokenClass: Mutually exclusive JWT categories
// - AuthError: Structured authentication failure reasons
//
// The AuthVerifier (implemented in trust_auth / trust_gateway)
// is the ONLY constructor path for VerifiedJwt.
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// All possible transport forms for an incoming credential.
/// The AuthVerifier accepts ONLY this enum — never raw strings.
///
/// REC-3: This ensures credential extraction is uniform regardless
/// of whether the request arrives via HTTP header, NATS message body,
/// or REST body field.
#[derive(Debug, Clone)]
pub enum RawCredential {
    /// `Authorization: Bearer <token>` HTTP header
    BearerHeader(String),
    /// `_meta.io.lianxi.session_jwt` field in NATS message body
    MetaWrapped(serde_json::Value),
    /// Legacy REST body field containing a raw JWT string
    BodyField(String),
}

/// JWT class — session vs execution grant. Mutually exclusive.
///
/// Session JWTs authenticate users/agents at the gateway ingress.
/// ExecutionGrant JWTs authorize specific tool invocations at executor ingress.
/// A Session JWT presented to an executor MUST be rejected, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenClass {
    /// typ = "lianxi.session+jwt", aud = "trust-gateway"
    Session,
    /// typ = "lianxi.execution-grant+jwt", aud = "executor-host"
    ExecutionGrant,
}

impl std::fmt::Display for TokenClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "lianxi.session+jwt"),
            Self::ExecutionGrant => write!(f, "lianxi.execution-grant+jwt"),
        }
    }
}

/// Authentication-level hierarchy (mirrors ActorContext::AuthLevel).
///
/// Levels are strictly ordered: higher levels subsume lower ones.
/// WebAuthn (L5) > VP (L4) > Session (L3) > API Key (L2) > Anonymous (L1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerifiedAuthLevel {
    /// Anonymous / unauthenticated
    Level1Anonymous = 1,
    /// API key or OAuth client credentials
    Level2ApiKey = 2,
    /// Standard JWT session (password-based)
    Level3Session = 3,
    /// Verifiable Presentation verified
    Level4Vp = 4,
    /// WebAuthn/FIDO2 verified
    Level5WebAuthn = 5,
}

/// Opaque proof that a JWT was cryptographically verified.
///
/// Inner claims are private — callers cannot construct this
/// without passing through `AuthVerifier::verify()`.
///
/// This type is the ONLY way to prove authentication in downstream
/// domain/application services. Passing raw JWT claims is forbidden
/// per RULE 010_JWT_CONTRACTS.md.
#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    /// Private — only accessible via accessor methods.
    tenant_id: String,
    subject: String,
    auth_level: VerifiedAuthLevel,
    session_jti: String,
    token_class: TokenClass,
    /// Raw expiration timestamp (Unix epoch seconds).
    expires_at: i64,
}

impl VerifiedJwt {
    /// Create a new VerifiedJwt. This MUST only be called by
    /// AuthVerifier::verify() after full cryptographic validation.
    ///
    /// # Safety Contract
    /// Calling this without prior signature verification violates
    /// the trust boundary. Only the `auth` crate should call this.
    pub fn new(
        tenant_id: String,
        subject: String,
        auth_level: VerifiedAuthLevel,
        session_jti: String,
        token_class: TokenClass,
        expires_at: i64,
    ) -> Self {
        Self {
            tenant_id,
            subject,
            auth_level,
            session_jti,
            token_class,
            expires_at,
        }
    }

    pub fn tenant_id(&self) -> &str { &self.tenant_id }
    pub fn subject(&self) -> &str { &self.subject }
    pub fn auth_level(&self) -> VerifiedAuthLevel { self.auth_level }
    pub fn session_jti(&self) -> &str { &self.session_jti }
    pub fn token_class(&self) -> TokenClass { self.token_class }
    pub fn expires_at(&self) -> i64 { self.expires_at }

    /// Check if this token has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }
}

/// Structured authentication error.
///
/// These variants replace generic anyhow errors for auth failures,
/// enabling callers to make policy decisions based on failure type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No credential found in the request.
    MissingCredential,
    /// The JWT signature could not be verified.
    InvalidSignature,
    /// The JWT has expired (`exp` claim).
    Expired,
    /// The JWT is not yet valid (`nbf` claim).
    NotYetValid,
    /// The JWT audience (`aud`) does not match the expected value.
    AudienceMismatch,
    /// The JWT issuer (`iss`) is not trusted.
    UntrustedIssuer,
    /// The JWT uses `alg=none` — always rejected.
    AlgorithmNone,
    /// A Session JWT was presented where an ExecutionGrant was expected,
    /// or vice versa.
    WrongTokenClass {
        expected: TokenClass,
        actual: TokenClass,
    },
    /// Multiple credential sources (header + body + `_meta`) present
    /// and they resolve to different identities.
    ConflictingCredentials,
    /// Generic internal error during verification.
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredential => write!(f, "No credential found in request"),
            Self::InvalidSignature => write!(f, "JWT signature verification failed"),
            Self::Expired => write!(f, "JWT has expired"),
            Self::NotYetValid => write!(f, "JWT is not yet valid (nbf)"),
            Self::AudienceMismatch => write!(f, "JWT audience does not match"),
            Self::UntrustedIssuer => write!(f, "JWT issuer is not trusted"),
            Self::AlgorithmNone => write!(f, "alg=none is not accepted"),
            Self::WrongTokenClass { expected, actual } => {
                write!(f, "Expected {} but received {}", expected, actual)
            }
            Self::ConflictingCredentials => {
                write!(f, "Multiple conflicting credential sources detected")
            }
            Self::Internal(msg) => write!(f, "Internal auth error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_jwt_accessors() {
        let jwt = VerifiedJwt::new(
            "tenant-abc".into(),
            "did:twin:user123".into(),
            VerifiedAuthLevel::Level3Session,
            "jti-456".into(),
            TokenClass::Session,
            chrono::Utc::now().timestamp() + 3600,
        );

        assert_eq!(jwt.tenant_id(), "tenant-abc");
        assert_eq!(jwt.subject(), "did:twin:user123");
        assert_eq!(jwt.auth_level(), VerifiedAuthLevel::Level3Session);
        assert_eq!(jwt.session_jti(), "jti-456");
        assert_eq!(jwt.token_class(), TokenClass::Session);
        assert!(!jwt.is_expired());
    }

    #[test]
    fn expired_jwt_detected() {
        let jwt = VerifiedJwt::new(
            "t".into(),
            "s".into(),
            VerifiedAuthLevel::Level1Anonymous,
            "j".into(),
            TokenClass::Session,
            0, // epoch — expired
        );
        assert!(jwt.is_expired());
    }

    #[test]
    fn token_class_display() {
        assert_eq!(TokenClass::Session.to_string(), "lianxi.session+jwt");
        assert_eq!(
            TokenClass::ExecutionGrant.to_string(),
            "lianxi.execution-grant+jwt"
        );
    }

    #[test]
    fn auth_error_display() {
        let err = AuthError::WrongTokenClass {
            expected: TokenClass::Session,
            actual: TokenClass::ExecutionGrant,
        };
        assert!(err.to_string().contains("lianxi.session+jwt"));
        assert!(err.to_string().contains("lianxi.execution-grant+jwt"));
    }

    #[test]
    fn auth_level_ordering() {
        assert!(VerifiedAuthLevel::Level5WebAuthn > VerifiedAuthLevel::Level3Session);
        assert!(VerifiedAuthLevel::Level3Session > VerifiedAuthLevel::Level1Anonymous);
    }

    #[test]
    fn conflicting_credentials_error() {
        let err = AuthError::ConflictingCredentials;
        assert!(err.to_string().contains("conflicting"));
    }
}
