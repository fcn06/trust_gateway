// ─────────────────────────────────────────────────────────────
// WebAuthn Session JWT — Phase 5
//
// Defines the enriched Session JWT claims that the Host mints
// after WebAuthn authentication. These JWTs carry:
//   - `amr`: Authentication Methods References (RFC 8176)
//   - `auth_level`: Numeric auth strength (1-5)
//   - `aud`: Intended audiences (ssi_agent, trust_gateway)
//
// This model is used by both the Host (minting) and the
// trust_auth AuthResolver (validation/extraction).
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Enriched session JWT claims minted by the Host after authentication.
///
/// Standard JWT claims (`iss`, `sub`, `exp`, `nbf`, `aud`, `jti`) are
/// handled by the JWT library. This struct carries the custom claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Tenant namespace.
    pub tenant_id: String,

    /// Authentication Methods References (RFC 8176).
    /// Examples: `["webauthn"]`, `["pwd", "otp"]`, `["hwk"]`.
    #[serde(default)]
    pub amr: Vec<String>,

    /// Numeric authentication strength (1-5).
    /// Maps directly to `trust_core::actor::AuthLevel`.
    #[serde(default = "default_auth_level")]
    pub auth_level: u8,

    /// DID of the resource owner (same as JWT `iss`).
    #[serde(default)]
    pub owner_did: Option<String>,
}

fn default_auth_level() -> u8 {
    3 // Level3Session
}

impl SessionClaims {
    /// Derive the AuthLevel enum from the numeric value.
    pub fn to_auth_level(&self) -> trust_core::actor::AuthLevel {
        match self.auth_level {
            1 => trust_core::actor::AuthLevel::Level1ApiKey,
            2 => trust_core::actor::AuthLevel::Level2Bearer,
            3 => trust_core::actor::AuthLevel::Level3Session,
            4 => trust_core::actor::AuthLevel::Level4Verified,
            5 => trust_core::actor::AuthLevel::Level5WebAuthn,
            _ => {
                tracing::warn!(
                    "Unknown auth_level {} — defaulting to Level3Session",
                    self.auth_level
                );
                trust_core::actor::AuthLevel::Level3Session
            }
        }
    }

    /// Check if the session was authenticated with WebAuthn.
    pub fn is_webauthn(&self) -> bool {
        self.amr.iter().any(|m| m == "webauthn" || m == "hwk")
    }

    /// Check if the session used multi-factor authentication.
    pub fn is_mfa(&self) -> bool {
        self.amr.len() >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_session_claims() {
        let claims = SessionClaims {
            tenant_id: "tenant-1".to_string(),
            amr: vec!["webauthn".to_string()],
            auth_level: 5,
            owner_did: Some("did:twin:zowner".to_string()),
        };
        assert!(claims.is_webauthn());
        assert!(!claims.is_mfa());
        assert_eq!(
            claims.to_auth_level(),
            trust_core::actor::AuthLevel::Level5WebAuthn
        );
    }

    #[test]
    fn test_password_otp_session_claims() {
        let claims = SessionClaims {
            tenant_id: "tenant-1".to_string(),
            amr: vec!["pwd".to_string(), "otp".to_string()],
            auth_level: 3,
            owner_did: None,
        };
        assert!(!claims.is_webauthn());
        assert!(claims.is_mfa());
        assert_eq!(
            claims.to_auth_level(),
            trust_core::actor::AuthLevel::Level3Session
        );
    }

    #[test]
    fn test_default_auth_level() {
        let json = r#"{"tenant_id": "t1", "amr": []}"#;
        let claims: SessionClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.auth_level, 3);
        assert_eq!(
            claims.to_auth_level(),
            trust_core::actor::AuthLevel::Level3Session
        );
    }

    #[test]
    fn test_unknown_auth_level_fallback() {
        let claims = SessionClaims {
            tenant_id: "t1".to_string(),
            amr: vec![],
            auth_level: 99,
            owner_did: None,
        };
        assert_eq!(
            claims.to_auth_level(),
            trust_core::actor::AuthLevel::Level3Session
        );
    }

    #[test]
    fn test_serde_round_trip() {
        let claims = SessionClaims {
            tenant_id: "tenant-x".to_string(),
            amr: vec!["webauthn".to_string()],
            auth_level: 5,
            owner_did: Some("did:twin:zowner".to_string()),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let decoded: SessionClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tenant_id, "tenant-x");
        assert_eq!(decoded.amr, vec!["webauthn"]);
        assert_eq!(decoded.auth_level, 5);
    }
}
