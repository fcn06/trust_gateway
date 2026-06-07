use crate::dto::MyClaims;
use super::contracts::{AuthVerifier, VerifiedJwt, AuthError};
use jwt_simple::prelude::*;

/// Secure envelope for sensitive authentication credentials.
///
/// Centralizes management of JWT keys and service tokens.
pub struct AuthVault {
    jwt_key: HS256Key,
    ed25519_key: Option<Ed25519KeyPair>,
}

impl AuthVault {
    /// Initialize the vault with a raw key seed.
    pub fn new(jwt_key_bytes: &[u8]) -> Self {
        // Optional: load Ed25519 key if provided in env
        let ed25519_key = std::env::var("HOST_ED25519_KEY_PEM")
            .ok()
            .and_then(|pem| Ed25519KeyPair::from_pem(&pem).ok());

        Self {
            jwt_key: HS256Key::from_bytes(jwt_key_bytes),
            ed25519_key,
        }
    }

    /// Issue a new session token. 
    /// Defaults to HS256 for local sessions unless Ed25519 is specifically requested.
    pub fn issue_token(&self, jwt_claims: JWTClaims<MyClaims>) -> String {
        self.jwt_key.authenticate(jwt_claims).unwrap_or_else(|_| "error".to_string())
    }

    fn map_claims(&self, claims: JWTClaims<MyClaims>) -> VerifiedJwt {
        let mut custom = claims.custom;
        custom.jti = claims.jwt_id.clone();
        
        VerifiedJwt::new(custom, claims.jwt_id)
    }
}

impl AuthVerifier for AuthVault {
    fn verify(&self, token: &str) -> Result<VerifiedJwt, AuthError> {
        // 1. Try HMAC (HS256) - standard for local sessions
        if let Ok(claims) = self.jwt_key.verify_token::<MyClaims>(token, None) {
            return Ok(self.map_claims(claims));
        }

        // 2. Try Ed25519 if available (cross-node/production)
        if let Some(ref key) = self.ed25519_key {
            if let Ok(claims) = key.public_key().verify_token::<MyClaims>(token, None) {
                return Ok(self.map_claims(claims));
            }
        }

        Err(AuthError::InvalidToken("JWT signature verification failed for all available keys".to_string()))
    }
}
