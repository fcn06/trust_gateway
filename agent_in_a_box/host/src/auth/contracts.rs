use crate::dto::MyClaims;

/// Error types for authentication and JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Missing token")]
    MissingToken,
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// A wrapper for a verified JWT and its associated claims.
#[derive(Debug, Clone)]
pub struct VerifiedJwt {
    claims: MyClaims,
    jwt_id: Option<String>,
}

impl VerifiedJwt {
    pub(crate) fn new(claims: MyClaims, jwt_id: Option<String>) -> Self {
        Self { claims, jwt_id }
    }

    pub fn claims(&self) -> &MyClaims {
        &self.claims
    }

    pub fn jwt_id(&self) -> Option<&str> {
        self.jwt_id.as_deref()
    }
}

/// Core interface for authentication verification.
///
/// Follows the 010_JWT_CONTRACTS rule: verified JWTs must be wrapped in 
/// a structured type and decoded via this unified interface.
pub trait AuthVerifier: Send + Sync {
    /// Verifies a raw JWT string and returns a structured result.
    fn verify(&self, token: &str) -> Result<VerifiedJwt, AuthError>;
}
