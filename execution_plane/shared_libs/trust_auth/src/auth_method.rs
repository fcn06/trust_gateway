// Re-export AuthMethod from trust_core
pub use trust_core::actor::AuthMethod;

/// The raw authentication input to be resolved into an IdentityContext.
#[derive(Debug, Clone)]
pub enum RawAuthInput {
    /// A raw JWT token (could be HMAC, EdDSA, or WebAuthn derived).
    Jwt(String),
    /// An API key passed via header.
    ApiKey(String),
    /// An OAuth2 bearer token.
    OAuth2Bearer(String),
    /// A DID-comm / VP token.
    VerifiablePresentation(String),
}
