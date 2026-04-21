// ─────────────────────────────────────────────────────────────
// Error types for trust_core traits
//
// Each trait has its own error type so implementations can
// map their internal errors cleanly.
// ─────────────────────────────────────────────────────────────

use thiserror::Error;

/// Error from the PolicyEngine.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy configuration error: {0}")]
    Configuration(String),
    #[error("policy evaluation failed: {0}")]
    Evaluation(String),
    #[error("unknown action: {action_name}")]
    UnknownAction { action_name: String },
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Error from the ApprovalStore.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("approval not found: {id}")]
    NotFound { id: String },
    #[error("approval already resolved: {id}")]
    AlreadyResolved { id: String },
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("concurrency conflict on key {key}: expected revision {expected}, found {found}")]
    ConcurrencyConflict { key: String, expected: u64, found: u64 },
    #[error("invalid state transition for {id}: {from} → {to}")]
    InvalidTransition { id: String, from: String, to: String },
}

/// Error from the GrantIssuer.
#[derive(Debug, Error)]
pub enum GrantError {
    #[error("JWT signing failed: {0}")]
    SigningFailed(String),
    #[error("key not available: {0}")]
    KeyUnavailable(String),
    #[error("invalid grant request: {0}")]
    InvalidRequest(String),
}

/// Error from a Connector.
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("connector not found for action: {action_name}")]
    NotFound { action_name: String },
    #[error("execution grant validation failed: {0}")]
    GrantValidationFailed(String),
    #[error("upstream service error: {0}")]
    Upstream(String),
    #[error("timeout executing action: {action_name}")]
    Timeout { action_name: String },
    #[error("connector error: {0}")]
    Internal(String),
}

/// Error from the ProofVerifier (OID4VP).
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("failed to create proof challenge: {0}")]
    ChallengeCreation(String),
    #[error("VP verification failed: {0}")]
    VerificationFailed(String),
    #[error("proof session not found: {session_id}")]
    SessionNotFound { session_id: String },
    #[error("proof session expired: {session_id}")]
    SessionExpired { session_id: String },
    #[error("invalid VP token: {0}")]
    InvalidToken(String),
    #[error("required claims not satisfied: {missing:?}")]
    ClaimsNotSatisfied { missing: Vec<String> },
    #[error("proof error: {0}")]
    Internal(String),
}

/// Error from the AuditSink.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to publish audit event: {0}")]
    PublishFailed(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Error from the NonceStore (JTI replay prevention).
#[derive(Debug, Error)]
pub enum NonceError {
    #[error("JTI already consumed: {jti}")]
    AlreadyConsumed { jti: String },
    #[error("nonce store backend error: {0}")]
    Backend(String),
}
