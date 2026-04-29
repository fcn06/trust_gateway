// ─────────────────────────────────────────────────────────────
// identity_context — Identity extraction, verification, and
//                    _meta validation
//
// Spec reference: §6 (domain model), §17 (_meta extraction),
//                 §18 (source registry)
//
// This crate provides transport-neutral identity primitives:
// - JWT verification (AuthVerifier trait, VerifiedJwt container)
// - _meta extraction, validation, and stripping
// - SourceContext for external swarm registration
// - ProposedAction as the unified pre-policy structure
//
// RULE[010_JWT_CONTRACTS.md]: All domain logic MUST receive
// identity via `VerifiedJwt`. The legacy `decode_jwt_claims`
// function is retained ONLY for audit logging of rejected tokens.
// ─────────────────────────────────────────────────────────────

pub mod models;
pub mod meta;
pub mod jwt;
pub mod source;
pub mod did;

// Re-export key types at crate root.
pub use models::{IdentityContext, ProposedAction, TransportKind};
pub use meta::{MetaPayload, extract_meta, strip_meta, validate_tenant_consistency};
pub use jwt::{
    // Verification types (preferred — RULE[010_JWT_CONTRACTS.md])
    AuthVerifier, AuthVerifyError, HmacAuthVerifier, VerifiedJwt,
    // Claims type
    JwtClaims,
    // Legacy introspection (audit-only — do NOT use for domain logic)
    decode_jwt_claims, extract_dids_from_jwt, extract_tenant_id_from_jwt, extract_jti_from_jwt,
};
pub use source::{SourceRegistration, SourceType, AuthMode};
pub use did::*;
