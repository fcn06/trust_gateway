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

pub mod did;
pub mod jwt;
pub mod meta;
pub mod models;
pub mod source;

// Re-export key types at crate root.
pub use did::*;
pub use jwt::{
    // Legacy introspection (audit-only — do NOT use for domain logic)
    decode_jwt_claims,
    extract_dids_from_jwt,
    extract_jti_from_jwt,
    extract_tenant_id_from_jwt,
    // Verification types (preferred — RULE[010_JWT_CONTRACTS.md])
    AuthVerifier,
    AuthVerifyError,
    HmacAuthVerifier,
    // Claims type
    JwtClaims,
    VerifiedJwt,
};
pub use meta::{extract_meta, strip_meta, validate_tenant_consistency, MetaPayload};
pub use models::{IdentityContext, ProposedAction, TransportKind};
pub use source::{AuthMode, SourceRegistration, SourceType};
