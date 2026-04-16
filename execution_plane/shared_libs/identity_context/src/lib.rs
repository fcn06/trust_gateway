// ─────────────────────────────────────────────────────────────
// identity_context — Identity extraction and _meta validation
//
// Spec reference: §6 (domain model), §17 (_meta extraction),
//                 §18 (source registry)
//
// This crate provides transport-neutral identity primitives:
// - JWT introspection (no validation, decoding only)
// - _meta extraction, validation, and stripping
// - SourceContext for external swarm registration
// - ProposedAction as the unified pre-policy structure
// ─────────────────────────────────────────────────────────────

pub mod models;
pub mod meta;
pub mod jwt;
pub mod source;

// Re-export key types at crate root.
pub use models::{IdentityContext, ProposedAction, TransportKind};
pub use meta::{MetaPayload, extract_meta, strip_meta, validate_tenant_consistency};
pub use jwt::{JwtClaims, decode_jwt_claims, extract_dids_from_jwt, extract_tenant_id_from_jwt, extract_jti_from_jwt};
pub use source::{SourceRegistration, SourceType, AuthMode};
