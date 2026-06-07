// ─────────────────────────────────────────────────────────────
// Meta Identity — wires identity_context::meta into the gateway
//
// Spec reference: §17 (_meta identity contract)
//
// Called by api.rs::propose_action_handler and gateway.rs
// NATS dispatch to extract + validate _meta before governance.
//
// RULE[010_JWT_CONTRACTS.md]: This module accepts pre-verified
// `&JwtClaims` from the caller (already verified via
// `TokenValidator::validate` or `AuthVerifier::verify`).
// It MUST NOT call `decode_jwt_claims` for domain logic.
// ─────────────────────────────────────────────────────────────

use identity_context::{
    meta::{self, MetaError},
    models::SourceContext,
    IdentityContext, TransportKind,
};

/// Result of _meta extraction from a tool call's arguments.
///
/// Contains the cleaned arguments and derived identity.
pub struct MetaExtractionResult {
    /// Clean arguments with _meta removed (safe for executor dispatch).
    pub clean_args: serde_json::Value,
    /// Derived identity context for policy evaluation.
    pub identity: IdentityContext,
    /// Raw _meta preserved for audit only (NEVER sent to executors).
    pub raw_meta: Option<serde_json::Value>,
}

/// Extract identity from `_meta` in tool call arguments, using
/// pre-verified JWT claims.
///
/// Per RULE[010_JWT_CONTRACTS.md]: The `verified_claims` parameter
/// contains claims that were cryptographically verified at the API
/// boundary (via `TokenValidator::validate`). This function uses
/// those claims directly instead of re-decoding the raw JWT string.
///
/// If `_meta` is present:
/// 1. Extracts and validates the _meta block
/// 2. Uses the verified claims for tenant consistency check
/// 3. Returns clean args + IdentityContext
///
/// If `_meta` is absent (internal NATS calls from ssi_agent):
/// Falls back to building identity from the pre-verified claims.
pub fn extract_identity_from_args(
    args: &mut serde_json::Value,
    base_identity: IdentityContext,
    transport: TransportKind,
    remote_addr: Option<String>,
) -> Result<MetaExtractionResult, MetaError> {
    // Try _meta extraction first (external swarm path)
    match meta::extract_meta(args) {
        Ok(meta_payload) => {
            // Build source context from _meta
            let source = SourceContext {
                source_type: identity_context::models::SourceType::ExternalSwarm,
                source_id: meta_payload
                    .source_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                transport,
                correlation_id: meta_payload
                    .correlation_id
                    .clone()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                remote_addr,
            };

            // Save raw _meta for audit before we consume it
            let raw_meta = Some(serde_json::json!({
                "session_jwt": "[REDACTED]",
                "tenant_id": meta_payload.tenant_id,
                "requester_did": meta_payload.requester_did,
                "correlation_id": meta_payload.correlation_id,
                "source_id": meta_payload.source_id,
            }));

            // Build identity context using base_identity as defaults
            let mut identity = base_identity.clone();
            identity.source = source;
            if let Some(meta_tenant) = meta_payload.tenant_id {
                // Spec §17.2 step 5 — hard reject on mismatch
                if !identity.tenant_id.is_empty() && meta_tenant != identity.tenant_id {
                    return Err(MetaError::TenantMismatch {
                        meta: meta_tenant,
                        jwt: identity.tenant_id,
                    });
                }
                identity.tenant_id = meta_tenant;
            }
            if let Some(req_did) = meta_payload.requester_did {
                identity.requester_did = req_did;
            }
            identity.session_jwt = meta_payload.session_jwt;

            // Final safety: ensure _meta is stripped from args
            meta::strip_meta(args);

            tracing::info!(
                "🔐 Meta identity extracted: tenant={}, requester={}, source={}",
                identity.tenant_id,
                identity.requester_did,
                identity.source.source_id,
            );

            Ok(MetaExtractionResult {
                clean_args: args.clone(),
                identity,
                raw_meta,
            })
        }
        Err(MetaError::NoMetaBlock) => {
            // No _meta present — this is a normal internal call.
            let source = SourceContext {
                source_type: identity_context::models::SourceType::SsiAgent,
                source_id: "self".to_string(),
                transport,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                remote_addr,
            };

            let mut identity = base_identity;
            identity.source = source;

            Ok(MetaExtractionResult {
                clean_args: args.clone(),
                identity,
                raw_meta: None,
            })
        }
        Err(e) => Err(e),
    }
}
