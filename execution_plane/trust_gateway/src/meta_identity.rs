// ─────────────────────────────────────────────────────────────
// Meta Identity — wires identity_context::meta into the gateway
//
// Spec reference: §17 (_meta identity contract)
//
// Called by api.rs::propose_action_handler and gateway.rs
// NATS dispatch to extract + validate _meta before governance.
// ─────────────────────────────────────────────────────────────

use identity_context::{
    IdentityContext, TransportKind,
    meta::{self, MetaError},
    jwt,
    models::SourceContext,
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

/// Attempt to extract identity from `_meta` in tool call arguments.
///
/// If `_meta` is present:
/// 1. Extracts and validates the _meta block
/// 2. Validates JWT ↔ tenant consistency
/// 3. Returns clean args + IdentityContext
///
/// If `_meta` is absent (internal NATS calls from ssi_agent):
/// Falls back to building identity from the session JWT directly.
pub fn extract_identity_from_args(
    args: &mut serde_json::Value,
    session_jwt: &str,
    transport: TransportKind,
    remote_addr: Option<String>,
) -> Result<MetaExtractionResult, MetaError> {
    // Try _meta extraction first (external swarm path)
    match meta::extract_meta(args) {
        Ok(meta_payload) => {
            // Build source context from _meta
            let source = SourceContext {
                source_type: identity_context::models::SourceType::ExternalSwarm,
                source_id: meta_payload.source_id.clone().unwrap_or_else(|| "unknown".to_string()),
                transport,
                correlation_id: meta_payload.correlation_id.clone()
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

            let identity = meta::build_identity_context(&meta_payload, source)?;

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
            // Derive identity from session JWT directly.
            let claims = jwt::decode_jwt_claims(session_jwt)
                .ok_or_else(|| MetaError::MalformedJwt("Could not decode JWT".to_string()))?;

            let source = SourceContext {
                source_type: identity_context::models::SourceType::SsiAgent,
                source_id: "self".to_string(),
                transport,
                correlation_id: if claims.jti.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    claims.jti.clone()
                },
                remote_addr,
            };

            let identity = IdentityContext {
                tenant_id: claims.tenant_id,
                owner_did: claims.iss,
                requester_did: claims.sub,
                session_jwt: session_jwt.to_string(),
                source,
            };

            Ok(MetaExtractionResult {
                clean_args: args.clone(),
                identity,
                raw_meta: None,
            })
        }
        Err(e) => Err(e),
    }
}
