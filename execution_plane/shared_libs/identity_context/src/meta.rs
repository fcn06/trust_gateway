// ─────────────────────────────────────────────────────────────
// _meta extraction, validation, and stripping
//
// Spec reference: §17 — _meta identity contract
//
// External swarms inject identity via `_meta.io.lianxi/*`
// fields in tool call arguments. This module:
// 1. Extracts them into a structured MetaPayload
// 2. Validates consistency against the session JWT
// 3. Strips _meta from arguments before executor dispatch
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::jwt::{self, JwtClaims};

/// The extracted _meta identity payload from tool call arguments.
///
/// Spec §17.1 — required and optional fields under `_meta.io.lianxi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaPayload {
    /// Session JWT — REQUIRED. Contains owner/requester DIDs and tenant_id.
    pub session_jwt: String,

    /// Explicit tenant_id override. If present, MUST match the JWT's tenant_id.
    pub tenant_id: Option<String>,

    /// Explicit requester DID override (for delegated calls).
    pub requester_did: Option<String>,

    /// Correlation ID for distributed tracing.
    pub correlation_id: Option<String>,

    /// Source identifier (registered swarm name).
    pub source_id: Option<String>,
}

/// Errors during _meta extraction and validation.
#[derive(Debug, Error)]
pub enum MetaError {
    #[error("Missing _meta.io.lianxi.session_jwt — required for identity resolution")]
    MissingSessionJwt,

    #[error("Malformed session JWT in _meta: {0}")]
    MalformedJwt(String),

    #[error("Tenant mismatch: _meta.tenant_id='{meta}' but JWT.tenant_id='{jwt}'")]
    TenantMismatch { meta: String, jwt: String },

    #[error("No _meta block present in arguments")]
    NoMetaBlock,
}

/// Extract the `_meta` block from tool call arguments.
///
/// Removes `_meta` from the argument map and returns the structured
/// identity payload. If no `_meta` key exists, returns `Err(NoMetaBlock)`
/// — callers should fall back to deriving identity from JWT headers.
///
/// Spec §17.2 steps 1-5.
pub fn extract_meta(args: &mut serde_json::Value) -> Result<MetaPayload, MetaError> {
    let meta_value = match args.as_object_mut() {
        Some(obj) => match obj.remove("_meta") {
            Some(v) => v,
            None => return Err(MetaError::NoMetaBlock),
        },
        None => return Err(MetaError::NoMetaBlock),
    };

    // Navigate to io.lianxi namespace (canonical)
    // Supports multiple forms:
    //   1. _meta["io.lianxi"]          — canonical dotted key
    //   2. _meta.io.lianxi             — nested io → lianxi
    //   3. _meta.lianxi                — simplified form
    let ag_block = meta_value
        .get("io.lianxi")
        .or_else(|| {
            meta_value
                .get("io")
                .and_then(|io| io.get("lianxi"))
        })
        .or_else(|| meta_value.get("lianxi"))
        .cloned()
        .unwrap_or(meta_value.clone());

    // Extract required session_jwt
    let session_jwt = ag_block
        .get("session_jwt")
        .or_else(|| ag_block.get("X-Session-JWT"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or(MetaError::MissingSessionJwt)?;

    // Validate JWT is decodable
    if jwt::decode_jwt_claims(&session_jwt).is_none() {
        return Err(MetaError::MalformedJwt(
            "Could not decode JWT payload".to_string(),
        ));
    }

    Ok(MetaPayload {
        session_jwt,
        tenant_id: ag_block
            .get("tenant_id")
            .or_else(|| ag_block.get("X-Tenant-ID"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        requester_did: ag_block
            .get("requester_did")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        correlation_id: ag_block
            .get("correlation_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        source_id: ag_block
            .get("source_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Validate that the _meta tenant_id (if provided) matches the JWT's tenant_id.
///
/// Spec §17.2 step 5 — hard reject on mismatch (prevents tenant impersonation).
pub fn validate_tenant_consistency(
    meta: &MetaPayload,
    jwt_claims: &JwtClaims,
) -> Result<(), MetaError> {
    if let Some(ref meta_tenant) = meta.tenant_id {
        if !jwt_claims.tenant_id.is_empty() && meta_tenant != &jwt_claims.tenant_id {
            return Err(MetaError::TenantMismatch {
                meta: meta_tenant.clone(),
                jwt: jwt_claims.tenant_id.clone(),
            });
        }
    }
    Ok(())
}

/// Final-stage stripping — guarantees no `_meta` key in executor-bound args.
///
/// Spec §17.3 — called immediately before dispatch. This is a safety net
/// even if extract_meta already removed it, since args may be re-serialized.
pub fn strip_meta(args: &mut serde_json::Value) {
    if let Some(obj) = args.as_object_mut() {
        obj.remove("_meta");
    }
}

/// Build an IdentityContext from a validated MetaPayload.
///
/// **DEPRECATED:** Use `build_identity_context_verified` instead, which
/// accepts pre-verified `&JwtClaims` from `AuthVerifier::verify()`.
/// This function re-decodes the JWT without signature verification.
///
/// Combines _meta fields with decoded JWT claims to produce the
/// unified identity view for policy evaluation.
#[deprecated(
    since = "0.2.0",
    note = "Use build_identity_context_verified() with pre-verified claims instead"
)]
pub fn build_identity_context(
    meta: &MetaPayload,
    source: crate::models::SourceContext,
) -> Result<crate::models::IdentityContext, MetaError> {
    let claims = jwt::decode_jwt_claims(&meta.session_jwt)
        .ok_or_else(|| MetaError::MalformedJwt("Failed to decode JWT".to_string()))?;

    // Validate tenant consistency
    validate_tenant_consistency(meta, &claims)?;

    // Derive tenant_id: explicit _meta > JWT > empty (will fail downstream)
    let tenant_id = meta
        .tenant_id
        .clone()
        .unwrap_or_else(|| claims.tenant_id.clone());

    // Derive requester_did: explicit _meta > JWT sub
    let requester_did = meta
        .requester_did
        .clone()
        .unwrap_or_else(|| claims.sub.clone());

    Ok(crate::models::IdentityContext {
        tenant_id,
        owner_did: claims.iss,
        requester_did,
        session_jwt: meta.session_jwt.clone(),
        source,
    })
}

/// Build an IdentityContext from a validated MetaPayload using
/// pre-verified claims.
///
/// Per RULE[010_JWT_CONTRACTS.md]: accepts `&JwtClaims` that have
/// already been verified via `AuthVerifier::verify()`, eliminating
/// the need to re-decode the JWT payload without signature validation.
///
/// This is the **preferred** path for all production call sites.
pub fn build_identity_context_verified(
    meta: &MetaPayload,
    verified_claims: &JwtClaims,
    source: crate::models::SourceContext,
) -> Result<crate::models::IdentityContext, MetaError> {
    // Validate tenant consistency using the verified claims
    validate_tenant_consistency(meta, verified_claims)?;

    // Derive tenant_id: explicit _meta > JWT > empty (will fail downstream)
    let tenant_id = meta
        .tenant_id
        .clone()
        .unwrap_or_else(|| verified_claims.tenant_id.clone());

    // Derive requester_did: explicit _meta > JWT sub
    let requester_did = meta
        .requester_did
        .clone()
        .unwrap_or_else(|| verified_claims.sub.clone());

    Ok(crate::models::IdentityContext {
        tenant_id,
        owner_did: verified_claims.iss.clone(),
        requester_did,
        session_jwt: meta.session_jwt.clone(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_jwt(claims: &serde_json::Value) -> String {
        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = encoder.encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = encoder.encode(serde_json::to_vec(claims).unwrap());
        format!("{}.{}.sig", header, payload)
    }

    // UT-001: _meta extraction success
    #[test]
    fn test_extract_meta_success() {
        let jwt = make_jwt(&serde_json::json!({
            "iss": "did:twin:zOwner",
            "sub": "did:twin:zRequester",
            "tenant_id": "tenant-eu-01",
            "jti": "sess-123",
        }));

        let mut args = serde_json::json!({
            "order_id": "ORD-42",
            "amount": 100,
            "_meta": {
                "io.lianxi": {
                    "session_jwt": jwt,
                    "tenant_id": "tenant-eu-01",
                    "correlation_id": "trace-abc",
                    "source_id": "swarm-alpha",
                }
            }
        });

        let meta = extract_meta(&mut args).expect("should extract _meta");

        // _meta is removed from args
        assert!(args.get("_meta").is_none(), "_meta must be removed from args");

        // Business args preserved
        assert_eq!(args.get("order_id").unwrap().as_str().unwrap(), "ORD-42");

        // MetaPayload populated
        assert_eq!(meta.tenant_id, Some("tenant-eu-01".to_string()));
        assert_eq!(meta.correlation_id, Some("trace-abc".to_string()));
        assert_eq!(meta.source_id, Some("swarm-alpha".to_string()));

        // Build identity context
        let identity = build_identity_context(&meta, Default::default())
            .expect("should build identity");
        assert_eq!(identity.tenant_id, "tenant-eu-01");
        assert_eq!(identity.owner_did, "did:twin:zOwner");
        assert_eq!(identity.requester_did, "did:twin:zRequester");
    }

    // UT-002: _meta tenant mismatch rejection
    #[test]
    fn test_tenant_mismatch_rejected() {
        let jwt = make_jwt(&serde_json::json!({
            "iss": "did:twin:z1",
            "tenant_id": "tenant-A",
        }));

        let mut args = serde_json::json!({
            "_meta": {
                "io.lianxi": {
                    "session_jwt": jwt,
                    "tenant_id": "tenant-B",  // MISMATCH!
                }
            }
        });

        let meta = extract_meta(&mut args).expect("extract should work");
        let claims = jwt::decode_jwt_claims(&meta.session_jwt).unwrap();
        let result = validate_tenant_consistency(&meta, &claims);

        assert!(result.is_err());
        match result.unwrap_err() {
            MetaError::TenantMismatch { meta, jwt } => {
                assert_eq!(meta, "tenant-B");
                assert_eq!(jwt, "tenant-A");
            }
            other => panic!("Expected TenantMismatch, got: {:?}", other),
        }
    }

    // NEG-001: Malformed JWT
    #[test]
    fn test_malformed_jwt_rejected() {
        let mut args = serde_json::json!({
            "_meta": {
                "io.lianxi": {
                    "session_jwt": "this-is-not-a-jwt",
                }
            }
        });

        let result = extract_meta(&mut args);
        assert!(matches!(result, Err(MetaError::MalformedJwt(_))));
    }

    // NEG-003: _meta must not leak to executor
    #[test]
    fn test_strip_meta_guarantees_removal() {
        let mut args = serde_json::json!({
            "order_id": "ORD-1",
            "_meta": { "io.lianxi": { "session_jwt": "abc" } },
        });

        strip_meta(&mut args);
        assert!(args.get("_meta").is_none(), "_meta MUST be absent after strip");
        assert_eq!(args.get("order_id").unwrap().as_str().unwrap(), "ORD-1");
    }

    #[test]
    fn test_no_meta_block_returns_error() {
        let mut args = serde_json::json!({
            "order_id": "ORD-1",
        });

        let result = extract_meta(&mut args);
        assert!(matches!(result, Err(MetaError::NoMetaBlock)));
    }

    #[test]
    fn test_missing_session_jwt_returns_error() {
        let mut args = serde_json::json!({
            "_meta": {
                "io.lianxi": {
                    "tenant_id": "t1",
                    // session_jwt is MISSING
                }
            }
        });

        let result = extract_meta(&mut args);
        assert!(matches!(result, Err(MetaError::MissingSessionJwt)));
    }
}
