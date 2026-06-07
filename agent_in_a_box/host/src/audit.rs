use serde_json::json;

/// Fire-and-forget audit event to NATS JetStream.
///
/// Publishes to `audit.tenant.{tenant_id}.{jti}` so events are tenant-scoped
/// and correlated by JWT session. Failures are logged but never block the caller.
pub async fn publish_audit(
    nats: &async_nats::Client,
    jti: &str,
    user_did: &str,
    action: &str,
    component: &str,
    detail: serde_json::Value,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
) {
    let tid = tenant_id.unwrap_or("default");
    let event = json!({
        "jti": jti,
        "tenant_id": tid,
        "user_did": user_did,
        "user_id": user_id.unwrap_or(""),
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "component": component,
        "action": action,
        "detail": detail,
    });
    let subject = format!("audit.tenant.{}.{}", tid, jti);
    if let Err(e) = nats
        .publish(subject, serde_json::to_vec(&event).unwrap_or_default().into())
        .await
    {
        tracing::warn!("Audit publish failed: {}", e);
    }
}

/// Extract `jti`, `user_did`, and `tenant_id` from a JWT without full verification.
/// Used for audit correlation only — the JWT has already been verified upstream.
pub fn extract_jti_from_jwt(jwt: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    let jti = claims.get("jti")?.as_str()?.to_string();
    let user_did = claims.get("iss")?.as_str().unwrap_or("unknown").to_string();
    Some((jti, user_did))
}

/// Extract `tenant_id` from a JWT without full verification.
pub fn extract_tenant_id_from_jwt(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims.get("tenant_id")?.as_str().map(|s| s.to_string())
}

use base64::Engine;

