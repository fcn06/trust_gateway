use axum::{extract::State, Json};
use std::sync::Arc;
use crate::gateway::GatewayState;

/// GET /.well-known/openid-configuration
pub async fn openid_configuration_handler(
    State(state): State<Arc<GatewayState>>,
) -> Json<serde_json::Value> {
    // If OAuth is not configured, we return a 404 or just an empty/error response.
    // Assuming OAuth is properly configured here based on the plan.
    let issuer = match &state.oauth_config {
        Some(config) => &config.server.issuer_url,
        None => return Json(serde_json::json!({ "error": "oauth_not_configured" })),
    };

    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/auth/authorize", issuer),
        "token_endpoint": format!("{}/auth/token", issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256", "EdDSA"],
        "scopes_supported": ["mcp:execute", "tools:list", "tools:call"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
    }))
}
