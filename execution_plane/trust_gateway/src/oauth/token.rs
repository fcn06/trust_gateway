use axum::{
    extract::{State, Form},
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::gateway::GatewayState;
use crate::oauth::store::{AuthCodeStore, AuthCodeEntry};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use jwt_simple::prelude::*;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

fn json_error(status: StatusCode, error: &str, desc: &str) -> axum::response::Response {
    (status, Json(ErrorResponse {
        error: error.to_string(),
        error_description: desc.to_string(),
    })).into_response()
}

// Generates a JWT signed with the HMAC secret
fn generate_access_token(
    state: &Arc<GatewayState>,
    entry: &AuthCodeEntry,
    ttl_secs: u64,
    issuer: &str,
) -> Result<String, anyhow::Error> {
    // We use the HMAC JWT secret from GatewayState.
    // In the future, this could use an Ed25519 key specified in OAuthConfig.
    let key = HS256Key::from_bytes(state.jwt_secret.as_bytes());

    let mut custom_claims = serde_json::Map::new();
    custom_claims.insert("scope".to_string(), serde_json::Value::Array(
        entry.scopes.iter().map(|s| serde_json::Value::String(s.clone())).collect()
    ));
    custom_claims.insert("tenant_id".to_string(), serde_json::Value::String(entry.tenant_id.clone()));
    custom_claims.insert("client_id".to_string(), serde_json::Value::String(entry.client_id.clone()));

    let claims = Claims::with_custom_claims(custom_claims, Duration::from_secs(ttl_secs))
        .with_subject(&entry.did)
        .with_issuer(issuer);

    let token = key.authenticate(claims)?;
    Ok(token)
}

pub async fn token_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let oauth_config = match &state.oauth_config {
        Some(c) => c,
        None => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "OAuth not configured"),
    };

    if req.grant_type != "authorization_code" {
        return json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "Only authorization_code is supported");
    }

    let code_val = match &req.code {
        Some(c) => c,
        None => return json_error(StatusCode::BAD_REQUEST, "invalid_request", "Missing code"),
    };

    let mut client_id = req.client_id.clone();
    let mut client_secret = req.client_secret.clone();

    // Check basic auth
    if let Some(auth_str) = headers.get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        if let Some(encoded) = auth_str.strip_prefix("Basic ") {
            if let Ok(decoded) = STANDARD.decode(encoded) {
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    if let Some((user, pass)) = decoded_str.split_once(':') {
                        client_id = Some(user.to_string());
                        client_secret = Some(pass.to_string());
                    }
                }
            }
        }
    }

    let client_id = match client_id {
        Some(cid) => cid,
        None => return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "Missing client credentials"),
    };

    let client_config = match oauth_config.clients.iter().find(|c| c.client_id == client_id) {
        Some(c) => c,
        None => return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "Unknown client"),
    };

    // If client_secret_env is set and not empty, check secret
    if !client_config.client_secret_env.is_empty() {
        let expected_secret = std::env::var(&client_config.client_secret_env).unwrap_or_default();
        if expected_secret.is_empty() {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Client secret not configured in environment");
        }
        if client_secret.as_deref() != Some(expected_secret.as_str()) {
            return json_error(StatusCode::UNAUTHORIZED, "invalid_client", "Invalid client secret");
        }
    }

    let kv = match state.jetstream.get_key_value("oauth_auth_codes").await {
        Ok(k) => k,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "KV error"),
    };
    let store = AuthCodeStore::new(kv);

    let entry = match store.get(code_val).await {
        Ok(Some(e)) => e,
        _ => return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid or expired authorization code"),
    };

    // MUST delete to ensure single use
    let _ = store.delete(code_val).await;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    if entry.expires_at < now {
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "Authorization code expired");
    }

    if entry.client_id != client_id {
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "Client ID mismatch");
    }

    if let Some(req_uri) = &req.redirect_uri {
        if req_uri != &entry.redirect_uri {
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "Redirect URI mismatch");
        }
    } else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request", "Missing redirect_uri");
    }

    // PKCE verification
    if let Some(challenge) = &entry.code_challenge {
        let verifier = match &req.code_verifier {
            Some(v) => v,
            None => return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "Missing code_verifier for PKCE"),
        };

        if entry.code_challenge_method.as_deref() == Some("S256") {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            let expected_challenge = URL_SAFE_NO_PAD.encode(&hash);
            if challenge != &expected_challenge {
                return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
            }
        } else if challenge != verifier {
            // plain text challenge (not recommended but part of spec)
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }
    }

    let ttl = oauth_config.server.access_token_ttl_secs;
    let issuer = &oauth_config.server.issuer_url;

    let access_token = match generate_access_token(&state, &entry, ttl, issuer) {
        Ok(t) => t,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to generate token"),
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ttl as i64,
    }).into_response()
}
