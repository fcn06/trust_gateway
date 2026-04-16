//! OAuth flow handlers — authorization redirect and callback.

use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    Json,
};
use serde::Deserialize;

use crate::{AppState, token_store::OAuthToken};

/// Query params for OAuth callback.
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackParams {
    pub code: String,
    pub state: String, // Contains tenant_id
}

/// GET /oauth/google/authorize/:tenant_id — Redirect to Google OAuth consent screen.
pub async fn google_authorize(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Result<Redirect, (StatusCode, String)> {
    if state.google_client_id.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Google OAuth not configured".to_string(),
        ));
    }

    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| {
        format!(
            "{}/oauth/google/callback",
            std::env::var("CONNECTOR_MCP_URL").unwrap_or_else(|_| "http://localhost:3050".to_string())
        )
    });

    let scopes = "https://www.googleapis.com/auth/calendar.events";

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&access_type=offline&prompt=consent",
        state.google_client_id,
        urlencoding(&redirect_uri),
        urlencoding(scopes),
        urlencoding(&tenant_id),
    );

    tracing::info!(
        "🔐 Redirecting tenant {} to Google OAuth consent",
        tenant_id
    );
    Ok(Redirect::temporary(&auth_url))
}

/// GET /oauth/google/callback — Handle OAuth callback and store tokens.
pub async fn google_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tenant_id = params.state;
    tracing::info!(
        "🔑 Google OAuth callback for tenant {}",
        tenant_id
    );

    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| {
        format!(
            "{}/oauth/google/callback",
            std::env::var("CONNECTOR_MCP_URL").unwrap_or_else(|_| "http://localhost:3050".to_string())
        )
    });

    // Exchange authorization code for tokens
    let client = reqwest::Client::new();
    let token_response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", &state.google_client_id),
            ("client_secret", &state.google_client_secret),
            ("redirect_uri", &redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Token exchange failed: {}", e),
            )
        })?;

    if !token_response.status().is_success() {
        let err_body = token_response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Google token exchange failed: {}", err_body),
        ));
    }

    let token_data: serde_json::Value = token_response.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse token response: {}", e),
        )
    })?;

    let now = chrono::Utc::now().timestamp();
    let expires_in = token_data["expires_in"].as_i64().unwrap_or(3600);

    let oauth_token = OAuthToken {
        tenant_id: tenant_id.clone(),
        provider: "google".to_string(),
        access_token: token_data["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        refresh_token: token_data["refresh_token"]
            .as_str()
            .map(|s| s.to_string()),
        expires_at: now + expires_in,
        scopes: vec!["calendar.events".to_string()],
        created_at: now,
    };

    state.token_store.store_token(&oauth_token).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to store token: {}", e),
        )
    })?;

    Ok(Json(serde_json::json!({
        "status": "connected",
        "tenant_id": tenant_id,
        "provider": "google",
        "scopes": ["calendar.events"],
    })))
}

/// GET /oauth/status/:tenant_id — Return connection status for all providers.
pub async fn integration_status(
    State(state): State<Arc<AppState>>,
    Path(tenant_id): Path<String>,
) -> Json<serde_json::Value> {
    let providers = vec!["google", "stripe", "shopify"];
    let mut statuses = Vec::new();

    for provider in providers {
        let (connected, scopes, connected_at) =
            match state.token_store.get_token(&tenant_id, provider).await {
                Ok(Some(token)) => {
                    let valid = crate::token_store::TokenStore::is_token_valid(&token);
                    (
                        valid,
                        token.scopes.clone(),
                        Some(token.created_at),
                    )
                }
                _ => (false, vec![], None),
            };

        statuses.push(serde_json::json!({
            "provider": provider,
            "connected": connected,
            "scopes": scopes,
            "connected_at": connected_at,
        }));
    }

    Json(serde_json::json!({ "integrations": statuses }))
}

/// Simple URL encoding helper.
fn urlencoding(s: &str) -> String {
    s.replace(' ', "%20")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}
