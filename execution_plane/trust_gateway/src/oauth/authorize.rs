use axum::{
    extract::{Query, State, Form},
    response::{Html, IntoResponse, Redirect},
    http::{StatusCode, HeaderMap},
};
use serde::Deserialize;
use std::sync::Arc;
use crate::gateway::GatewayState;
use crate::oauth::store::AuthCodeEntry;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub action: String, // "approve" or "deny"
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scopes: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie_str) = headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        for cookie in cookie_str.split(';') {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("ssi_token=") {
                return Some(val.to_string());
            }
        }
    }
    None
}

pub async fn authorize_handler(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let oauth_config = match &state.oauth_config {
        Some(c) => c,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth not configured").into_response(),
    };

    let client = match oauth_config.clients.iter().find(|c| c.client_id == query.client_id) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response(),
    };

    if !client.redirect_uris.contains(&query.redirect_uri) {
        return (StatusCode::BAD_REQUEST, "Invalid redirect_uri").into_response();
    }

    if query.response_type != "code" {
        return (StatusCode::BAD_REQUEST, "Unsupported response_type").into_response();
    }

    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => {
            let oauth_config = match &state.oauth_config {
                Some(c) => c,
                None => return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth not configured").into_response(),
            };
            let issuer_url = oauth_config.server.issuer_url.trim_end_matches('/');

            // Redirect to Portal for login
            let return_to = format!("{}/auth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}", 
                issuer_url,
                urlencoding::encode(&query.client_id), 
                urlencoding::encode(&query.redirect_uri),
                urlencoding::encode(&query.response_type),
                urlencoding::encode(&query.scope.clone().unwrap_or_default()),
                urlencoding::encode(&query.state)
            );
            
            // Add PKCE params if present
            let mut return_to = return_to;
            if let Some(cc) = &query.code_challenge {
                return_to.push_str(&format!("&code_challenge={}", urlencoding::encode(cc)));
            }
            if let Some(ccm) = &query.code_challenge_method {
                return_to.push_str(&format!("&code_challenge_method={}", urlencoding::encode(ccm)));
            }

            let portal_url = format!("{}/login?return_to={}", state.connectors.portal_url.trim_end_matches('/'), urlencoding::encode(&return_to));
            return Redirect::temporary(&portal_url).into_response();
        }
    };

    // Construct a temporary HeaderMap with the Bearer token so we can reuse TokenValidator
    let mut temp_headers = HeaderMap::new();
    temp_headers.insert(axum::http::header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

    let verified_jwt = match state.token_validator.validate(&temp_headers, &state.jwt_secret).await {
        Ok(jwt) => jwt,
        Err(_) => {
            let oauth_config = match &state.oauth_config {
                Some(c) => c,
                None => return (StatusCode::INTERNAL_SERVER_ERROR, "OAuth not configured").into_response(),
            };
            let issuer_url = oauth_config.server.issuer_url.trim_end_matches('/');

            // Invalid token, force re-login
            let return_to = format!("{}/auth/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}", 
                issuer_url,
                urlencoding::encode(&query.client_id), 
                urlencoding::encode(&query.redirect_uri),
                urlencoding::encode(&query.response_type),
                urlencoding::encode(&query.scope.unwrap_or_default()),
                urlencoding::encode(&query.state)
            );
            let portal_url = format!("{}/login?return_to={}", state.connectors.portal_url.trim_end_matches('/'), urlencoding::encode(&return_to));
            return Redirect::temporary(&portal_url).into_response();
        }
    };

    let scopes: Vec<String> = query.scope
        .unwrap_or_default()
        .split(' ')
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Verify all requested scopes are allowed for this client
    for s in &scopes {
        if !client.allowed_scopes.contains(s) {
            return (StatusCode::BAD_REQUEST, format!("Scope {} not allowed for this client", s)).into_response();
        }
    }

    let display_name = client.display_name.as_deref().unwrap_or(&client.client_id);
    let html = crate::oauth::consent::render_consent_screen(
        display_name,
        &scopes,
        &query.client_id,
        &query.redirect_uri,
        &query.state,
        query.code_challenge.as_deref(),
        query.code_challenge_method.as_deref(),
    );

    html.into_response()
}

pub async fn consent_handler(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> impl IntoResponse {
    if form.action != "approve" {
        return Redirect::temporary(&format!("{}?error=access_denied&state={}", form.redirect_uri, urlencoding::encode(&form.state))).into_response();
    }

    let token = match extract_session_token(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing session").into_response(),
    };

    let mut temp_headers = HeaderMap::new();
    temp_headers.insert(axum::http::header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

    let verified_jwt = match state.token_validator.validate(&temp_headers, &state.jwt_secret).await {
        Ok(jwt) => jwt,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid session").into_response(),
    };

    let code = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let ttl = state.oauth_config.as_ref().map(|c| c.server.authorization_code_ttl_secs).unwrap_or(600) as i64;

    let entry = AuthCodeEntry {
        code: code.clone(),
        client_id: form.client_id,
        did: verified_jwt.sub.clone(),
        tenant_id: verified_jwt.tenant_id.clone(),
        scopes: form.scopes.split(' ').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect(),
        redirect_uri: form.redirect_uri.clone(),
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
        state: form.state.clone(),
        created_at: now,
        expires_at: now + ttl,
    };

    // Store in NATS KV
    // Create the store instance using the jetstream context
    let kv = match state.jetstream.get_key_value("oauth_auth_codes").await {
        Ok(k) => k,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to access KV: {}", e)).into_response(),
    };
    
    let store = crate::oauth::store::AuthCodeStore::new(kv);
    if let Err(e) = store.store(&entry).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store auth code: {}", e)).into_response();
    }

    let redirect_url = format!("{}?code={}&state={}", form.redirect_uri, urlencoding::encode(&code), urlencoding::encode(&form.state));
    Redirect::to(&redirect_url).into_response()
}
