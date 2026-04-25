// ─────────────────────────────────────────────────────────────
// WebAuthn Authenticator — implements trust_core::traits::Authenticator
//
// Community edition concrete implementation that wraps the
// existing passkey-based WebAuthn logic and the HMAC-SHA256
// JWT session validator.
// ─────────────────────────────────────────────────────────────

use std::sync::Arc;
use trust_core::traits::{Authenticator, AuthenticatedIdentity, AuthError};
use crate::shared_state::WebauthnSharedState;
use jwt_simple::prelude::MACLike;

/// Community `Authenticator` backed by passkey-based WebAuthn
/// and HMAC-SHA256 JWT session tokens.
pub struct WebAuthnAuthenticator {
    shared: Arc<WebauthnSharedState>,
}

impl WebAuthnAuthenticator {
    pub fn new(shared: Arc<WebauthnSharedState>) -> Self {
        Self { shared }
    }
}

#[async_trait::async_trait]
impl Authenticator for WebAuthnAuthenticator {
    /// Validate a session JWT and extract the authenticated identity.
    ///
    /// The JWT is signed with HMAC-SHA256 using the host's `jwt_key`.
    /// On success, returns the user_id, tenant_id, and session metadata.
    async fn validate_session(
        &self,
        token: &str,
    ) -> Result<AuthenticatedIdentity, AuthError> {
        if token.is_empty() {
            return Err(AuthError::InvalidToken("empty token".to_string()));
        }

        let claims = self.shared.jwt_key
            .verify_token::<crate::dto::MyClaims>(token, None)
            .map_err(|e| AuthError::InvalidToken(format!("{:?}", e)))?;

        let user_id = claims.custom.user_id.clone();
        let username = claims.custom.username.clone();

        // Resolve tenant for this user
        let tenant_id = super::logic::lookup_user_tenant(&self.shared, &user_id)
            .await
            .unwrap_or_default();

        let session_id = claims.jwt_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        Ok(AuthenticatedIdentity {
            user_id,
            tenant_id,
            display_name: Some(username),
            email: None, // WebAuthn doesn't provide email
            auth_method: "webauthn".to_string(),
            session_id,
        })
    }

    /// Create a WebAuthn assertion challenge for Tier 2 re-authentication.
    ///
    /// Returns the WebAuthn `RequestChallengeResponse` as JSON, which
    /// the frontend uses to invoke `navigator.credentials.get()`.
    async fn create_reauth_challenge(
        &self,
        user_id: &str,
    ) -> Result<serde_json::Value, AuthError> {
        // Load credentials for this user
        let user_creds = {
            let creds_map = self.shared.user_credentials.read().await;
            creds_map.get(user_id).cloned()
        };

        let creds = match user_creds {
            Some(c) if !c.is_empty() => c,
            _ => {
                // Try loading from KV
                if let Some(kv_stores) = &self.shared.kv_stores {
                    if let Some(cred_store) = kv_stores.get("user_credentials") {
                        if let Ok(Some(entry)) = cred_store.get(user_id).await {
                            serde_json::from_slice(&entry)
                                .map_err(|e| {
                                    tracing::error!("Failed to parse credentials for user {}: {}", user_id, e);
                                    AuthError::Internal("credential store corrupted".to_string())
                                })?
                        } else {
                            return Err(AuthError::UserNotFound { user_id: user_id.to_string() });
                        }
                    } else {
                        return Err(AuthError::Internal("credential store unavailable".to_string()));
                    }
                } else {
                    return Err(AuthError::Internal("KV stores unavailable".to_string()));
                }
            }
        };

        let (rcr, auth_state) = self.shared.webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| AuthError::Internal(format!("WebAuthn challenge: {:?}", e)))?;

        // Store the auth state for verification later
        let session_id = uuid::Uuid::new_v4().to_string();
        {
            let mut sessions = self.shared.authentication_sessions.write().await;
            // Store with a special "reauth:" prefix to distinguish from login flows
            sessions.insert(
                format!("reauth:{}", session_id),
                (auth_state, String::new(), user_id.to_string()),
            );
        }

        Ok(serde_json::json!({
            "session_id": session_id,
            "options": rcr,
        }))
    }

    /// Verify a WebAuthn assertion response for Tier 2 re-authentication.
    async fn verify_reauth(
        &self,
        user_id: &str,
        response: &serde_json::Value,
    ) -> Result<bool, AuthError> {
        let session_id = response.get("session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::ReauthFailed("missing session_id".to_string()))?;

        let credential_json = response.get("credential")
            .ok_or_else(|| AuthError::ReauthFailed("missing credential".to_string()))?;

        let auth_response: webauthn_rs::prelude::PublicKeyCredential = 
            serde_json::from_value(credential_json.clone())
                .map_err(|e| AuthError::ReauthFailed(format!("credential parse: {}", e)))?;

        let reauth_key = format!("reauth:{}", session_id);
        let (auth_state, _, stored_user_id) = {
            let mut sessions = self.shared.authentication_sessions.write().await;
            sessions.remove(&reauth_key)
                .ok_or(AuthError::ReauthFailed("session expired or invalid".to_string()))?
        };

        // Verify the user_id matches
        if stored_user_id != user_id {
            return Err(AuthError::ReauthFailed("user_id mismatch".to_string()));
        }

        match self.shared.webauthn.finish_passkey_authentication(&auth_response, &auth_state) {
            Ok(_) => {
                tracing::info!("✅ Re-authentication succeeded for user {}", user_id);
                Ok(true)
            }
            Err(e) => {
                tracing::warn!("❌ Re-authentication failed for user {}: {:?}", user_id, e);
                Err(AuthError::ReauthFailed(format!("{:?}", e)))
            }
        }
    }
}
