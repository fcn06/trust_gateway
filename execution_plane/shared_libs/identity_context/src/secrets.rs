// ─────────────────────────────────────────────────────────────
// identity_context — Hardened secrets loader
// ─────────────────────────────────────────────────────────────

use std::path::Path;

/// A wrapper that zeroizes its content on drop to prevent secrets from lingering in memory.
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        unsafe {
            let bytes = self.0.as_mut_vec();
            for byte in bytes.iter_mut() {
                *byte = 0;
            }
        }
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString(***)")
    }
}

/// Dynamic secret loader. It attempts to read the secret from systemd's transient
/// credentials directory (specified via the `CREDENTIALS_DIRECTORY` environment variable)
/// before falling back to the standard environment variable lookup.
pub fn load_secret(var_name: &str) -> Option<SecretString> {
    // 1. Try systemd credentials directory first
    if let Ok(creds_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let file_name = match var_name {
            "NATS_NKEY_SEED" => "nats_nkey_seed",
            "JWT_SECRET" => "jwt_secret",
            "B2B_JWT_SECRET" => "b2b_jwt_secret",
            "B2B_SECRET_COMPANY_ALPHA" => "b2b_secret_alpha",
            "B2B_SECRET_COMPANY_BETA" => "b2b_secret_beta",
            "B2B_SECRET_COMPANY_GAMMA" => "b2b_secret_gamma",
            "B2B_SECRET_COMPANY_DELTA" => "b2b_secret_delta",
            "B2B_SECRET_COMPANY_EPSILON" => "b2b_secret_epsilon",
            "LLM_A2A_API_KEY" => "llm_a2a_api_key",
            "LLM_MCP_API_KEY" => "llm_mcp_api_key",
            "GOOGLE_CLIENT_ID" => "google_client_id",
            "GOOGLE_CLIENT_SECRET" => "google_client_secret",
            "GOOGLE_REDIRECT_URI" => "google_redirect_uri",
            "OAUTH_SECRET_CLAUDE_DESKTOP" => "oauth_secret_claude_desktop",
            "OAUTH_SECRET_CLAUDE_WEB" => "oauth_secret_claude_web",
            "TELEGRAM_BOT_TOKEN" => "telegram_bot_token",
            "TELEGRAM_CHAT_ID" => "telegram_chat_id",
            "GATEWAY_PRIVATE_KEY" => "gateway_private_key",
            _ => var_name,
        };
        let path = Path::new(&creds_dir).join(file_name);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                return Some(SecretString::new(content.trim().to_string()));
            }
        }
    }
    // 2. Fall back to environment variable
    if let Ok(val) = std::env::var(var_name) {
        return Some(SecretString::new(val));
    }
    None
}
