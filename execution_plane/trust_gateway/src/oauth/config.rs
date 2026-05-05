use serde::Deserialize;

fn default_access_token_ttl() -> u64 {
    3600
}

fn default_auth_code_ttl() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub server: OAuthServerConfig,
    pub clients: Vec<OAuthClientEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthServerConfig {
    pub issuer_url: String,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_secs: u64,
    #[serde(default = "default_auth_code_ttl")]
    pub authorization_code_ttl_secs: u64,
    pub token_signing_key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthClientEntry {
    pub client_id: String,
    pub client_secret_env: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}
