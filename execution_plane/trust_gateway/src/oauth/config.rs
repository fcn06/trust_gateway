// oauth/config.rs
use serde::Deserialize;
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig { pub clients: Vec<OAuthClient> }
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthClient { pub client_id: String }
