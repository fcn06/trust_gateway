//! Authentication configuration module for SSI Identity Agent.
//! 
//! This module provides authentication configuration types and utilities
//! for configuring different authentication methods (None, Bearer Token, API Key).

use serde::{Deserialize, Serialize};
use std::env;

/// Authentication configuration for the agent server.
/// 
/// Supports multiple authentication methods that can be configured via
/// environment variables or programmatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    /// No authentication (default for development)
    None,
    /// Bearer token authentication
    BearerToken {
        /// List of valid tokens
        tokens: Vec<String>,
        /// Optional bearer format description (e.g., "JWT")
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
    /// API Key authentication
    ApiKey {
        /// Valid API keys
        keys: Vec<String>,
        /// Location of the API key: "header", "query", or "cookie"
        #[serde(default = "default_api_key_location")]
        location: String,
        /// Name of the header/query param/cookie
        #[serde(default = "default_api_key_name")]
        name: String,
    },
    /// Dynamic OAuth2 JWT verification
    OAuth2Jwt {
        /// Secret key for HMAC signature validation
        secret: String,
        /// Expected audience claim
        audience: String,
        /// Expected issuer claim
        issuer: String,
    },
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::None
    }
}

impl AuthConfig {
    /// Create auth config from environment variables.
    /// 
    /// Checks for:
    /// - `AUTH_BEARER_TOKENS`: Comma-separated list of bearer tokens
    /// - `AUTH_BEARER_FORMAT`: Optional format description (e.g., "JWT")
    /// - `AUTH_API_KEYS`: Comma-separated list of API keys
    /// - `AUTH_API_KEY_LOCATION`: Where to look for API key ("header", "query", "cookie")
    /// - `AUTH_API_KEY_NAME`: Name of the header/query param/cookie
    pub fn from_env() -> Self {
        // Check for bearer tokens first
        if let Ok(tokens_str) = env::var("AUTH_BEARER_TOKENS") {
            let tokens: Vec<String> = tokens_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if !tokens.is_empty() {
                return Self::BearerToken {
                    tokens,
                    format: env::var("AUTH_BEARER_FORMAT").ok(),
                };
            }
        }

        // Check for API keys
        if let Ok(keys_str) = env::var("AUTH_API_KEYS") {
            let keys: Vec<String> = keys_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if !keys.is_empty() {
                return Self::ApiKey {
                    keys,
                    location: env::var("AUTH_API_KEY_LOCATION")
                        .unwrap_or_else(|_| default_api_key_location()),
                    name: env::var("AUTH_API_KEY_NAME").unwrap_or_else(|_| default_api_key_name()),
                };
            }
        }

        // Default to no authentication
        Self::None
    }
}

/// Default location for API key authentication.
fn default_api_key_location() -> String {
    "header".to_string()
}

/// Default name for API key header/query param/cookie.
fn default_api_key_name() -> String {
    "X-API-Key".to_string()
}
