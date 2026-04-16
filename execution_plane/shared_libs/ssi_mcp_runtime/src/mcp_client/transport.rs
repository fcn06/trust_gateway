//! SSE Transport utilities for MCP client connections.
//!
//! This module provides reusable transport initialization
//! with support for authentication headers (migrated to StreamableHttp in rmcp 1.3).

use rmcp::model::InitializeRequestParams;
use rmcp::service::RunningService;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::RoleClient;
use std::sync::Arc;

/// Type alias for an initialized MCP client connection.
pub type McpClient = RunningService<RoleClient, InitializeRequestParams>;

/// Create a StreamableHttp transport connection with optional Bearer auth.
///
/// # Arguments
/// * `uri` - The MCP server endpoint URI
/// * `api_key` - Optional API key for Bearer token authentication
///
/// # Returns
/// A configured `StreamableHttpClientTransport` ready for use with `serve_client`
pub fn create_transport(
    uri: impl Into<Arc<str>>,
    api_key: Option<String>,
) -> StreamableHttpClientTransport<reqwest::Client> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(uri);

    // Add Bearer token if API key is provided
    if let Some(key) = api_key {
        config = config.auth_header(format!("Bearer {}", key));
    }

    StreamableHttpClientTransport::with_client(reqwest::Client::new(), config)
}
