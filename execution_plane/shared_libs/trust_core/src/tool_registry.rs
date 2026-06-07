// ─────────────────────────────────────────────────────────────
// Tool Registry — Stable Tool Identifiers & Descriptors (P3)
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Risk classification for tools — drives policy tier selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    ReadOnly,
    Write,
    Financial,
    Destructive,
}

/// Executor profile — determines which executor_host profile handles the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorProfile {
    Connector,
    Vp,
    NativeTool,
    SandboxedTool,
    SandboxedSkill,
}

/// Egress classification — determines which egress validator rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressClass {
    /// Internal-only (never exposed to external callers).
    Internal,
    /// B2B egress (full deterministic validator applied).
    B2b,
    /// Public API egress (strictest filtering).
    Public,
}

/// Deprecation metadata for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationInfo {
    /// When this tool was deprecated (ISO 8601).
    pub deprecated_at: String,
    /// Suggested replacement tool_id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
    /// Human-readable reason for deprecation.
    pub reason: String,
}

/// Complete descriptor for a registered tool.
///
/// Stored in the `tool_registry` NATS KV bucket.
/// Key format: `tool_{tool_id}` (using `_` separator per RULE 020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Stable reverse-DNS identifier: `io.lianxi.stripe.refund@v1`
    pub tool_id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Detailed description for LLMs (maps to MCP description). If empty, display_name is used.
    #[serde(default)]
    pub description: String,
    /// MCP-compatible tool name (for protocol clients): `stripe_refund`
    pub mcp_name: String,
    /// JSON Schema for tool input parameters.
    pub input_schema: serde_json::Value,
    /// JSON Schema for tool output.
    pub output_schema: serde_json::Value,
    /// Risk classification.
    pub risk_tier: RiskTier,
    /// Which executor profile handles this tool.
    pub executor_profile: ExecutorProfile,
    /// Required OAuth/VP scopes for authorization.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Egress classification.
    pub egress_class: EgressClass,
    /// Tool bundle memberships (e.g., "finance", "scheduling").
    #[serde(default)]
    pub bundle_membership: Vec<String>,
    /// Semantic version string.
    pub version: String,
    /// Deprecation info, if this tool is deprecated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecation: Option<DeprecationInfo>,
    /// Optional cron schedule string (e.g. "0 9 * * 1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
}

impl ToolDescriptor {
    /// Create a tool descriptor with sensible defaults.
    pub fn new(
        tool_id: &str,
        display_name: &str,
        mcp_name: &str,
        risk_tier: RiskTier,
        executor_profile: ExecutorProfile,
        egress_class: EgressClass,
    ) -> Self {
        Self {
            tool_id: tool_id.to_string(),
            display_name: display_name.to_string(),
            description: String::new(),
            mcp_name: mcp_name.to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier,
            executor_profile,
            required_scopes: Vec::new(),
            egress_class,
            bundle_membership: Vec::new(),
            version: "1.0.0".to_string(),
            deprecation: None,
            cron: None,
        }
    }

    /// Generate the NATS KV key for this descriptor.
    /// RULE 020: Uses `_` as separator, never `:`.
    pub fn kv_key(&self) -> String {
        format!("tool_{}", self.tool_id.replace([':', '@'], "_"))
    }
}

/// P3: Returns the built-in registry of stable tool descriptors.
///
/// These are the canonical reverse-DNS identifiers for all known tools,
/// enabling registry-first routing and deprecating prefix-fallback.
///
/// Each tool carries its executor profile, risk tier, and egress class,
/// allowing the router to make deterministic dispatch decisions without
/// prefix matching.
pub fn builtin_descriptors() -> Vec<ToolDescriptor> {
    vec![
        // ── Connector Tools (OAuth/SaaS) ───────────────────
        // ── Core Tools (Meta-tools - ALWAYS AVAILABLE) ──────────────
        ToolDescriptor {
            tool_id: "io.lianxi.core.search_skills@v1".into(),
            display_name: "Search Skills and Tools".into(),
            description: "📌 Meta Tool (Optional): Search the full library of available skills and tools across all categories by keyword. Even though historically named 'search_skills', this unified meta-tool discovers both dynamic skills (WASI/sandboxed) and standard platform tools seamlessly. Use this only if list_bundles does not provide enough information.".into(),
            mcp_name: "search_skills".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Keyword to search for" }
                },
                "required": ["query"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector, // Handled internally by Router
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["core".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.core.switch_context@v1".into(),
            display_name: "Switch Context".into(),
            description: "📌 Meta Tool (Step 2 of 2): Activate a different tool bundle (category) to load new tools. Call this with the bundle_name (e.g. 'discovery', 'scheduling', 'ecommerce') returned by list_bundles. After calling this, the server immediately switches your active tool list. IMPORTANT: Standard MCP clients automatically reload the toolset. If you are an agnostic client, you should re-query or refresh the tool list to see the newly loaded tools. CRITICAL: When you finish using the custom tools in a bundle, or when the user's intent or task changes, you MUST switch back to the 'default_tools' bundle by calling switch_context(bundle_name: 'default_tools') to restore access to the standard toolset.".into(),
            mcp_name: "switch_context".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "bundle_name": { "type": "string", "description": "Bundle to activate" }
                },
                "required": ["bundle_name"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["core".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.core.list_bundles@v1".into(),
            display_name: "List Bundles".into(),
            description: "📌 Meta Tool (Step 1 of 2): List all available skill bundles (categories) and their associated tools. Use ONLY if standard tools in your current list are not sufficient to fulfill the request. This is the first step of the discovery workflow: list_bundles → switch_context. Identify the target bundle name, then call switch_context(bundle_name) to load those tools into your session.".into(),
            mcp_name: "list_bundles".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["core".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },


        // ── Default Tools (ALWAYS AVAILABLE) ───────────────
        ToolDescriptor {
            tool_id: "io.lianxi.vp.search@v1".into(),
            display_name: "Search".into(),
            description: "Search the web by keyword query. Returns a list of search results with links and snippets. Do NOT use this tool to read or extract the full content of a specific URL. If the user provides a URL to read or summarize, use the discovery workflow (📌 Meta Tools) to find a content extraction tool instead.".into(),
            mcp_name: "vp_search".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query" }
                },
                "required": ["query"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.claw.weather@v1".into(),
            display_name: "Claw — Current Weather".into(),
            description: "Get the current weather for a specific city or location.".into(),
            mcp_name: "claw_weather".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "location": { "type": "string", "description": "City or location" }
                },
                "required": ["location"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.google.calendar.list@v1".into(),
            display_name: "Google Calendar — List Events".into(),
            description: "List upcoming events from the user's Google Calendar. Useful for checking availability or schedule.".into(),
            mcp_name: "google_calendar_list_events".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["calendar:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["default_tools".into(), "scheduling".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.google.calendar.create@v1".into(),
            display_name: "Google Calendar — Create Event".into(),
            description: "Create a new event in the user's Google Calendar. Requires event details like summary, start time, and end time.".into(),
            mcp_name: "google_calendar_create_event".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::Write,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["calendar:write".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["default_tools".into(), "scheduling".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },

        // ── Ecommerce Bundle ───────────────────────────────
        ToolDescriptor {
            tool_id: "io.lianxi.shopify.list_orders@v1".into(),
            display_name: "Shopify — List Orders".into(),
            description: "Retrieve a list of recent orders from the Shopify e-commerce store. Useful for checking order status, fulfillment, or customer purchases.".into(),
            mcp_name: "shopify_list_orders".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["shopify:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["ecommerce".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.stripe.list_payments@v1".into(),
            display_name: "Stripe — List Payments".into(),
            description: "Retrieve a list of recent payments and transactions from Stripe. Useful for verifying refunds, charges, or overall revenue status.".into(),
            mcp_name: "stripe_list_payments".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["stripe:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["ecommerce".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },

        // ── Discovery Bundle ───────────────────────────────
        ToolDescriptor {
            tool_id: "io.lianxi.claw.extract_content@v1".into(),
            display_name: "Claw — Extract Content from URL".into(),
            description: "Extract the main content from a given webpage URL. Returns clean, markdown-formatted text suitable for reading or summarization.".into(),
            mcp_name: "claw_extract_content_from_url".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL to extract" }
                },
                "required": ["url"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },
        ToolDescriptor {
            tool_id: "io.lianxi.vp.discover@v1".into(),
            display_name: "Discover Agent Services".into(),
            description: "Discover the services and capabilities (skills) of a target agent by providing its DID. Returns a list of available tools and endpoints.".into(),
            mcp_name: "discover_agent_services".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target_did": { "type": "string", "description": "Target agent DID" }
                },
                "required": ["target_did"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        },


    ]
}

/// Build a lookup map from MCP name → ToolDescriptor for efficient routing.
pub fn builtin_lookup() -> std::collections::HashMap<String, ToolDescriptor> {
    builtin_descriptors()
        .into_iter()
        .map(|d| (d.mcp_name.clone(), d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_descriptor_round_trip() {
        let desc = ToolDescriptor {
            tool_id: "io.lianxi.stripe.refund@v1".into(),
            display_name: "Stripe Refund".into(),
            description: "Detailed description".into(),
            mcp_name: "stripe_refund".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::Financial,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["stripe:write".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["finance".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
        };
        let json = serde_json::to_string(&desc).unwrap();
        let restored: ToolDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tool_id, "io.lianxi.stripe.refund@v1");
        assert_eq!(restored.risk_tier, RiskTier::Financial);
        assert_eq!(restored.executor_profile, ExecutorProfile::Connector);
    }

    #[test]
    fn kv_key_uses_underscore() {
        // RULE 020: JetStream composite keys use _ separator
        let tool_id = "io.lianxi.stripe.refund@v1";
        let kv_key = format!("tool_{}", tool_id.replace([':', '@'], "_"));
        assert!(!kv_key.contains(':'));
        assert!(kv_key.starts_with("tool_"));
    }
}
