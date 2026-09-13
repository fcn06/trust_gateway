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
    Dynamic,
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
    /// Optional app_id that registered this tool dynamically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Explicit operation metadata (defaults to read_only per backward compatibility).
    #[serde(default)]
    pub operation_attributes: crate::action::OperationAttributes,
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
            app_id: None,
            operation_attributes: crate::action::OperationAttributes::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.google.calendar.list@v1".into(),
            display_name: "Google Calendar — List Events".into(),
            description: "List upcoming events from the user's Google Calendar. Useful for checking availability or schedule.".into(),
            mcp_name: "google_calendar_list_events".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "max_results": { "type": "integer", "description": "Maximum number of events to list" },
                    "time_min": { "type": "string", "description": "Minimum event start time (ISO 8601)" }
                }
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["calendar:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["default_tools".into(), "scheduling".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.google.calendar.create@v1".into(),
            display_name: "Google Calendar — Create Event".into(),
            description: "Create a new event in the user's Google Calendar. Requires event details like summary, start time, and end time.".into(),
            mcp_name: "google_calendar_create_event".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "summary": { "type": "string", "description": "Event title/summary" },
                    "start_time": { "type": "string", "description": "Start time (ISO 8601 string, e.g. 2026-08-01T08:30:00+02:00)" },
                    "end_time": { "type": "string", "description": "End time (ISO 8601 string, e.g. 2026-08-01T09:30:00+02:00)" },
                    "description": { "type": "string", "description": "Event description" }
                },
                "required": ["summary", "start_time", "end_time"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::Write,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["calendar:write".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["default_tools".into(), "scheduling".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },

        // ── Ecommerce Bundle ───────────────────────────────
        ToolDescriptor {
            tool_id: "io.lianxi.shopify.list_orders@v1".into(),
            display_name: "Shopify — List Orders".into(),
            description: "Retrieve a list of recent orders from the Shopify e-commerce store. Useful for checking order status, fulfillment, or customer purchases.".into(),
            mcp_name: "shopify_list_orders".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit of orders to retrieve" },
                    "status": { "type": "string", "description": "Status filter" }
                }
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["shopify:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["ecommerce".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.stripe.list_payments@v1".into(),
            display_name: "Stripe — List Payments".into(),
            description: "Retrieve a list of recent payments and transactions from Stripe. Useful for verifying refunds, charges, or overall revenue status.".into(),
            mcp_name: "stripe_list_payments".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Limit of payments to retrieve" },
                    "status": { "type": "string", "description": "Status filter" }
                }
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Connector,
            required_scopes: vec!["stripe:read".into()],
            egress_class: EgressClass::B2b,
            bundle_membership: vec!["ecommerce".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.b2b.call@v1".into(),
            display_name: "Call B2B Agent".into(),
            description: "Sends a request or query to a registered B2B Agent by providing its DID or alias and a prompt message. Authenticates securely using the user's active WebAuthn-signed Session JWT.".into(),
            mcp_name: "call_b2b_agent".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Target B2B agent DID or alias (e.g. 'company-alpha' or 'did:web:company-alpha.com')" },
                    "prompt": { "type": "string", "description": "The request prompt or details to send to the B2B agent" }
                },
                "required": ["target", "prompt"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.b2b.register@v1".into(),
            display_name: "Register B2B Agent".into(),
            description: "Registers a new B2B Agent in the user's local directory by providing its alias, DID, and endpoint URL.".into(),
            mcp_name: "register_b2b_agent".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "alias": { "type": "string", "description": "Human-readable name or alias for the B2B agent (e.g., 'company-alpha')" },
                    "b2b_agent_did": { "type": "string", "description": "DID of the B2B agent (e.g., 'did:web:company-alpha.com')" },
                    "endpoint_url": { "type": "string", "description": "The B2B agent HTTP endpoint URL" }
                },
                "required": ["alias", "b2b_agent_did", "endpoint_url"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.b2b.list@v1".into(),
            display_name: "List Registered B2B Agents".into(),
            description: "Lists all B2B agents registered in the user's local directory.".into(),
            mcp_name: "list_registered_b2b_agents".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.b2b.discover@v1".into(),
            display_name: "Discover B2B Agents".into(),
            description: "Queries the central registry/gateway to search for publicly available B2B agent endpoints.".into(),
            mcp_name: "discover_b2b_agents".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "search_query": { "type": "string", "description": "Optional search term to filter B2B agents" }
                }
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.reputation.inspect@v1".into(),
            display_name: "Inspect Counterparty Reputation".into(),
            description: "Queries the local ledger and counterparty history to assess past transaction success count, failure count, and whether cold-start peer attestation is required.".into(),
            mcp_name: "reputation_inspect_counterparty".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "counterparty_did": { "type": "string", "description": "DID of the counterparty agent (e.g. 'did:web:supplier.example.com')" }
                },
                "required": ["counterparty_did"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.contract.propose_or_amend@v1".into(),
            display_name: "Propose or Amend Interaction Contract".into(),
            description: "Drafts or amends an Interaction Contract (NICP) with agreed business terms, computes the RFC 8785 canonical digest, pre-signs it with local host key, and links previous contract hash if amending.".into(),
            mcp_name: "contract_propose_or_amend".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "contract_id": { "type": "string", "description": "Unique identifier for the contract" },
                    "counterparty_did": { "type": "string", "description": "DID of the counterparty agent" },
                    "capabilities": { "type": "array", "items": { "type": "string" }, "description": "Target capabilities bound to the contract (e.g. ['io.logistics.freight@v1'])" },
                    "max_amount_minor": { "type": "integer", "description": "Maximum financial ceiling in minor units (e.g. 1500000 for 15,000.00 EUR)" },
                    "currency": { "type": "string", "description": "Currency code (default 'EUR')" },
                    "settlement_terms": { "type": "string", "description": "Commercial settlement terms (e.g. 'Net-15')" },
                    "cancellation_terms": { "type": "string", "description": "Cancellation policy (e.g. '24h notice')" },
                    "previous_contract_hash": { "type": "string", "description": "Optional canonical hash of parent version if amending" },
                    "reputation_receipt_ids": { "type": "array", "items": { "type": "string" }, "description": "Optional receipt IDs from local vault to attach as reputation evidence" }
                },
                "required": ["contract_id", "counterparty_did", "capabilities"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.contract.activate@v1".into(),
            display_name: "Verify and Activate Contract".into(),
            description: "Verifies counterparty Ed25519 signature, structural validity, and canonical hash, then executes the deterministic 9-step activation ceremony transitioning contract to Active state.".into(),
            mcp_name: "contract_verify_and_activate".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "contract_id": { "type": "string", "description": "ID of the contract draft to activate" },
                    "counterparty_attestation": {
                        "type": "object",
                        "description": "Counterparty signature attestation object with contract_hash, signer_did, and signature",
                        "required": ["contract_hash", "signer_did", "signature"]
                    }
                },
                "required": ["contract_id", "counterparty_attestation"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::Write,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.receipt.vault@v1".into(),
            display_name: "Receipt Vault and Verification".into(),
            description: "Manages the agent's proof of good execution vault: saves new receipts, retrieves relevant receipts to present to counterparties, or verifies counterparty-presented receipts.".into(),
            mcp_name: "receipt_present_and_store".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["store", "get_for_presentation", "verify"], "description": "Action to perform in the receipt vault" },
                    "receipt": { "type": "object", "description": "ExecutionReceipt object (required for 'store' and 'verify')" },
                    "capability_id": { "type": "string", "description": "Optional capability filter for 'get_for_presentation'" }
                },
                "required": ["action"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::Vp,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "discovery".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },

        // ── Sandboxed Native Skills & Tools ────────────────
        ToolDescriptor {
            tool_id: "io.lianxi.skill.inspect_schema@v1".into(),
            display_name: "Inspect Schema".into(),
            description: "Inspect schema of dataset (columns, data types, nullability, sample structure)".into(),
            mcp_name: "inspect_schema".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "dataset_path": { "type": "string", "description": "File path or name of the dataset to inspect" }
                },
                "required": ["dataset_path"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.skill.compute_statistics@v1".into(),
            display_name: "Compute Statistics".into(),
            description: "Compute summary statistics (mean, median, stddev, min, max) for numeric columns in a dataset".into(),
            mcp_name: "compute_statistics".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "dataset_path": { "type": "string", "description": "File path or name of dataset" }
                },
                "required": ["dataset_path"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.skill.detect_anomalies@v1".into(),
            display_name: "Detect Anomalies".into(),
            description: "Detect anomalies and outliers in dataset values".into(),
            mcp_name: "detect_anomalies".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "dataset_path": { "type": "string", "description": "File path or name of dataset" }
                },
                "required": ["dataset_path"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.skill.generate_markdown@v1".into(),
            display_name: "Generate Markdown Report".into(),
            description: "Generate a formatted markdown report summarizing dataset analysis results".into(),
            mcp_name: "generate_markdown".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Report title" },
                    "summary": { "type": "string", "description": "Markdown content body" }
                },
                "required": ["title", "summary"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.skill.join_datasets@v1".into(),
            display_name: "Join Datasets".into(),
            description: "Join two datasets on a specified key column".into(),
            mcp_name: "join_datasets".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "left_path": { "type": "string" },
                    "right_path": { "type": "string" },
                    "join_key": { "type": "string" }
                },
                "required": ["left_path", "right_path", "join_key"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.skill.sample_rows@v1".into(),
            display_name: "Sample Rows".into(),
            description: "Sample N rows from a dataset".into(),
            mcp_name: "sample_rows".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "dataset_path": { "type": "string" },
                    "limit": { "type": "integer", "default": 5 }
                },
                "required": ["dataset_path"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into(), "analysis".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.claw.extract_content_from_url@v1".into(),
            display_name: "Extract Content From URL".into(),
            description: "Extract clean text content from a web URL".into(),
            mcp_name: "claw_extract_content_from_url".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Target web page URL" }
                },
                "required": ["url"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
        },
        ToolDescriptor {
            tool_id: "io.lianxi.claw.hello_world@v1".into(),
            display_name: "Hello World Native Tool".into(),
            description: "Echo test native tool".into(),
            mcp_name: "claw_hello_world".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                },
                "required": ["name"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            risk_tier: RiskTier::ReadOnly,
            executor_profile: ExecutorProfile::NativeTool,
            required_scopes: Vec::new(),
            egress_class: EgressClass::Internal,
            bundle_membership: vec!["default_tools".into(), "core".into()],
            version: "1.0.0".into(),
            deprecation: None,
            cron: None,
            app_id: None,
            operation_attributes: Default::default(),
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
            app_id: None,
            operation_attributes: Default::default(),
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
