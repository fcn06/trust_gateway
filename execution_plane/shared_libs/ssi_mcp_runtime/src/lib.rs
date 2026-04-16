pub mod mcp_client;
pub mod mcp_agent_logic;
pub mod mcp_tools;
pub mod runtime;
pub mod audit;
pub mod llm_policy;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SsiAuthenticationData {
    pub x_envelope: Option<String>,
    pub x_instruction: Option<String>,
    pub jwt: Option<String>,
    pub tenant_id: Option<String>,
}
