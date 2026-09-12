use anyhow::{Context, Result};
use async_nats::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use trust_core::action::NormalizedActionProposal;
use trust_core::tool_registry::ToolDescriptor;
use trust_model::CallChainContext;

/// Output formats supported by the CLI adapter
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum CliOutputFormat {
    #[default]
    Json,
    Table,
    Raw,
}

/// Invocation context supplied by the CLI / caller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliInvocationContext {
    pub tenant_id: String,
    pub caller_did: Option<String>,
    pub trace_id: String,
    pub session_jwt: Option<String>,
    pub output_format: CliOutputFormat,
}

impl Default for CliInvocationContext {
    fn default() -> Self {
        Self {
            tenant_id: "default-tenant".to_string(),
            caller_did: Some("did:key:cli-operator".to_string()),
            trace_id: uuid::Uuid::new_v4().to_string(),
            session_jwt: None,
            output_format: CliOutputFormat::Json,
        }
    }
}

/// Response received from Gateway action proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProposalResponse {
    pub action_id: String,
    pub status: String,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub escalation: Option<String>,
}

/// Tool invoker that communicates with Trust Gateway via NATS (Policy Enforcement Point)
pub struct ToolInvoker {
    nats: Client,
    timeout: Duration,
}

impl ToolInvoker {
    pub fn new(nats: Client) -> Self {
        Self {
            nats,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Computes canonical RFC 8785 JSON input hash for the arguments.
    pub fn compute_input_hash(arguments: &serde_json::Value) -> Result<String> {
        Ok(trust_canonical::canonical_hash(arguments))
    }

    /// Submits the governed action proposal to Trust Gateway and handles output & exit codes.
    pub async fn invoke(
        &self,
        context: &CliInvocationContext,
        tool: &ToolDescriptor,
        arguments: serde_json::Value,
    ) -> Result<i32> {
        let input_hash = Self::compute_input_hash(&arguments)?;

        let mut call_chain = CallChainContext::new(&context.trace_id);
        call_chain.call_stack.push(tool.mcp_name.clone());
        call_chain
            .invocation_counts
            .insert(tool.mcp_name.clone(), 1);

        let proposal = NormalizedActionProposal {
            tenant_id: context.tenant_id.clone(),
            workspace_id: "default".to_string(),
            requester_id: context
                .caller_did
                .clone()
                .unwrap_or_else(|| "did:key:cli-operator".to_string()),
            source_type: "cli".to_string(),
            auth_method: "session".to_string(),
            auth_level: "level3_session".to_string(),
            scopes: tool.required_scopes.clone(),
            tool_server: "trust_gateway".to_string(),
            tool_name: tool.mcp_name.clone(),
            action_name: tool.mcp_name.clone(),
            action_arguments: arguments.clone(),
            payload: serde_json::json!({
                "session_jwt": context.session_jwt.clone().unwrap_or_default(),
                "input_hash": input_hash,
                "_meta": {
                    "io.lianxi": {
                        "correlation_id": context.trace_id.clone(),
                    }
                }
            }),
            transport_metadata: None,
            planning_context: None,
            contract_context: None,
            call_chain_context: Some(call_chain),
        };

        let subject = format!("trust.v1.{}.action.propose", context.tenant_id);
        let payload = serde_json::to_vec(&proposal)?;

        tracing::debug!("Publishing proposal to NATS subject: {}", subject);

        let response_msg =
            tokio::time::timeout(self.timeout, self.nats.request(subject, payload.into()))
                .await
                .context("NATS proposal request timed out")?
                .context("NATS proposal failed to receive response")?;

        let response: GatewayProposalResponse = serde_json::from_slice(&response_msg.payload)
            .context("Failed to deserialize Gateway proposal response")?;

        match response.status.as_str() {
            "succeeded" | "approved" | "auto_approved" => {
                let output = response.result.unwrap_or(serde_json::json!({
                    "status": "success",
                    "action_id": response.action_id
                }));
                println!("{}", format_output(&output, context.output_format));
                Ok(0)
            }
            "denied" => {
                let err_msg = response
                    .error
                    .unwrap_or_else(|| "Policy denied this action".to_string());
                eprintln!("⛔ Policy Denial (126): {}", err_msg);
                Ok(126)
            }
            "escalation" | "pending_approval" => {
                if let Some(app_id) = response.approval_id {
                    eprintln!(
                        "⏳ Action requires human operator approval [approval_id: {}]",
                        app_id
                    );
                } else {
                    eprintln!("⏳ Action requires approval escalation");
                }
                Ok(130)
            }
            _ => {
                let err_msg = response
                    .error
                    .unwrap_or_else(|| format!("Action failed with status: {}", response.status));
                eprintln!("❌ Execution error: {}", err_msg);
                Ok(1)
            }
        }
    }
}

/// Formats output based on selected output format
pub fn format_output(val: &serde_json::Value, format: CliOutputFormat) -> String {
    match format {
        CliOutputFormat::Json => serde_json::to_string_pretty(val).unwrap_or_default(),
        CliOutputFormat::Raw => {
            if let Some(s) = val.as_str() {
                s.to_string()
            } else {
                val.to_string()
            }
        }
        CliOutputFormat::Table => {
            if let Some(obj) = val.as_object() {
                let mut lines = Vec::new();
                lines.push(format!("{:<25} | {:<40}", "FIELD", "VALUE"));
                lines.push("-".repeat(68));
                for (k, v) in obj {
                    let v_str = if let Some(s) = v.as_str() {
                        s.to_string()
                    } else {
                        v.to_string()
                    };
                    lines.push(format!("{:<25} | {:<40}", k, v_str));
                }
                lines.join("\n")
            } else {
                serde_json::to_string_pretty(val).unwrap_or_default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_input_hash_deterministic() {
        let args1 = serde_json::json!({"b": 2, "a": 1});
        let args2 = serde_json::json!({"a": 1, "b": 2});

        let h1 = ToolInvoker::compute_input_hash(&args1).unwrap();
        let h2 = ToolInvoker::compute_input_hash(&args2).unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_format_output_json_and_table() {
        let val = serde_json::json!({
            "order_id": "123",
            "status": "refunded"
        });

        let json_out = format_output(&val, CliOutputFormat::Json);
        assert!(json_out.contains("\"order_id\": \"123\""));

        let table_out = format_output(&val, CliOutputFormat::Table);
        assert!(table_out.contains("FIELD"));
        assert!(table_out.contains("order_id"));
        assert!(table_out.contains("refunded"));
    }
}
