// ─────────────────────────────────────────────────────────────
// TrustEnvelope — Canonical Message Envelope (P2)
// ─────────────────────────────────────────────────────────────

use serde::{Deserialize, Serialize};

/// Canonical message envelope for all NATS publish/consume boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEnvelope<T> {
    pub schema_version: u16,
    pub tenant_id: String,
    pub action_id: String,
    pub trace_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_fingerprint: Option<String>,
    pub idempotency_key: String,
    pub payload: T,
}

impl<T> TrustEnvelope<T> {
    pub fn new(tenant_id: impl Into<String>, action_id: impl Into<String>, payload: T) -> Self {
        Self {
            schema_version: 1,
            tenant_id: tenant_id.into(),
            action_id: action_id.into(),
            trace_id: uuid::Uuid::new_v4().to_string(),
            issued_at: chrono::Utc::now(),
            auth_context: None,
            policy_fingerprint: None,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            payload,
        }
    }
    pub fn with_auth_context(mut self, subject: impl Into<String>) -> Self {
        self.auth_context = Some(subject.into()); self
    }
    pub fn with_policy_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.policy_fingerprint = Some(fp.into()); self
    }
    pub fn with_trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = id.into(); self
    }
}

/// Payload: Action proposed by agent for gateway evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    pub tool_name: String,
    pub canonical_args: serde_json::Value,
    pub input_hash: String,
    pub source: String,
}

/// Payload: Granted action dispatched to executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedAction {
    pub grant_jwt: String,
    pub tool_id: String,
    pub tool_version: String,
    pub canonical_args: serde_json::Value,
    pub input_hash: String,
    pub reply_subject: String,
}

/// Payload: Result of executor invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    pub executor_profile: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip() {
        let env = TrustEnvelope::new("t", "a", ProposedAction {
            tool_name: "test".into(),
            canonical_args: serde_json::json!({}),
            input_hash: "h".into(),
            source: "s".into(),
        }).with_auth_context("did:twin:u").with_policy_fingerprint("fp");
        let json = serde_json::to_string(&env).unwrap();
        let r: TrustEnvelope<ProposedAction> = serde_json::from_str(&json).unwrap();
        assert_eq!(r.schema_version, 1);
        assert_eq!(r.auth_context, Some("did:twin:u".into()));
    }

    #[test]
    fn trace_propagation() {
        let orig = TrustEnvelope::new("t", "a", ProposedAction {
            tool_name: "t".into(), canonical_args: serde_json::json!({}),
            input_hash: "h".into(), source: "s".into(),
        });
        let tid = orig.trace_id.clone();
        let down = TrustEnvelope::new("t", "a", GrantedAction {
            grant_jwt: "j".into(), tool_id: "t".into(), tool_version: "v1".into(),
            canonical_args: serde_json::json!({}), input_hash: "h".into(),
            reply_subject: "r".into(),
        }).with_trace_id(&tid);
        assert_eq!(down.trace_id, tid);
    }
}
