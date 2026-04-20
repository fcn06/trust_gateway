//! Data Transfer Objects for HTTP API and inter-component messaging.
//!
//! Contains request/response types for Axum handlers and WIT mapping functions.

use serde::{Deserialize, Serialize};

use crate::sovereign::gateway::common_types::{ConnectionPolicy, MlsMessage};

// === Core Message DTOs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlainDidcommDto {
    pub id: String,
    #[serde(rename = "type", alias = "typ")]
    pub r#type: String,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub thid: Option<String>,
    pub body: serde_json::Value,
    pub created_time: Option<i64>,
    pub expires_time: Option<i64>,
    pub status: Option<String>,
    pub envelope: Option<String>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub msg: MlsMessage,
    pub envelope: Option<String>,
}

/// Convert an MlsMessage to a PlainDidcommDto for storage/API compatibility.
pub fn map_wit_to_dto(msg: &MlsMessage, envelope: Option<String>) -> PlainDidcommDto {
    let body_str = String::from_utf8_lossy(&msg.ciphertext).to_string();
    tracing::info!("DEBUG map_wit_to_dto: body_str = {}", &body_str);
    let body_json = serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or(serde_json::Value::String(body_str.clone()));
    
    let mut extracted_id = None;
    let mut extracted_thid = None;
    let mut extracted_body = body_json.clone();

    // If body_json is an object containing metadata, extract it
    if let Some(obj) = body_json.as_object() {
        if let Some(id_val) = obj.get("id").and_then(|v| v.as_str()) {
            extracted_id = Some(id_val.to_string());
        }
        if let Some(thid_val) = obj.get("thid").and_then(|v| v.as_str()) {
            extracted_thid = Some(thid_val.to_string());
        }
        if let Some(real_body) = obj.get("body") {
            extracted_body = real_body.clone();
        }
    }

    let mut extracted_to = None;
    
    // First try extracting from the original JSON envelope to prevent nested JSON
    if let Some(env) = &envelope {
        if let Ok(orig_dto) = serde_json::from_str::<serde_json::Value>(env) {
            if let Some(to_val) = orig_dto.get("to") {
                if let Some(arr) = to_val.as_array() {
                    extracted_to = Some(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
                }
            }
            if extracted_thid.is_none() {
                if let Some(thid_val) = orig_dto.get("thid").and_then(|v| v.as_str()) {
                    extracted_thid = Some(thid_val.to_string());
                }
            }
        }
    }

    PlainDidcommDto {
        id: extracted_id.unwrap_or_else(|| format!("mls-{}-{}", msg.group_id, msg.epoch)),
        r#type: msg.content_type.clone(),
        from: Some(msg.sender_target_id.clone()),
        to: extracted_to,
        thid: extracted_thid.or(Some(msg.group_id.clone())),
        body: extracted_body,
        created_time: Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64),
        expires_time: None,
        status: None,
        envelope,
        alias: None,
    }
}

pub fn map_dto_to_wit(payload: PlainDidcommDto) -> MlsMessage {
    // Bundle metadata into ciphertext to ensure the receiver can adopt the same ID
    // and correctly group threads.
    let packet = serde_json::json!({
        "id": payload.id,
        "thid": payload.thid,
        "body": payload.body,
    });

    let ciphertext = serde_json::to_vec(&packet).unwrap_or_default();
    
    MlsMessage {
        group_id: payload.thid.unwrap_or_else(|| payload.id.clone()),
        epoch: 0,
        content_type: payload.r#type,
        ciphertext,
        sender_target_id: payload.from.unwrap_or_default(),
    }
}

// === JWT Claims ===

#[derive(Debug, Serialize, Deserialize)]
pub struct MyClaims {
    pub user_id: String,
    pub username: String,
}

// === Identity DTOs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserIdentityMetadata {
    pub alias: String,
    #[serde(default)]
    pub is_institutional: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnrichedIdentity {
    pub did: String,
    pub alias: String,
    #[serde(default)]
    pub is_institutional: bool,
}

// === Contact Request DTOs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContactRequest {
    pub id: String,
    pub owner_did: String,
    pub sender_did: String,
    pub role: Option<String>,
    pub request_msg: serde_json::Value,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactRequestsResponse {
    pub requests: Vec<ContactRequest>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContactRequestDto {
    pub id: String,
    pub owner_did: String,
    pub sender_did: String,
    pub role: Option<String>,
    pub thid: Option<String>,
    pub request_msg: String,
    pub status: String,
    pub created_at: i64,
}

// === Escalation Request DTOs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EscalationRequest {
    pub id: String,
    pub user_did: String,
    pub tool_name: String,
    pub status: String,          // PENDING, APPROVED, DENIED, PENDING_PROOF, PROOF_VERIFIED, TIMEOUT
    pub created_at: String,
    pub nats_reply_subject: String,
    #[serde(default)]
    pub requester_did: String,
    /// The biological user's ID who owns this escalation request.
    /// Resolved from user_did at storage time via VaultCommand::ResolveDid.
    /// Used to filter requests per-user in the portal UI.
    #[serde(default)]
    pub owner_user_id: Option<String>,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    // ── Trust Gateway extensions (v5) ──
    /// Approval tier: "tier0" (auto), "tier1" (portal click), "tier2" (re-auth), "tier3" (OID4VP proof)
    #[serde(default)]
    pub tier: Option<String>,
    /// Human-readable reason from the policy rule
    #[serde(default)]
    pub reason: Option<String>,
    /// Whether OID4VP proof presentation is required before approval
    #[serde(default)]
    pub proof_required: bool,
    /// OID4VP proof request details (presentation_definition, required_claims, etc.)
    #[serde(default)]
    pub proof_request: Option<serde_json::Value>,
    /// Who approved this request (user_did of approver)
    #[serde(default)]
    pub approved_by: Option<String>,
    /// OID4VP proof verification result (stored after successful proof)
    #[serde(default)]
    pub proof_verification: Option<serde_json::Value>,
    /// Enriched approval payload from Trust Gateway (ActionReview with business diff, risk, etc.)
    #[serde(default)]
    pub action_review: Option<serde_json::Value>,
    // ── Conversation context for post-execution notification ──
    /// Thread ID of the conversation that triggered this escalation.
    /// Used to route the execution result back to the correct chat thread.
    #[serde(default)]
    pub conversation_thid: Option<String>,
    /// DID of the user who sent the original message (the sender in the chat).
    #[serde(default)]
    pub conversation_sender_did: Option<String>,
    /// Institutional DID of the agent that handled the tool call.
    #[serde(default)]
    pub conversation_inst_did: Option<String>,
    /// Host user_id of the agent owner (needed for process_send_message_logic).
    #[serde(default)]
    pub conversation_user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EscalationRequestsResponse {
    pub requests: Vec<EscalationRequest>,
}

// === WebAuthn Request DTOs ===

#[derive(Deserialize)]
pub struct StartRegRequest {
    pub username: String,
    /// Optional invite code to join an existing tenant on sign-up.
    /// If absent, a new personal tenant is auto-created.
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Deserialize)]
pub struct FinishRegRequest {
    pub session_id: String,
    pub response: String,
}

#[derive(Deserialize)]
pub struct StartLoginRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct FinishLoginRequest {
    pub session_id: String,
    pub response: String,
}

// === Identity Request DTOs ===

#[derive(Deserialize)]
pub struct CreateIdentityRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct PublishIdentityRequest {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct UserQuery {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct EnrichIdentityRequest {
    pub did: String,
    pub alias: String,
    pub is_institutional: Option<bool>,
}

#[derive(Deserialize)]
pub struct ActivateIdentityRequest {
    pub did: String,
}

// === ACL Request DTOs ===

#[derive(Deserialize)]
pub struct UpdatePolicyRequest {
    pub policy: ConnectionPolicy,
}

// === Messaging DTOs ===

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub from: Option<String>,
    pub to: String,
    pub body: String,
    #[serde(alias = "type")]
    pub r#type: String,
    pub thid: Option<String>,
}

#[derive(Deserialize)]
pub struct SendLedgerlessRequest {
    pub target_did: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct GenerateDidWebRequest {
    pub domain: String,
}

#[derive(Deserialize)]
pub struct GetMessagesQuery {
    pub recipient: Option<String>,
}

// === Recovery DTOs ===

#[derive(Deserialize)]
pub struct SetRecoveryRequest {
    pub nickname: String,
    pub secret: String,
}

// === MCP DTOs ===

#[derive(Deserialize)]
pub struct McpSignRequest {
    pub instruction: String,
}

#[derive(Serialize)]
pub struct McpSignResponse {
    #[serde(rename = "X-Envelope")]
    pub x_envelope: String,
    #[serde(rename = "X-Instruction")]
    pub x_instruction: String,
}

// === Invitation DTOs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvitationBody {
    pub goal_code: String,
    pub goal: String,
    pub accept: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceEndpoint {
    pub id: String,
    pub r#type: String,
    pub service_endpoint: String,
    pub routing_keys: Vec<String>,
    pub accept: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OobInvitation {
    pub r#type: String,
    pub id: String,
    pub from: String,
    pub body: InvitationBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ServiceEndpoint>>,
}

#[derive(Debug, Deserialize)]
pub struct HandshakeRequest {
    pub invitation: OobInvitation,
}

// === Registration Cookie (Blueprint) ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegistrationCookie {
    pub aid: String,            // NATS Account ID
    pub lpk: String,            // Link Public Key (Base64)
    pub rly: String,            // Relay Endpoint URL
    pub nid: String,            // Node ID (for O(1) subjects)
    pub uid: Option<String>,    // Hashed User Nickname (for UI display)
    /// Real tenant UUID from the tenant_registry. When present,
    /// this MUST be used instead of `aid` for all tenant-scoped operations.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

// === Multi-Tenant Structures ===

/// A business/organization tenant record in the `tenant_registry` KV.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TenantRecord {
    pub tenant_id: String,
    pub display_name: String,
    pub owner_user_id: String,
    pub created_at: i64,
}

/// Links a user to one or more tenants via the `user_tenant_membership` KV.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TenantMembership {
    pub tenant_id: String,
    pub role: String,      // "owner", "staff", "customer"
    pub joined_at: i64,
}

/// Short-lived invite code stored in `tenant_invites` KV.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TenantInvite {
    pub code: String,
    pub tenant_id: String,
    pub role: String,           // Role granted on join (e.g., "staff")
    pub created_by: String,     // user_id of the creator
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkRemoteResponse {
    pub code: String,
}

// === Profile DTOs ===

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct UserProfile {
    pub user_id: String,
    pub username: String,
    pub country: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct UpdateProfileRequest {
    pub country: Option<String>,
}

// === Finish Registration Response ===

#[derive(Debug, Serialize)]
pub struct FinishRegResponse {
    pub success: bool,
    pub user_id: String,
    pub cookie: Option<RegistrationCookie>,
}

// === Gateway DTOs ===

#[derive(Deserialize)]
pub struct RegisterGatewayRequest {
    pub did: String,
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
}

pub struct GetPublishedDidsRequest {
    pub user_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dto_mapping() {
        let dto = PlainDidcommDto {
            id: "msg-123".into(),
            r#type: "t".into(),
            from: Some("me".into()),
            to: Some(vec!["you".into()]),
            thid: Some("thread-456".into()),
            body: serde_json::json!({"content": "hello"}),
            created_time: None,
            expires_time: None,
            status: None,
            envelope: None,
            alias: None,
        };
        let w = map_dto_to_wit(dto.clone());
        let env = serde_json::to_string(&dto).ok();
        println!("ciphertext: {:?}", String::from_utf8_lossy(&w.ciphertext));
        let d = map_wit_to_dto(&w, env);
        println!("to: {:?}, id: {:?}, thid: {:?}", d.to, d.id, d.thid);
        assert_eq!(d.id, "msg-123");
        assert_eq!(d.thid, Some("thread-456".into()));
        assert_eq!(d.body["content"], "hello");
    }
}
