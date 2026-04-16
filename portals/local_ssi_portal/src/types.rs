//! Data Transfer Objects for local SSI portal.
//!
//! Contains all serializable types used for API communication.

use serde::{Deserialize, Serialize};

// === Config ===

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PortalConfig {
    #[serde(default)]
    pub api_base_url: String,
    #[serde(default)]
    pub connector_url: Option<String>,
    #[serde(default)]
    pub did_restaurant: Option<String>,
    #[serde(default)]
    pub kitchen_menu_visible: bool,
}


impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            api_base_url: String::new(),
            connector_url: None,
            did_restaurant: None,
            kitchen_menu_visible: false,
        }
    }
}

// === Messages ===

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct PlainDidcomm {
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: Option<String>,
    pub body: serde_json::Value,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub created_time: Option<i64>,
    pub expires_time: Option<i64>,
    pub thid: Option<String>,
    pub pthid: Option<String>,
    pub attachments: Option<serde_json::Value>,
    pub status: Option<String>,
    pub alias: Option<String>,
}

#[derive(Serialize)]
pub struct SendMessageRequest {
    pub to: String,
    pub body: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub thid: Option<String>,
}

#[derive(Serialize)]
pub struct SendLedgerlessRequest {
    pub target_did: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct GenerateDidWebRequest {
    pub domain: String,
}

// === Policies ===

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct ConnectionPolicy {
    pub did: String,
    pub alias: String,
    pub permissions: Vec<String>,
    pub status: String,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct UpdatePolicyRequest {
    pub policy: ConnectionPolicy,
}

// === Identities ===

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct EnrichedIdentity {
    pub did: String,
    pub alias: String,
    #[serde(default)]
    pub is_institutional: bool,
}

#[derive(Serialize)]
pub struct CreateIdentityRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct ActivateRequest {
    pub did: String,
}

// === Contact Requests ===

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContactRequest {
    pub id: String,
    pub owner_did: String,
    pub sender_did: String,
    pub role: Option<String>,
    pub request_msg: serde_json::Value,
    pub status: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContactRequestsResponse {
    pub requests: Vec<ContactRequest>,
}

// === Recovery ===

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct SetRecoveryRequest {
    pub nickname: String,
    pub secret: String,
}

// === Authentication ===

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct RegistrationCookie {
    pub aid: String,            // NATS Account ID
    pub lpk: String,            // Link Public Key (Base64)
    pub rly: String,            // Relay Endpoint URL
    pub uid: Option<String>,    // Hashed User Nickname (for UI display)
    /// Real tenant UUID from the tenant_registry. When present,
    /// this MUST be used instead of `aid` for all tenant-scoped operations.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Deserialize)]
pub struct FinishRegResponse {
    pub success: bool,
    pub user_id: String,
    pub registration_cookie: Option<RegistrationCookie>,
}

#[derive(Deserialize)]
pub struct FinishLoginResponse {
    pub token: String,
    pub user_id: String,
    pub registration_cookie: RegistrationCookie,
}

// === Invitations ===

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct InvitationBody {
    pub goal_code: String,
    pub goal: String,
    pub accept: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct OobInvitation {
    pub id: String,
    #[serde(rename = "type")]
    pub invitation_type: String,
    pub from: String,
    pub body: InvitationBody,
}

#[derive(Serialize)]
pub struct HandshakeRequest {
    pub invitation: OobInvitation,
}

// === Profile ===

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub country: Option<String>,
}

// === Escalation Requests ===

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EscalationRequest {
    pub id: String,
    pub user_did: String,
    pub tool_name: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub nats_reply_subject: String,
    #[serde(default)]
    pub requester_did: String,
    #[serde(default)]
    pub owner_user_id: Option<String>,
    #[serde(default)]
    pub arguments: Option<serde_json::Value>,
    // Trust Gateway v5 extensions
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub proof_required: bool,
    #[serde(default)]
    pub proof_request: Option<serde_json::Value>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub proof_verification: Option<serde_json::Value>,
    /// Enriched approval payload from Trust Gateway (ActionReview)
    #[serde(default)]
    pub action_review: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct EscalationRequestsResponse {
    pub requests: Vec<EscalationRequest>,
}

