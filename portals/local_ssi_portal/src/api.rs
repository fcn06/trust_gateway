//! API client functions for the local SSI portal.
//!
//! All HTTP calls to the backend are centralized here.

use reqwasm::http::{Request, RequestCredentials};
use crate::types::*;

/// Helper to create authorization header
pub fn auth_header(token: &str) -> String {
    format!("Bearer {}", token)
}

fn check_status(resp: &reqwasm::http::Response) -> Result<(), String> {
    if resp.ok() {
        Ok(())
    } else {
        Err(format!("Request failed with status: {} {}", resp.status(), resp.status_text()))
    }
}

// === Identity APIs ===

pub async fn list_identities(base_url: &str, token: String) -> Result<Vec<EnrichedIdentity>, String> {
    let resp = Request::get(&format!("{}/identities", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn create_identity(base_url: &str, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/identities", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    check_status(&resp)?;
    Ok(())
}

pub async fn generate_did_web(base_url: &str, req: GenerateDidWebRequest, token: String) -> Result<serde_json::Value, String> {
    let resp = Request::post(&format!("{}/identities/generate_did_web", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    check_status(&resp)?;
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn activate_identity(base_url: &str, did: String, token: String) -> Result<(), String> {
    let req = ActivateRequest { did };
    let resp = Request::post(&format!("{}/identities/activate", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

pub async fn enrich_identity(base_url: &str, did: String, alias: String, is_institutional: bool, token: String) -> Result<(), String> {
    let url = format!("{}/identities/enrich", base_url);
    
    let body = serde_json::json!({
        "did": did,
        "alias": alias,
        "is_institutional": is_institutional
    });
    let resp = Request::post(&url)
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    Ok(())
}

pub async fn get_active_did(base_url: &str, token: String) -> Result<String, String> {
    let resp = Request::get(&format!("{}/identities/active", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    
    // Response is a JSON string like "did:twin:..." - need to parse it
    let text = resp.text().await.map_err(|e| e.to_string())?;
    // Strip surrounding quotes if present (JSON string response)
    let did = text.trim().trim_matches('"').to_string();
    Ok(did)
}

pub async fn publish_did(base_url: &str, user_id: String) -> Result<String, String> {
    let body = serde_json::json!({ "user_id": user_id }).to_string();
    let resp = Request::post(&format!("{}/identities/publish", base_url))
        .credentials(RequestCredentials::Include)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    check_status(&resp)?;
    resp.text().await.map_err(|e| e.to_string())
}

pub async fn get_published_dids(base_url: &str, user_id: String) -> Result<Vec<String>, String> {
    let resp = Request::get(&format!("{}/identities/published?user_id={}", base_url, user_id))
        .credentials(RequestCredentials::Include)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    resp.json().await.map_err(|e| e.to_string())
}

// === Messaging APIs ===

pub async fn send_message(base_url: &str, req: SendMessageRequest, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/messaging/send", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

pub async fn send_ledgerless_request(base_url: &str, req: SendLedgerlessRequest, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/messaging/send_ledgerless", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

pub async fn get_messages(base_url: &str, token: String) -> Result<Vec<PlainDidcomm>, String> {
    let resp = Request::get(&format!("{}/messaging/messages", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json().await.map_err(|e| e.to_string())
}

// === Policy APIs ===

pub async fn get_policies(base_url: &str, token: String) -> Result<Vec<ConnectionPolicy>, String> {
    let resp = Request::get(&format!("{}/acl/policies", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn update_policy(base_url: &str, policy: ConnectionPolicy, token: String) -> Result<(), String> {
    let req = UpdatePolicyRequest { policy };
    let resp = Request::post(&format!("{}/acl/policies", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

// === Invitation APIs ===

pub async fn generate_invitation(base_url: &str, token: String) -> Result<OobInvitation, String> {
    let resp = Request::get(&format!("{}/invitations/generate", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn accept_invitation(base_url: &str, invitation: OobInvitation, token: String) -> Result<(), String> {
    let req = HandshakeRequest { invitation };
    let resp = Request::post(&format!("{}/invitations/accept", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

// === Contact Request APIs ===

pub async fn get_contact_requests(base_url: &str, token: String) -> Result<Vec<ContactRequest>, String> {
    let resp = Request::get(&format!("{}/contact_requests", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    let response: ContactRequestsResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(response.requests)
}

pub async fn accept_contact_request(base_url: &str, id: String, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/contact_requests/{}/accept", base_url, id))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

pub async fn refuse_contact_request(base_url: &str, id: String, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/contact_requests/{}/refuse", base_url, id))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

// === Profile APIs ===

pub async fn get_profile(base_url: &str, token: String) -> Result<UserProfile, String> {
    let resp = Request::get(&format!("{}/profile/get", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json().await.map_err(|e| e.to_string())
}

pub async fn update_profile(base_url: &str, profile: UserProfile, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/profile/update", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&profile).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

// === Recovery APIs ===

pub async fn set_recovery(base_url: &str, nickname: String, secret: String, token: String) -> Result<(), String> {
    let req = SetRecoveryRequest { nickname, secret };
    let resp = Request::post(&format!("{}/recovery", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&req).unwrap())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

// === Remote Access APIs ===

pub async fn link_remote(base_url: &str, token: String) -> Result<String, String> {
    let resp = Request::post(&format!("{}/link-remote", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    check_status(&resp)?;

    #[derive(serde::Deserialize)]
    struct LinkResponse { code: String }
    
    let link: LinkResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(link.code)
}

// === Escalation Request APIs ===

pub async fn get_escalation_requests(base_url: &str, token: String) -> Result<Vec<EscalationRequest>, String> {
    let resp = Request::get(&format!("{}/escalation_requests", base_url))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    check_status(&resp)?;
    let response: EscalationRequestsResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(response.requests)
}

pub async fn approve_escalation_request(base_url: &str, id: String, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/escalation_requests/{}/approve", base_url, id))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

pub async fn deny_escalation_request(base_url: &str, id: String, token: String) -> Result<(), String> {
    let resp = Request::post(&format!("{}/escalation_requests/{}/deny", base_url, id))
        .credentials(RequestCredentials::Include)
        .header("Authorization", &auth_header(&token))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.ok() { Ok(()) } else { Err(format!("HTTP {}", resp.status())) }
}

