use std::sync::Arc;
use std::collections::HashMap;
use axum::{
    extract::{State, Json, Path as AxumPath, Query},
    http::{StatusCode, HeaderMap, Method},
    response::IntoResponse,
    Router, routing::post,
};
use serde::Deserialize;
// use serde_json::Value;
use webauthn_rs::prelude::*;
use jwt_simple::prelude::Duration;
use tokio::sync::oneshot;
use anyhow::Result;
use hex;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::RngCore;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key, KeyInit, aead::Aead};
use futures::StreamExt;
use jwt_simple::prelude::MACLike; 

use crate::shared_state::WebauthnSharedState;
use crate::commands::{VaultCommand, AclCommand};
use crate::logic::{compute_local_subject, calculate_blind_key};
use crate::dto::{RegistrationCookie, LinkRemoteResponse, MyClaims, TenantRecord, TenantMembership, TenantInvite}; 
use crate::handlers::api::{process_accept_invitation_logic, process_send_message_logic, process_get_messages_logic};
use crate::dto::OobInvitation;

use super::dtos::*;
use super::logic::*;

pub async fn start_registration_handler(State(shared): State<Arc<WebauthnSharedState>>, Json(payload): Json<StartRegRequest>) -> Result<Json<serde_json::Value>, StatusCode> {
    match start_registration_logic(&shared, payload.username, payload.invite_code).await {
        Ok((session_id, ccr)) => Ok(Json(serde_json::json!({
            "session_id": session_id,
            "options": ccr
        }))),
        Err(e) => {
            tracing::error!("Registration start error: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn finish_registration_handler(State(shared): State<Arc<WebauthnSharedState>>, Json(payload): Json<FinishRegRequest>) -> impl IntoResponse {
    let sid = payload.session_id.clone();
    tracing::info!("Finishing registration for session: {}", sid);
    match finish_registration_logic(shared.clone(), payload.session_id, payload.response).await {
        Ok((success, user_id, cookie)) => {
            if success {
                let cookie_json = serde_json::to_string(&cookie).unwrap_or_default();
                let mut response = Json(serde_json::json!({ 
                    "success": true,
                    "user_id": user_id,
                    "registration_cookie": cookie
                })).into_response();

                if let Ok(hv) = axum::http::HeaderValue::from_str(&format!("ssi_registration_cookie={}; Secure; SameSite=None; Path=/; Max-Age=31536000", urlencoding::encode(&cookie_json))) {
                    response.headers_mut().append(axum::http::header::SET_COOKIE, hv);
                }
                response
            } else {
                tracing::warn!("Registration finish logic returned false for session: {} (likely mismatched challenge or expired session)", sid);
                StatusCode::BAD_REQUEST.into_response()
            }
        },
        Err(e) => {
            tracing::error!("Registration finish error for session {}: {:?}", sid, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        },
    }
}

pub async fn start_login_handler(State(shared): State<Arc<WebauthnSharedState>>, Json(payload): Json<StartLoginRequest>) -> Result<Json<serde_json::Value>, StatusCode> {
    match start_login_logic(&shared, payload.username).await {
        Ok((session_id, rcr)) => Ok(Json(serde_json::json!({
            "session_id": session_id,
            "options": rcr
        }))),
        Err(e) => {
            tracing::error!("Login start error: {:?}", e);
            Err(StatusCode::NOT_FOUND)
        },
    }
}

pub async fn finish_login_handler(State(shared): State<Arc<WebauthnSharedState>>, Json(payload): Json<FinishLoginRequest>) -> impl IntoResponse {
    match finish_login_logic(shared.clone(), payload.session_id, payload.response).await {
        Ok((token, user_id, username, cookie)) => {
            let cookie_json = serde_json::to_string(&cookie).unwrap_or_default();
            
            let mut response = Json(serde_json::json!({ 
                "token": token.clone(),
                "user_id": user_id.clone(),
                "username": username.clone(),
                "registration_cookie": cookie
            })).into_response();

            let headers = response.headers_mut();
            
            let cookies = vec![
                format!("ssi_token={}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=7200", token),
                format!("ssi_username={}; Secure; SameSite=None; Path=/; Max-Age=7200", username),
                format!("ssi_user_id={}; Secure; SameSite=None; Path=/; Max-Age=7200", user_id),
                format!("ssi_registration_cookie={}; Secure; SameSite=None; Path=/; Max-Age=31536000", urlencoding::encode(&cookie_json)),
            ];

            for cookie_str in cookies {
                if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie_str) {
                    headers.append(axum::http::header::SET_COOKIE, hv);
                }
            }

            response
        },
        Err(e) => {
            tracing::error!("Login finish error: {:?}", e);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

pub async fn get_profile_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<UserProfile>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;
    let username = claims.username;

    // Blinded Key: HMAC(user_id, house_salt)
    let key = calculate_blind_key(&user_id, &shared.house_salt);

    let mut profile = UserProfile {
        user_id: user_id.clone(),
        username: username.clone(),
        country: None,
    };

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("user_profiles") {
            if let Ok(Some(entry)) = store.get(&key).await {
                // Decrypt
                let enc_key_bytes = {
                    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared.house_salt).expect("HMAC error");
                    mac.update(user_id.as_bytes());
                    mac.finalize().into_bytes().to_vec()
                };
                
                let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key_bytes));
                if entry.len() > 24 {
                    let nonce = XNonce::from_slice(&entry[0..24]);
                    let ciphertext = &entry[24..];
                    if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                         if let Ok(p) = serde_json::from_slice::<UserProfile>(&plaintext) {
                             profile = p;
                         }
                    }
                }
            }
        }
    }

    Ok(Json(profile))
}

pub async fn update_profile_handler(
    State(shared): State<Arc<WebauthnSharedState>>, 
    headers: HeaderMap, 
    body: String
) -> impl IntoResponse {
    let req: UpdateProfileRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };
    
    let claims = match extract_claims(&shared, &headers).await {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
    };
    let user_id = claims.user_id;
    let username = claims.username;

    let profile = UserProfile {
        user_id: user_id.clone(),
        username: username.clone(),
        country: req.country,
    };

    let key = calculate_blind_key(&user_id, &shared.house_salt);

    // Encrypt
    let enc_key_bytes = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared.house_salt).expect("HMAC error");
        mac.update(user_id.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key_bytes));
    
    let mut nonce_bytes = [0u8; 24];
    {
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce_bytes);
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = match serde_json::to_vec(&profile) {
        Ok(p) => p,
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(c) => c,
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    
    let mut payload = Vec::with_capacity(24 + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    let kv_stores = match shared.kv_stores.as_ref() {
        Some(k) => k,
        None => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let store = match kv_stores.get("user_profiles") {
        Some(s) => s,
        None => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if store.put(key, payload.into()).await.is_err() {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Json(profile).into_response()
}

pub async fn set_recovery_config_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    Json(payload): Json<SetRecoveryRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let _user_id = claims.user_id;

    // TODO: Recovery config was tied to the beacon protocol, which has been removed
    // in the hybrid pivot. This endpoint is kept as a stub for future re-implementation
    // using the new architecture (e.g., MLS-based recovery groups).
    tracing::warn!("⚠️ Recovery config is not yet implemented in the hybrid architecture");
    Ok(Json(serde_json::json!({ "status": "success", "message": "Recovery config endpoint (stub)" })))
}

pub async fn link_remote_access_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<LinkRemoteResponse>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;
    let username = claims.username;

    let (nkey_tx, nkey_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::DeriveLinkNkey { 
        user_id: user_id.clone(), 
        resp: nkey_tx 
    }).await;
    
    let link_public_key = match nkey_rx.await {
        Ok(Ok(pk)) => pk,
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let (hmac_tx, hmac_rx) = oneshot::channel();
    let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { 
        user_id: user_id.clone(), 
        resp: hmac_tx 
    }).await;
    
    let account_id = match hmac_rx.await {
        Ok(Ok(secret)) => {
             let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).unwrap();
             mac.update(b"login");
             let result = mac.finalize();
             hex::encode(result.into_bytes())
        },
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let code = uuid::Uuid::new_v4().to_string()[0..6].to_uppercase();

    // Look up tenant for the cookie
    let tenant_id = lookup_user_tenant(&shared, &user_id).await;

    let record = RegistrationCookie {
        aid: account_id,
        lpk: link_public_key,
        rly: shared.config.service_gateway_base_url.clone(),
        nid: crate::logic::compute_node_id(&shared.house_salt),
        uid: Some(hex::encode(sha2::Sha256::digest(username.as_bytes()))[0..16].to_string()),
        tenant_id,
    };

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(provision_store) = kv_stores.get("provisioning") {
            let record_bytes = serde_json::to_vec(&record).unwrap();
            provision_store.put(code.clone(), record_bytes.into()).await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    tracing::info!("🔗 Created Bridge Code: {} for user: {}", code, user_id);

    Ok(Json(LinkRemoteResponse { code }))
}

/// Generate a 6-char staff invite code for the caller's tenant.
/// The code is valid for 7 days and grants the "staff" role.
pub async fn generate_tenant_invite_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    let tenant_id = lookup_user_tenant(&shared, &user_id).await
        .ok_or(StatusCode::NOT_FOUND)?;

    let code = uuid::Uuid::new_v4().to_string()[..6].to_uppercase();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let invite = TenantInvite {
        code: code.clone(),
        tenant_id: tenant_id.clone(),
        role: "staff".to_string(),
        created_by: user_id,
        created_at: now,
        expires_at: now + 86400 * 7, // 7 days
    };

    if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("tenant_invites")) {
        kv.put(&code, serde_json::to_vec(&invite).unwrap().into()).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    } else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    tracing::info!("🎟️ Generated tenant invite {} for tenant {}", code, tenant_id);

    Ok(Json(serde_json::json!({
        "code": code,
        "tenant_id": tenant_id,
        "expires_in_seconds": 86400 * 7
    })))
}

/// Return the current user's tenant info (id, display_name, role).
pub async fn get_tenant_info_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let claims = extract_claims(&shared, &headers).await?;
    let user_id = claims.user_id;

    // Look up membership
    let membership = if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("user_tenant_membership")) {
        if let Ok(Some(entry)) = kv.get(&user_id).await {
            serde_json::from_slice::<Vec<TenantMembership>>(&entry)
                .unwrap_or_default()
                .into_iter()
                .next()
        } else {
            None
        }
    } else {
        None
    };

    if let Some(mem) = membership {
        if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("tenant_registry")) {
            if let Ok(Some(entry)) = kv.get(&mem.tenant_id).await {
                if let Ok(record) = serde_json::from_slice::<TenantRecord>(&entry) {
                    return Ok(Json(serde_json::json!({
                        "tenant_id": record.tenant_id,
                        "display_name": record.display_name,
                        "owner_user_id": record.owner_user_id,
                        "role": mem.role
                    })));
                }
            }
        }
    }

    Ok(Json(serde_json::json!({ "tenant_id": null })))
}

pub async fn check_handshake_status_handler(
    State(shared): State<Arc<WebauthnSharedState>>,
    headers: HeaderMap,
    AxumPath(thid): AxumPath<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let expected_token = std::env::var("SHOP_TOKEN").unwrap_or_else(|_| "demo-token".to_string());
    
    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);
    
    if token != expected_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("sovereign_kv") {
             if let Ok(mut keys_stream) = store.keys().await {
                 while let Some(Ok(key)) = keys_stream.next().await {
                      if let Ok(Some(entry)) = store.get(&key).await {
                          match serde_json::from_slice::<serde_json::Value>(&entry) {
                              Ok(json_msg) => {
                                  let msg_thid = json_msg["thid"].as_str();
                                  let msg_typ = json_msg["typ"].as_str().or_else(|| json_msg["type"].as_str());
                                  
                                  if msg_thid == Some(&thid) {
                                      if let Some(typ) = msg_typ {
                                          let typ_lower = typ.to_lowercase();
                                          if typ_lower.contains("response") || 
                                             typ_lower.contains("success") || 
                                             typ_lower.contains("accepted") ||
                                             typ_lower.contains("handshake") ||
                                             typ_lower.contains("login") ||
                                             typ_lower.contains("newsletter")
                                          {
                                               return Ok(Json(json_msg));
                                          }
                                      }
                                  }
                              },
                              Err(_) => {},
                          }
                      }
                 }
             }
        }
    }
    
    Err(StatusCode::NOT_FOUND)
}


pub async fn subscribe_user_to_global_logins(shared: Arc<WebauthnSharedState>, user_id: String) {
    if let Some(_nc) = &shared.nats {
         // 1. Attempt to resolve AID (hash) from local persistent KV first (allows subscription when Vault is locked)
         let mut hash_opt = None;
         if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("userid_to_aid")) {
             if let Ok(Some(entry)) = kv.get(&user_id).await {
                 if let Ok(val) = String::from_utf8(entry.to_vec()) {
                     hash_opt = Some(val);
                 }
             }
         }

         // 2. Fallback to Vault derivation if not in KV (e.g. first time or migration)
         if hash_opt.is_none() {
             let (tx, rx) = oneshot::channel();
             let _ = shared.vault_cmd_tx.send(VaultCommand::GetHmacSecret { user_id: user_id.clone(), resp: tx }).await;
             
             if let Ok(Ok(secret)) = rx.await {
                 let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).unwrap();
                 mac.update(b"login");
                 let hash = hex::encode(mac.finalize().into_bytes());
                 
                 // Persist for next startup
                 if let Some(kv) = shared.kv_stores.as_ref().and_then(|m| m.get("userid_to_aid")) {
                     let _ = kv.put(&user_id, hash.clone().into()).await;
                 }
                 hash_opt = Some(hash);
             }
         }

         if let Some(hash) = hash_opt {
             let shared_clone = shared.clone();
             
             // Populate portal_id_map for O(1) dispatch
             if let Ok(mut map) = shared.portal_id_map.lock() {
                 map.insert(hash.clone(), user_id.clone());
             }

             tracing::info!("🌍 [O(1)] Registered portal hash for {} (AID: {})", user_id, hash);
             
             // No more individual subscriptions here! 
             // All incoming portal traffic will be caught by the Node Wildcard in loops.rs
             // and dispatched via handle_portal_request.
          }
    }
}

pub async fn handle_portal_request(
    shared: Arc<WebauthnSharedState>,
    category: &str,
    hash: &str,
    action: &str,
    payload: Vec<u8>,
    reply: Option<String>,
) {
    // 1. Resolve User ID from Portal Hash (AID)
    let user_id = {
        let map = shared.portal_id_map.lock().unwrap();
        match map.get(hash).cloned() {
            Some(uid) => uid,
            None => {
                tracing::debug!("⚠️ Unknown portal hash: {}", hash);
                return;
            }
        }
    };

    let nc = match &shared.nats {
        Some(nc) => nc.clone(),
        None => return,
    };

    match category {
        "auth" => {
            tracing::info!("🌍 Received Global Login Assertion for {}", user_id);
            let (tx, rx) = oneshot::channel();
            let _ = shared.identity_cmd_tx.send(crate::commands::IdentityCommand::ProcessGlobalLogin { 
                assertion: payload, 
                resp: tx 
            }).await;
            
            if let Some(reply_subject) = reply {
                let response_payload = match rx.await {
                    Ok(Ok(true)) => {
                        tracing::info!("✅ Global Login Verified for {}", user_id);
                        serde_json::json!({ "status": "success", "message": "Login initiated" })
                    },
                    Ok(Ok(false)) => serde_json::json!({ "status": "failure", "message": "Login refused" }),
                    Ok(Err(e)) => serde_json::json!({ "status": "error", "message": e }),
                    Err(e) => serde_json::json!({ "status": "error", "message": format!("Channel error: {}", e) }),
                };
                let _ = nc.publish(reply_subject, serde_json::to_vec(&response_payload).unwrap().into()).await;
            }
        },
        "inbox" => {
            match action {
                "accept" => {
                    if let Ok(invitation) = serde_json::from_slice::<OobInvitation>(&payload) {
                        let result = process_accept_invitation_logic(shared.clone(), user_id, invitation).await;
                        let resp = match result {
                            Ok(val) => val,
                            Err(e) => serde_json::json!({ "status": "error", "message": e }),
                        };
                        if let Some(r) = reply {
                             let _ = nc.publish(r, serde_json::to_vec(&resp).unwrap().into()).await;
                        }
                    }
                },
                "messages" => {
                    let result = process_get_messages_logic(shared.clone(), user_id, None).await;
                    let resp = match result {
                        Ok(val) => serde_json::to_value(val).unwrap_or(serde_json::Value::Null),
                        Err(e) => serde_json::json!({ "status": "error", "message": e }),
                    };
                    if let Some(r) = reply {
                        let _ = nc.publish(r, serde_json::to_vec(&resp).unwrap().into()).await;
                    }
                },
                _ => tracing::warn!("⚠️ Unhandled inbox action: {}", action),
            }
        },
        "outbound" => {
            if action == "send" {
                if let Ok(req) = serde_json::from_slice::<serde_json::Value>(&payload) {
                    let to_did = req["to_did"].as_str().unwrap_or_default().to_string();
                    let body = req["body"].as_str().unwrap_or_default().to_string();
                    let typ = req["typ"].as_str().unwrap_or("https://didcomm.org/message/2.0/default").to_string();
                    let from_did = req["from_did"].as_str().map(|s| s.to_string());
                    let result = process_send_message_logic(shared.clone(), user_id, from_did, to_did, body, typ, None).await;
                    let resp = match result {
                        Ok(val) => val,
                        Err(e) => serde_json::json!({ "status": "error", "message": e }),
                    };
                    if let Some(r) = reply {
                        let _ = nc.publish(r, serde_json::to_vec(&resp).unwrap().into()).await;
                    }
                }
            }
        },
        "acl" => {
            if action == "policies" {
                if let Ok(active_did) = resolve_active_did_for_user(shared.clone(), &user_id).await {
                    let (tx, rx) = oneshot::channel();
                    let _ = shared.acl_cmd_tx.send(AclCommand::GetPolicies { owner: active_did, resp: tx }).await;
                    let policies = rx.await.unwrap_or_default();
                    if let Some(r) = reply {
                         let _ = nc.publish(r, serde_json::to_vec(&policies).unwrap().into()).await;
                    }
                } else if let Some(r) = reply {
                    let _ = nc.publish(r, b"[]".to_vec().into()).await;
                }
            }
        },
        "identity" => {
            if action == "active" {
                if let Ok(did) = resolve_active_did_for_user(shared.clone(), &user_id).await {
                    if let Some(r) = reply {
                        let resp = serde_json::json!({ "did": did });
                        let _ = nc.publish(r, serde_json::to_vec(&resp).unwrap().into()).await;
                    }
                } else if let Some(r) = reply {
                     let _ = nc.publish(r, b"{}".to_vec().into()).await;
                }
            }
        },
        "invitations" => {
            if action == "generate" {
                 use crate::dto::{InvitationBody};
                 if let Ok(active_did) = resolve_active_did_for_user(shared.clone(), &user_id).await {
                     let invitation_id = uuid::Uuid::new_v4().to_string();
                     let inv = crate::dto::OobInvitation {
                         id: invitation_id,
                         r#type: "https://didcomm.org/out-of-band/1.0/invitation".to_string(),
                         from: active_did.clone(),
                         body: InvitationBody {
                             goal_code: "connect".to_string(),
                             goal: "Establish connection".to_string(),
                             accept: vec!["didcomm/v2".to_string()],
                         },
                         services: None,
                      };
                      if let Some(r) = reply {
                          let _ = nc.publish(r, serde_json::to_vec(&inv).unwrap().into()).await;
                      }
                 }
            }
        },
        _ => {
             tracing::warn!("⚠️ Unhandled portal category: {} for user {}", category, user_id);
        }
    }
}

pub async fn subscribe_to_global_logins(shared: Arc<WebauthnSharedState>) {
    // 1. Iterate all users in username_to_userid
    // 2. Call subscribe_user_to_global_logins for each
    if let Some(kv_stores) = &shared.kv_stores {
        if let Some(store) = kv_stores.get("username_to_userid") {
            // Need to scan keys
            match store.keys().await {
                Ok(mut keys) => {
                    while let Some(Ok(key)) = keys.next().await {
                        if let Ok(Some(val)) = store.get(&key).await {
                             if let Ok(user_id) = String::from_utf8(val.to_vec()) {
                                subscribe_user_to_global_logins(shared.clone(), user_id).await;
                            }
                        }
                    }
                },
                Err(e) => tracing::error!("Failed to list keys in username_to_userid: {}", e),
            }
        }
    }
}
