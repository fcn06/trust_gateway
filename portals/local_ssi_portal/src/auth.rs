//! WebAuthn authentication helpers.

use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;
use web_sys::{window, PublicKeyCredential, CredentialCreationOptions, CredentialRequestOptions, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse};
use js_sys::{Object, Reflect, Uint8Array, JSON};
use reqwasm::http::Request;
use base64::{Engine as _, engine::general_purpose};

use crate::types::{RegistrationCookie, FinishRegResponse, FinishLoginResponse};

/// Perform WebAuthn registration flow
pub async fn perform_webauthn_register(base_url: &str, username: &str, invite_code: Option<String>) -> Result<Option<RegistrationCookie>, String> {
    let mut body = serde_json::json!({ "username": username });
    if let Some(code) = invite_code {
        body["invite_code"] = serde_json::json!(code);
    }

    let start_res = Request::post(&format!("{}/webauthn/register/start", base_url))
        .credentials(reqwasm::http::RequestCredentials::Include)
        .body(serde_json::to_string(&body).unwrap())
        .header("Content-Type", "application/json")
        .send().await.map_err(|e| e.to_string())?;

    if !start_res.ok() {
        let status = start_res.status();
        let body_text = start_res.text().await.unwrap_or_default();
        return Err(format!("Registration start failed: HTTP {} - {}", status, body_text));
    }

    let start_json: serde_json::Value = start_res.json().await.map_err(|e| format!("JSON Parse Error: {}", e))?;
    let session_id = start_json["session_id"].as_str().ok_or("No session_id")?.to_string();
    let options_json = start_json["options"].to_string();

    let window = window().ok_or("No window")?;
    let credentials = window.navigator().credentials();

    let opts_js_val = JSON::parse(&options_json).map_err(|e| format!("{:?}", e))?;
    let opts_obj = Object::from(opts_js_val);
    fix_binary_fields(&opts_obj, "create")?;
    
    let opts: CredentialCreationOptions = opts_obj.unchecked_into();
    let promise = credentials.create_with_options(&opts).map_err(|e| format!("{:?}", e))?;
    let result = JsFuture::from(promise).await.map_err(|e| format!("{:?}", e))?;
    
    let cred = PublicKeyCredential::from(result);
    let response = cred.response();
    let attestation_response = response.dyn_into::<AuthenticatorAttestationResponse>()
        .map_err(|_| "Not an attestation response")?;
        
    let att_obj = uint8_to_base64(Uint8Array::new(&attestation_response.attestation_object()));
    let client_data = uint8_to_base64(Uint8Array::new(&attestation_response.client_data_json()));
    
    let cred_json = serde_json::json!({
        "id": cred.id(),
        "rawId": uint8_to_base64(Uint8Array::new(&cred.raw_id())),
        "type": cred.type_(),
        "response": {
            "attestationObject": att_obj,
            "clientDataJSON": client_data
        }
    });

    let finish_res = Request::post(&format!("{}/webauthn/register/finish", base_url))
        .credentials(reqwasm::http::RequestCredentials::Include)
        .body(serde_json::to_string(&serde_json::json!({
            "session_id": session_id,
            "response": serde_json::to_string(&cred_json).unwrap()
        })).unwrap())
        .header("Content-Type", "application/json")
        .send().await.map_err(|e| e.to_string())?;

    if !finish_res.ok() {
        let status = finish_res.status();
        let body_text = finish_res.text().await.unwrap_or_default();
        return Err(format!("Registration finish failed: HTTP {} - {}", status, body_text));
    }

    let resp: FinishRegResponse = finish_res.json().await.map_err(|e| e.to_string())?;
    Ok(resp.registration_cookie)
}

/// Perform WebAuthn login flow
pub async fn perform_webauthn_login(base_url: &str, username: &str) -> Result<(String, String, RegistrationCookie), String> {
    let start_res = Request::post(&format!("{}/webauthn/login/start", base_url))
        .credentials(reqwasm::http::RequestCredentials::Include)
        .body(serde_json::to_string(&serde_json::json!({ "username": username })).unwrap())
        .header("Content-Type", "application/json")
        .send().await.map_err(|e| e.to_string())?;

    if !start_res.ok() {
        let status = start_res.status();
        let body_text = start_res.text().await.unwrap_or_default();
        return Err(format!("Login start failed: HTTP {} - {}", status, body_text));
    }

    let start_json: serde_json::Value = start_res.json().await.map_err(|e| format!("JSON Parse Error: {}", e))?;
    let session_id = start_json["session_id"].as_str().ok_or("No session_id")?.to_string();
    let options_json = start_json["options"].to_string();

    let window = window().ok_or("No window")?;
    let credentials = window.navigator().credentials();

    let opts_js_val = JSON::parse(&options_json).map_err(|e| format!("{:?}", e))?;
    let opts_obj = Object::from(opts_js_val);
    fix_binary_fields(&opts_obj, "get")?;
    
    let opts: CredentialRequestOptions = opts_obj.unchecked_into();
    let promise = credentials.get_with_options(&opts).map_err(|e| format!("{:?}", e))?;
    let result = JsFuture::from(promise).await.map_err(|e| format!("{:?}", e))?;
    
    let cred = PublicKeyCredential::from(result);
    let response = cred.response();
    let assertion_response = response.dyn_into::<AuthenticatorAssertionResponse>()
        .map_err(|_| "Not an assertion response")?;
        
    let auth_data = uint8_to_base64(Uint8Array::new(&assertion_response.authenticator_data()));
    let client_data = uint8_to_base64(Uint8Array::new(&assertion_response.client_data_json()));
    let signature = uint8_to_base64(Uint8Array::new(&assertion_response.signature()));
    let user_handle = assertion_response.user_handle().map(|h| uint8_to_base64(Uint8Array::new(&h)));
    
    let cred_json = serde_json::json!({
        "id": cred.id(),
        "rawId": uint8_to_base64(Uint8Array::new(&cred.raw_id())),
        "type": cred.type_(),
        "response": {
            "authenticatorData": auth_data,
            "clientDataJSON": client_data,
            "signature": signature,
            "userHandle": user_handle
        }
    });

    let finish_res = Request::post(&format!("{}/webauthn/login/finish", base_url))
        .credentials(reqwasm::http::RequestCredentials::Include)
        .body(serde_json::to_string(&serde_json::json!({
            "session_id": session_id,
            "response": serde_json::to_string(&cred_json).unwrap()
        })).unwrap())
        .header("Content-Type", "application/json")
        .send().await.map_err(|e| e.to_string())?;

    if !finish_res.ok() {
        let status = finish_res.status();
        let body_text = finish_res.text().await.unwrap_or_default();
        return Err(format!("Login finish failed: HTTP {} - {}", status, body_text));
    }

    let finish_resp: FinishLoginResponse = finish_res.json().await.map_err(|e| e.to_string())?;
    Ok((finish_resp.token, finish_resp.user_id, finish_resp.registration_cookie))
}

/// Fix binary fields in WebAuthn options (convert base64 to Uint8Array)
fn fix_binary_fields(obj: &Object, mode: &str) -> Result<(), String> {
    let pk_val = Reflect::get(obj, &"publicKey".into()).map_err(|_| "No publicKey")?;
    let pk = Object::from(pk_val);

    // challenge
    if let Ok(c) = Reflect::get(&pk, &"challenge".into()) {
        if let Some(s) = c.as_string() {
            let buf = base64_to_uint8(&s);
            Reflect::set(&pk, &"challenge".into(), &buf).ok();
        }
    }

    // user.id (create)
    if mode == "create" {
        if let Ok(u) = Reflect::get(&pk, &"user".into()) {
            let user = Object::from(u);
            if let Ok(id) = Reflect::get(&user, &"id".into()) {
                if let Some(s) = id.as_string() {
                    let buf = base64_to_uint8(&s);
                    Reflect::set(&user, &"id".into(), &buf).ok();
                }
            }
        }
    }

    // allowCredentials[].id (get)
    if let Ok(creds) = Reflect::get(&pk, &"allowCredentials".into()) {
        if js_sys::Array::is_array(&creds) {
            let arr = js_sys::Array::from(&creds);
            for i in 0..arr.length() {
                let cred = Object::from(arr.get(i));
                if let Ok(id) = Reflect::get(&cred, &"id".into()) {
                    if let Some(s) = id.as_string() {
                        let buf = base64_to_uint8(&s);
                        Reflect::set(&cred, &"id".into(), &buf).ok();
                    }
                }
            }
        }
    }

    Ok(())
}

fn base64_to_uint8(base64: &str) -> Uint8Array {
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(base64).unwrap_or_else(|_| {
        general_purpose::STANDARD.decode(base64).unwrap_or_default()
    });
    Uint8Array::from(decoded.as_slice())
}

fn uint8_to_base64(bytes: Uint8Array) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes.to_vec())
}
