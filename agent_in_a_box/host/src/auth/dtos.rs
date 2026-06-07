use serde::Deserialize;

#[derive(Deserialize)]
pub struct StartRegRequest {
    pub username: String,
    #[serde(default)]
    pub invite_code: Option<String>,
}
#[derive(Deserialize)]
pub struct FinishRegRequest { pub session_id: String, pub response: String }
#[derive(Deserialize)]
pub struct StartLoginRequest { pub username: String }
#[derive(Deserialize)]
pub struct FinishLoginRequest { pub session_id: String, pub response: String }

#[derive(Deserialize)]
pub struct SetRecoveryRequest { pub nickname: String, pub secret: String }

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

