use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MyClaims {
    pub user_id: String,
    pub username: String,
    pub tenant_id: String,
    pub jti: Option<String>,
}

fn main() {
    let key = HS256Key::from_bytes(b"dev-secret-only-for-local-testing");
    let claims = Claims::with_custom_claims(MyClaims {
        user_id: "1cee31be-8322-49b4-9665-a74d02193042".to_string(),
        username: "hyb30".to_string(),
        tenant_id: "2394b791-61be-48d7-8147-1ab6654da302".to_string(),
        jti: Some("manual-test-jti".to_string()),
    }, Duration::from_hours(24));
    
    let token = key.authenticate(claims).unwrap();
    println!("{}", token);
}
