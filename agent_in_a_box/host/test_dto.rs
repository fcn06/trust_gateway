use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlainDidcommDto {
    pub id: String,
    #[serde(rename = "type", alias = "typ")]
    pub typ: String,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub thid: Option<String>,
    pub body: serde_json::Value,
}

pub struct MlsMessage {
    pub ciphertext: Vec<u8>,
}

fn map_dto_to_wit(payload: PlainDidcommDto) -> MlsMessage {
    let ciphertext = serde_json::to_vec(&payload).unwrap_or_default();
    MlsMessage { ciphertext }
}

fn map_wit_to_dto(msg: &MlsMessage) -> PlainDidcommDto {
    let body_str = String::from_utf8_lossy(&msg.ciphertext).to_string();
    let body_json = serde_json::from_str::<serde_json::Value>(&body_str).unwrap_or(serde_json::Value::String(body_str.clone()));
    
    let mut extracted_to = None;
    if let Some(to_val) = body_json.get("to") {
        if let Some(arr) = to_val.as_array() {
            extracted_to = Some(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());
        }
    }

    PlainDidcommDto {
        id: "test".into(),
        typ: "test".into(),
        from: None,
        to: extracted_to,
        thid: None,
        body: body_json,
    }
}

fn main() {
    let dto = PlainDidcommDto {
        id: "1".into(),
        typ: "t".into(),
        from: Some("me".into()),
        to: Some(vec!["you".into()]),
        thid: None,
        body: serde_json::json!({"content": "hello"}),
    };
    let w = map_dto_to_wit(dto);
    println!("ciphertext: {:?}", String::from_utf8_lossy(&w.ciphertext));
    let d = map_wit_to_dto(&w);
    println!("to: {:?}", d.to);
}
