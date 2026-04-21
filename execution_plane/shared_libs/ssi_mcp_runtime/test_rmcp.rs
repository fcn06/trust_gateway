use serde::{Deserialize, Serialize};

fn main() {
    let raw = serde_json::json!({
        "content": [{
            "type": "text",
            "text": "some text"
        }],
        "is_error": false
    });
    
    let res: Result<rmcp::model::CallToolResult, _> = serde_json::from_value(raw);
    println!("{:?}", res.is_ok());
    if let Err(e) = res {
        println!("Error: {}", e);
    }
}
