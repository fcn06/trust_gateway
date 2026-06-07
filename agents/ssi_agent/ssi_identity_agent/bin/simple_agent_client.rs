//! A simple HTTP client example to test the A2A client.

use a2a_rs::{
    HttpClient,
    domain::{Message, Part},
    services::AsyncA2AClient,
};
use clap::{Parser};
use serde_json::Value;

use configuration::setup_logging;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Host to bind the server to
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    /// Port to connect to
    #[clap(long, default_value = "8080")]
    port: String,
    #[clap(long, default_value = "warn")]
    log_level: String,
    #[clap(long)]
    user_query: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    // Parse command-line arguments
    let args = Args::parse();
    setup_logging(&args.log_level);

    let bind_address = format!("http://{}:{}", args.host, args.port);
    println!("Server listening on: {}", bind_address);

    // Initializing client with bearer token
    let client = HttpClient::with_auth(bind_address.to_string(), "285a36b587f005e7321ec8d46a973bb1".to_string());

    println!("##############################################################");

    let task_id = format!("task-{}", uuid::Uuid::new_v4());
    let message_id = uuid::Uuid::new_v4().to_string();
    
    println!("\nUser_Query : {}", args.user_query);
    
    let message = Message::builder()
        .role(a2a_rs::domain::Role::User)
        .parts(vec![Part::Text {
            text: args.user_query.clone(),
            metadata: None,
        }])
        .metadata(serde_json::Map::new()) // No special metadata
        .message_id(message_id)
        .build();

    println!("Sending message to agent to process task ...\n");

    let task = client
        .send_task_message(&task_id, &message, None, Some(50))
        .await?;

    println!("\nGot response with status: {:?}", task.status.state);

    if let Some(response_message) = task.status.message {
        println!("\nAgent response:");
        for part in response_message.parts {
            match part {
                Part::Text { text, .. } => {
                    // Attempt to parse the text as JSON
                    match serde_json::from_str::<Value>(&text) {
                        Ok(Value::Object(map)) => {
                            if let Some(text_value) = map.get("text_response") {
                                if let Some(s) = text_value.as_str() {
                                    let cleaned_s = s.trim_matches('"');
                                    println!("  {}", cleaned_s);
                                } else {
                                    println!("  [Non-string text_response value] {}", text_value);
                                }
                            } else {
                                println!("  [JSON object without text_response] {}", text);
                            }
                        },
                        Ok(Value::String(s)) => {
                            let cleaned_s = s.trim_matches('"');
                            println!("{}", cleaned_s);
                        }
                        _ => println!("  {}", text), 
                    }
                },
                _ => println!("  [Non-text content]"),
            }
        }
    }

    println!("##############################################################");

    Ok(())
}
