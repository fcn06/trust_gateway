use std::env;
use futures::StreamExt;

#[tokio::main]
async fn main() {
    let nc = async_nats::connect("nats://localhost:4222").await.unwrap();
    let js = async_nats::jetstream::new(nc);
    let kv = js.get_key_value("escalation_requests").await.unwrap();
    let mut keys = kv.keys().await.unwrap();
    while let Some(Ok(key)) = keys.next().await {
        if let Ok(Some(val)) = kv.get(&key).await {
            println!("Key: {}", key);
            println!("Value: {}", String::from_utf8_lossy(&val));
        }
    }
}
