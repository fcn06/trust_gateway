use std::time::Duration;
use tokio::time::timeout;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nc = async_nats::connect("127.0.0.1:4222").await?;
    let js = async_nats::jetstream::new(nc);
    
    let stream_name = "agent_audit_stream"; 
    let stream = match js.get_stream(stream_name).await {
        Ok(s) => s,
        Err(e) => {
            println!("Stream error: {}", e);
            return Ok(());
        }
    };
    
    let consumer = stream.create_consumer(async_nats::jetstream::consumer::pull::Config {
        deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
        ..Default::default()
    }).await?;
    
    let mut messages = consumer.fetch().max_messages(300).expires(Duration::from_millis(300)).messages().await?;
    
    let mut events = 0;
    
    loop {
        match timeout(Duration::from_millis(50), messages.next()).await {
            Ok(Some(Ok(m))) => {
                events += 1;
                let _ = m.ack().await;
            }
            Ok(Some(Err(e))) => {
                println!("Message error: {}", e);
                break;
            }
            Ok(None) => {
                println!("Stream ended safely.");
                break;
            }
            Err(_) => {
                println!("Timeout hit! Events retrieved: {}", events);
                break;
            }
        }
    }
    
    println!("Total fetched with 50ms: {}", events);
    Ok(())
}
