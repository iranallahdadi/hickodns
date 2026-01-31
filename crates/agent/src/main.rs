use reqwest::Client;
use serde::Serialize;
use uuid::Uuid;
use std::time::Duration;

#[derive(Serialize)]
struct AgentRegistration {
    name: String,
    addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = std::env::var("CONTROL_API").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let client = Client::new();
    let id = Uuid::new_v4();
    let reg = AgentRegistration { name: format!("agent-{}", id), addr: "127.0.0.1:5353".to_string() };
    let res = client.post(format!("{}/api/v1/agents/register", api)).json(&reg).send().await?;
    println!("registered: {}", res.status());
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        // heartbeat (not implemented server side yet)
        let _ = client.post(format!("{}/api/v1/agents/heartbeat", api)).json(&reg).send().await;
    }
}
