use reqwest;
use tokio;
use std::net::SocketAddr;
use influx_backend::*;
use tokio::sync::OnceCell;

const LOCAL_BASE_URL: &str = "http://127.0.0.1:3001";
static SERVER_INIT: OnceCell<()> = OnceCell::const_new();

async fn ensure_server_running() {
    SERVER_INIT.get_or_init(|| async {
        let stream_name = "integration_test_stream";
        let js = setup_nats(stream_name, "nats://localhost:4222", "integration.test.>").await;
        let scylla_session = setup_cassandra("localhost:9042").await;
        let app = create_router(js.clone(), scylla_session);

        let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service()).await.unwrap();
        });
        
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await; // Wait for server and Cassandra to be fully ready
    }).await;
}

#[tokio::test]
async fn test_root_route_integration() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running().await;
    let response = reqwest::get(format!("{}/", LOCAL_BASE_URL)).await?.text().await?;
    assert_eq!(response, "Hello, InFlux Backend!");
    Ok(())
}

#[tokio::test]
async fn test_publish_route_integration() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running().await;
    let response = reqwest::get(format!("{}/publish", LOCAL_BASE_URL)).await?.text().await?;
    assert_eq!(response, "Message published to NATS JetStream!");
    Ok(())
}

#[tokio::test]
async fn test_add_user_route_integration() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running().await;
    let response = reqwest::get(format!("{}/add_user", LOCAL_BASE_URL)).await?.text().await?;
    assert!(response.contains("User test_user added to Cassandra!"));
    Ok(())
}

#[tokio::test]
async fn test_encrypt_message_route_integration() -> Result<(), Box<dyn std::error::Error>> {
    ensure_server_running().await;
    let response = reqwest::get(format!("{}/encrypt_message", LOCAL_BASE_URL)).await?.text().await?;
    assert!(response.contains("Original:"));
    assert!(response.contains("Encrypted:"));
    assert!(response.contains("Decrypted:"));
    Ok(())
}
