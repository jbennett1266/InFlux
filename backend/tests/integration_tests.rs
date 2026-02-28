mod common;
use common::{create_test_server, get_resources, cleanup_database};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_root_route_integration() {
    let server = create_test_server().await;
    let response = server.get("/").await;
    response.assert_text("Hello, InFlux Backend!");
}

#[tokio::test]
async fn test_publish_route_integration() {
    let server = create_test_server().await;
    let response = server.get("/publish").await;
    response.assert_text("Message published to NATS JetStream!");
}

#[tokio::test]
async fn test_add_user_route_integration() {
    let server = create_test_server().await;
    let res = get_resources().await;
    
    // Cleanup before test
    cleanup_database(&res.session).await;
    sleep(Duration::from_millis(500)).await;

    let response = server.get("/add_user").await;
    response.assert_text("User test_user added to Cassandra!");
}

#[tokio::test]
async fn test_encrypt_message_route_integration() {
    let server = create_test_server().await;
    let response = server.get("/encrypt_message").await;
    
    response.assert_status_ok();
    let text = response.text();
    assert!(text.contains("Original:"));
    assert!(text.contains("Encrypted:"));
    assert!(text.contains("Decrypted:"));
}
