mod common;
use common::{create_test_server, get_resources, cleanup_database};
use tokio::time::{sleep, Duration};
use serde_json::json;

#[tokio::test]
async fn test_root_route_integration() {
    let server = create_test_server().await;
    let response = server.get("/").await;
    response.assert_text("Hello, InFlux Backend!");
}

#[tokio::test]
async fn test_publish_and_retrieve_integration() {
    let server = create_test_server().await;
    let res = get_resources().await;
    cleanup_database(&res.session).await;

    // 1. Publish a message
    let payload = json!({
        "sender": "test_user",
        "content": "Persistent message test"
    });
    let response = server.post("/publish").json(&payload).await;
    response.assert_text("Sent");

    // 2. Retrieve messages
    sleep(Duration::from_millis(500)).await;
    let response = server.get("/messages").await;
    response.assert_status_ok();
    
    let messages: Vec<serde_json::Value> = response.json();
    assert!(!messages.is_empty());
    assert_eq!(messages[0]["sender"], "test_user");
    assert_eq!(messages[0]["content"], "Persistent message test");
}

#[tokio::test]
async fn test_generate_keys_integration() {
    let server = create_test_server().await;
    let response = server.get("/generate_keys").await;
    response.assert_status_ok();
}
