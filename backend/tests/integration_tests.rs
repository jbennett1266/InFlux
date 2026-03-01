mod common;
use common::{create_test_server, get_resources, cleanup_database};
use tokio::time::{sleep, Duration};
use serde_json::json;

#[tokio::test]
async fn test_auth_and_messaging_flow() {
    let server = create_test_server().await;
    let res = get_resources().await;
    cleanup_database(&res.session).await;

    // 1. Register
    let auth_payload = json!({
        "username": "tester",
        "password": "password123"
    });
    let reg_res = server.post("/register").json(&auth_payload).await;
    reg_res.assert_status(axum::http::StatusCode::CREATED);

    // 2. Login
    let login_res = server.post("/login").json(&auth_payload).await;
    login_res.assert_status(axum::http::StatusCode::OK);
    let auth_data: serde_json::Value = login_res.json();
    let token = auth_data["access_token"].as_str().unwrap();

    // 3. Publish (Protected)
    let msg_payload = json!({
        "content": "Auth protected message"
    });
    let pub_res = server.post("/publish")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap())
        .json(&msg_payload).await;
    pub_res.assert_status(axum::http::StatusCode::OK);
    pub_res.assert_text("Sent");

    // 4. Retrieve (Protected)
    sleep(Duration::from_millis(500)).await;
    let get_res = server.get("/messages")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap())
        .await;
    get_res.assert_status_ok();
    let messages: Vec<serde_json::Value> = get_res.json();
    assert!(!messages.is_empty());
}

#[tokio::test]
async fn test_unauthorized_access() {
    let server = create_test_server().await;
    let response = server.get("/messages").await;
    response.assert_status_unauthorized();
}
