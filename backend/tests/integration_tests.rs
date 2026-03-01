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
async fn test_full_thread_lifecycle_integration() {
    let server = create_test_server().await;
    let res = get_resources().await;
    cleanup_database(&res.session).await;

    // 1. Register users
    let alice_creds = json!({ "username": "alice", "password": "password123" });
    let bob_creds = json!({ "username": "bob", "password": "password123" });
    server.post("/register").json(&alice_creds).await.assert_status(axum::http::StatusCode::CREATED);
    server.post("/register").json(&bob_creds).await.assert_status(axum::http::StatusCode::CREATED);

    // 2. Login Alice
    let login_res = server.post("/login").json(&alice_creds).await;
    let auth_data: serde_json::Value = login_res.json();
    let alice_token = auth_data["access_token"].as_str().unwrap();

    // 3. Create a Group Thread
    let thread_payload = json!({
        "name": "Secret Group",
        "members": ["bob"], 
        "is_group": true
    });
    let thread_res = server.post("/threads")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&thread_payload).await;
    thread_res.assert_status(axum::http::StatusCode::OK);
    let thread_id = thread_res.json::<serde_json::Value>()["id"].as_str().unwrap().to_string();

    // 4. List Threads for Alice
    let list_res = server.get("/threads")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .await;
    list_res.assert_status(axum::http::StatusCode::OK);
    let threads: Vec<serde_json::Value> = list_res.json();
    assert!(!threads.is_empty());

    // 5. Publish message to thread
    let msg_payload = json!({
        "content": "Encrypted group message"
    });
    server.post(&format!("/publish/{}", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&msg_payload).await.assert_status(axum::http::StatusCode::OK);

    // 6. Retrieve messages for thread
    sleep(Duration::from_millis(500)).await;
    let get_res = server.get(&format!("/messages/{}", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .await;
    get_res.assert_status(axum::http::StatusCode::OK);
    let messages: Vec<serde_json::Value> = get_res.json();
    assert!(!messages.is_empty());
}

#[tokio::test]
async fn test_thread_membership_isolation() {
    let server = create_test_server().await;
    let res = get_resources().await;
    cleanup_database(&res.session).await;

    // 1. Register UNIQUE Alice and Eve
    let alice = json!({ "username": "alice_iso", "password": "password" });
    let eve = json!({ "username": "eve_iso", "password": "password" });
    server.post("/register").json(&alice).await.assert_status(axum::http::StatusCode::CREATED);
    server.post("/register").json(&eve).await.assert_status(axum::http::StatusCode::CREATED);

    // 2. Login
    let alice_token = server.post("/login").json(&alice).await.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();
    let eve_token = server.post("/login").json(&eve).await.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();

    // 3. Alice creates a private thread
    let thread_res = server.post("/threads")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&json!({ "name": "Private", "members": [], "is_group": false })).await;
    let thread_id = thread_res.json::<serde_json::Value>()["id"].as_str().unwrap().to_string();

    // 4. Eve attempts to read Alice's thread
    let access_res = server.get(&format!("/messages/{}", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", eve_token)).unwrap())
        .await;
    access_res.assert_status(axum::http::StatusCode::FORBIDDEN);
}
