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
async fn test_full_thread_lifecycle_and_permissions() {
    let server = create_test_server().await;
    let res = get_resources().await;
    cleanup_database(&res.session).await;
    sleep(Duration::from_secs(1)).await;

    // 1. Register Alice and Bob (UNIQUE)
    let u_alice = format!("alice_{}", Uuid::new_v4());
    let u_bob = format!("bob_{}", Uuid::new_v4());
    let alice = json!({ "username": u_alice, "password": "password" });
    let bob = json!({ "username": u_bob, "password": "password" });
    server.post("/register").json(&alice).await.assert_status(axum::http::StatusCode::CREATED);
    server.post("/register").json(&bob).await.assert_status(axum::http::StatusCode::CREATED);

    // 2. Login
    let alice_token = server.post("/login").json(&alice).await.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();
    let bob_token = server.post("/login").json(&bob).await.json::<serde_json::Value>()["access_token"].as_str().unwrap().to_string();

    // 3. Alice creates a group
    let thread_res = server.post("/threads")
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&json!({ "name": "Team", "members": [u_bob], "is_group": true })).await;
    let thread_id = thread_res.json::<serde_json::Value>()["id"].as_str().unwrap().to_string();

    // 4. Bob (Non-Owner) attempts to add Charlie (Forbidden)
    let add_res = server.post(&format!("/threads/{}/members", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", bob_token)).unwrap())
        .json(&json!({ "username": "charlie" })).await;
    add_res.assert_status(axum::http::StatusCode::FORBIDDEN);

    // 5. Alice adds Charlie
    let u_charlie = format!("charlie_{}", Uuid::new_v4());
    let charlie = json!({ "username": u_charlie, "password": "password" });
    server.post("/register").json(&charlie).await;
    server.post(&format!("/threads/{}/members", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&json!({ "username": u_charlie })).await.assert_status(axum::http::StatusCode::OK);

    // 6. Alice transfers ownership to Bob
    server.patch(&format!("/threads/{}/owner", thread_id))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .json(&json!({ "new_owner": u_bob })).await.assert_status(axum::http::StatusCode::OK);

    // 7. Alice (Former Owner) attempts to remove Charlie (Forbidden)
    server.delete(&format!("/threads/{}/members/{}", thread_id, u_charlie))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", alice_token)).unwrap())
        .await.assert_status(axum::http::StatusCode::FORBIDDEN);

    // 8. Bob (New Owner) removes Charlie
    server.delete(&format!("/threads/{}/members/{}", thread_id, u_charlie))
        .add_header(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_str(&format!("Bearer {}", bob_token)).unwrap())
        .await.assert_status(axum::http::StatusCode::OK);
}

use uuid::Uuid;
