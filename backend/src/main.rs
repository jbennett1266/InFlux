use axum::{
    routing::{get, post, delete, patch},
    Router, Json, extract::{Request, Query, Path, Extension},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig};
use scylla::{Session, SessionBuilder};
use futures::StreamExt;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{encode, Header, Algorithm, Validation, EncodingKey, DecodingKey, decode};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};
use tower_http::cors::{Any, CorsLayer};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;
use x25519_dalek::{StaticSecret, PublicKey};
use uuid::Uuid;

const JWT_SECRET: &[u8] = b"influx_secret_key_change_in_production";

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub id: Uuid,
    pub sender: String,
    pub content: String,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub content: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Thread {
    pub id: String,
    pub name: String,
    pub is_group: bool,
    pub owner: String,
}

#[derive(Deserialize)]
pub struct CreateThreadRequest {
    pub name: String,
    pub members: Vec<String>,
    pub is_group: bool,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub username: String,
}

#[derive(Deserialize)]
pub struct TransferOwnerRequest {
    pub new_owner: String,
}

#[derive(Clone)]
pub struct CurrentUser {
    pub username: String,
}

pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Some(auth_header) = auth_header {
        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..];
            match decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::new(Algorithm::HS256)) {
                Ok(data) => {
                    req.extensions_mut().insert(CurrentUser { username: data.claims.sub });
                    return Ok(next.run(req).await);
                },
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

pub async fn setup_nats(stream_name: &str, nats_url: &str, subject: &str) -> nats::jetstream::Context {
    let nc = nats::connect(nats_url).await.expect("Failed to connect to NATS");
    let js = jetstream::new(nc);
    match js.get_stream(stream_name).await {
        Ok(_) => (),
        Err(_) => {
            js.create_stream(StreamConfig {
                name: stream_name.to_string(),
                subjects: vec![subject.to_string()],
                ..Default::default()
            }).await.ok();
        }
    };
    js
}

pub async fn setup_cassandra(cassandra_url: &str) -> Arc<Session> {
    let mut retry_count = 0;
    let session = loop {
        match SessionBuilder::new().known_nodes(&[cassandra_url]).build().await {
            Ok(s) => break s,
            Err(_) if retry_count < 15 => { sleep(Duration::from_secs(5)).await; retry_count += 1; }
            Err(e) => panic!("Cassandra failed: {:?}", e),
        }
    };
    let scylla_session = Arc::new(session);
    scylla_session.query("CREATE KEYSPACE IF NOT EXISTS influx_ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.users (username TEXT PRIMARY KEY, password_hash TEXT, public_key TEXT)", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.messages (channel_id TEXT, message_id UUID, sender TEXT, content TEXT, timestamp BIGINT, PRIMARY KEY (channel_id, timestamp)) WITH CLUSTERING ORDER BY (timestamp DESC)", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.threads (id TEXT PRIMARY KEY, name TEXT, is_group BOOLEAN, owner TEXT)", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.user_threads (username TEXT, thread_id TEXT, thread_name TEXT, is_group BOOLEAN, PRIMARY KEY (username, thread_id))", &[]).await.ok();
    scylla_session
}

pub fn create_router(js: nats::jetstream::Context, scylla_session: Arc<Session>) -> Router {
    let js_shared = js.clone();
    let db_shared = scylla_session.clone();
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    Router::new()
        .route("/publish/:channel_id", post({
            let js = js_shared.clone();
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>, Path(channel_id): Path<String>, Json(payload): Json<SendMessageRequest>| {
                let js = js.clone();
                let db = db.clone();
                async move {
                    let check = db.query("SELECT thread_id FROM influx_ks.user_threads WHERE username = ? AND thread_id = ?", (&user.username, &channel_id)).await;
                    if (channel_id != "global") && (check.is_err() || check.unwrap().rows.and_then(|r| r.into_iter().next()).is_none()) {
                        return (StatusCode::FORBIDDEN, "Not a member").into_response();
                    }
                    let msg_id = Uuid::new_v4();
                    let ts = chrono::Utc::now().timestamp_millis();
                    let _ = db.query("INSERT INTO influx_ks.messages (channel_id, message_id, sender, content, timestamp) VALUES (?, ?, ?, ?, ?)", (&channel_id, msg_id, &user.username, &payload.content, ts)).await;
                    let _ = js.publish(format!("influx.events.{}", channel_id), "broadcast".into()).await;
                    (StatusCode::OK, "Sent").into_response()
                }
            }
        }))
        .route("/messages/:channel_id", get({
            let db = db_shared.clone();
            move |Extension(_user): Extension<CurrentUser>, Path(channel_id): Path<String>| {
                let db = db.clone();
                async move {
                    let check = db.query("SELECT thread_id FROM influx_ks.user_threads WHERE username = ? AND thread_id = ?", (&_user.username, &channel_id)).await;
                    if (channel_id != "global") && (check.is_err() || check.unwrap().rows.and_then(|r| r.into_iter().next()).is_none()) {
                        return (StatusCode::FORBIDDEN, "Not a member").into_response();
                    }
                    let result = db.query("SELECT message_id, sender, content, timestamp FROM influx_ks.messages WHERE channel_id = ? LIMIT 50", (&channel_id,)).await;
                    match result {
                        Ok(rows) => {
                            let mut messages = Vec::new();
                            if let Some(it) = rows.rows {
                                for row in it {
                                    if let Ok((id, sender, content, timestamp)) = row.into_typed::<(Uuid, String, String, i64)>() {
                                        messages.push(Message { id, sender, content, timestamp });
                                    }
                                }
                            }
                            Json(messages).into_response()
                        },
                        Err(_) => Json(vec![] as Vec<Message>).into_response()
                    }
                }
            }
        }))
        .route("/threads", post({
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>, Json(payload): Json<CreateThreadRequest>| {
                let db = db.clone();
                async move {
                    let thread_id = Uuid::new_v4().to_string();
                    let _ = db.query("INSERT INTO influx_ks.threads (id, name, is_group, owner) VALUES (?, ?, ?, ?)", (&thread_id, &payload.name, payload.is_group, &user.username)).await;
                    let mut members = payload.members;
                    if !members.contains(&user.username) { members.push(user.username.clone()); }
                    for member in members {
                        let _ = db.query("INSERT INTO influx_ks.user_threads (username, thread_id, thread_name, is_group) VALUES (?, ?, ?, ?)", (member, &thread_id, &payload.name, payload.is_group)).await;
                    }
                    Json(serde_json::json!({ "id": thread_id })).into_response()
                }
            }
        }).get({
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>| {
                let db = db.clone();
                async move {
                    let result = db.query("SELECT thread_id, thread_name, is_group FROM influx_ks.user_threads WHERE username = ?", (&user.username,)).await;
                    match result {
                        Ok(rows) => {
                            let mut threads = Vec::new();
                            if let Some(it) = rows.rows {
                                for row in it {
                                    if let Ok((id, name, is_group)) = row.into_typed::<(String, String, bool)>() {
                                        let owner_res = db.query("SELECT owner FROM influx_ks.threads WHERE id = ?", (&id,)).await;
                                        let owner = owner_res.ok().and_then(|r| r.rows).and_then(|r| r.into_iter().next()).and_then(|r| r.into_typed::<(String,)>().ok()).map(|(s,)| s).unwrap_or_default();
                                        threads.push(Thread { id, name, is_group, owner });
                                    }
                                }
                            }
                            Json(threads).into_response()
                        },
                        Err(_) => Json(vec![] as Vec<Thread>).into_response()
                    }
                }
            }
        }))
        .route("/threads/:thread_id/members", post({
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>, Path(thread_id): Path<String>, Json(payload): Json<AddMemberRequest>| {
                let db = db.clone();
                async move {
                    let thread_res = db.query("SELECT name, is_group, owner FROM influx_ks.threads WHERE id = ?", (&thread_id,)).await;
                    if let Ok(rows) = thread_res {
                        if let Some(row) = rows.rows.and_then(|r| r.into_iter().next()) {
                            if let Ok((name, is_group, owner)) = row.into_typed::<(String, bool, String)>() {
                                if owner != user.username { return (StatusCode::FORBIDDEN, "Not owner").into_response(); }
                                let _ = db.query("INSERT INTO influx_ks.user_threads (username, thread_id, thread_name, is_group) VALUES (?, ?, ?, ?)", (&payload.username, &thread_id, &name, is_group)).await;
                                return (StatusCode::OK, "Member added").into_response();
                            }
                        }
                    }
                    (StatusCode::NOT_FOUND, "Thread not found").into_response()
                }
            }
        }))
        .route("/threads/:thread_id/members/:username", delete({
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>, Path((thread_id, target_username)): Path<(String, String)>| {
                let db = db.clone();
                async move {
                    let thread_res = db.query("SELECT owner FROM influx_ks.threads WHERE id = ?", (&thread_id,)).await;
                    if let Ok(rows) = thread_res {
                        if let Some(row) = rows.rows.and_then(|r| r.into_iter().next()) {
                            if let Ok((owner,)) = row.into_typed::<(String,)>() {
                                if owner != user.username { return (StatusCode::FORBIDDEN, "Not owner").into_response(); }
                                let _ = db.query("DELETE FROM influx_ks.user_threads WHERE username = ? AND thread_id = ?", (target_username, &thread_id)).await;
                                return (StatusCode::OK, "Member removed").into_response();
                            }
                        }
                    }
                    (StatusCode::NOT_FOUND, "Thread not found").into_response()
                }
            }
        }))
        .route("/threads/:thread_id/owner", patch({
            let db = db_shared.clone();
            move |Extension(user): Extension<CurrentUser>, Path(thread_id): Path<String>, Json(payload): Json<TransferOwnerRequest>| {
                let db = db.clone();
                async move {
                    let thread_res = db.query("SELECT owner FROM influx_ks.threads WHERE id = ?", (&thread_id,)).await;
                    if let Ok(rows) = thread_res {
                        if let Some(row) = rows.rows.and_then(|r| r.into_iter().next()) {
                            if let Ok((owner,)) = row.into_typed::<(String,)>() {
                                if owner != user.username { return (StatusCode::FORBIDDEN, "Not owner").into_response(); }
                                let _ = db.query("UPDATE influx_ks.threads SET owner = ? WHERE id = ?", (&payload.new_owner, &thread_id)).await;
                                return (StatusCode::OK, "Owner updated").into_response();
                            }
                        }
                    }
                    (StatusCode::NOT_FOUND, "Thread not found").into_response()
                }
            }
        }))
        .route_layer(middleware::from_fn(auth_middleware))
        .route("/", get(handler))
        .route("/register", post({
            let db = db_shared.clone();
            move |Json(payload): Json<AuthRequest>| {
                let db = db.clone();
                async move {
                    let salt = SaltString::generate(&mut OsRng);
                    let argon2 = Argon2::default();
                    let password_hash = argon2.hash_password(payload.password.as_bytes(), &salt).unwrap().to_string();
                    match db.query("INSERT INTO influx_ks.users (username, password_hash) VALUES (?, ?)", (payload.username, password_hash)).await {
                        Ok(_) => StatusCode::CREATED.into_response(),
                        Err(e) => { println!("Register Error: {:?}", e); StatusCode::INTERNAL_SERVER_ERROR.into_response() }
                    }
                }
            }
        }))
        .route("/login", post({
            let db = db_shared.clone();
            move |Json(payload): Json<AuthRequest>| {
                let db = db.clone();
                async move {
                    let result = db.query("SELECT password_hash FROM influx_ks.users WHERE username = ?", (payload.username.clone(),)).await;
                    if let Ok(rows) = result {
                        if let Some(row) = rows.rows.and_then(|r| r.into_iter().next()) {
                            if let Ok((hash_str,)) = row.into_typed::<(String,)>() {
                                if let Ok(parsed_hash) = PasswordHash::new(&hash_str) {
                                    if Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash).is_ok() {
                                        return Json(AuthResponse { access_token: create_jwt(&payload.username, 900), refresh_token: create_jwt(&payload.username, 86400) }).into_response();
                                    }
                                }
                            }
                        }
                    }
                    StatusCode::UNAUTHORIZED.into_response()
                }
            }
        }))
        .route("/refresh", post(move |Json(payload): Json<RefreshRequest>| async move {
            match decode::<Claims>(&payload.refresh_token, &DecodingKey::from_secret(JWT_SECRET), &Validation::new(Algorithm::HS256)) {
                Ok(data) => Json(AuthResponse { access_token: create_jwt(&data.claims.sub, 900), refresh_token: create_jwt(&data.claims.sub, 86400) }).into_response(),
                Err(_) => StatusCode::UNAUTHORIZED.into_response()
            }
        }))
        .route("/generate_keys", get(|| async {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            Json(serde_json::json!({ "public_key": general_purpose::STANDARD.encode(public.as_bytes()), "private_key": general_purpose::STANDARD.encode(secret.to_bytes()), })).into_response()
        }))
        .layer(cors)
}

#[tokio::main]
async fn main() {
    let js = setup_nats("influx_events", "nats://nats:4222", "influx.events.>").await;
    let scylla = setup_cassandra("cassandra:9042").await;
    let app = create_router(js, scylla);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

pub async fn handler() -> String { "Hello, InFlux Backend!".to_string() }

pub fn create_jwt(username: &str, expiration_seconds: i64) -> String {
    let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::seconds(expiration_seconds)).expect("valid timestamp").timestamp() as usize;
    let claims = Claims { sub: username.to_owned(), exp: expiration };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap()
}

pub fn derive_shared_secret(my_private: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    let shared = my_private.diffie_hellman(their_public);
    *shared.as_bytes()
}

pub fn symmetric_encrypt(plaintext: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 12]) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("Encryption failed");
    (ciphertext, nonce_bytes)
}

pub fn symmetric_decrypt(ciphertext: &[u8], key: &[u8; 32], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption error: {:?}", e))
}
