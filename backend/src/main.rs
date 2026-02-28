use axum::{routing::{get, post}, Router, Json};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig, consumer::DeliverPolicy};
use scylla::{Session, SessionBuilder};
use futures::StreamExt;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub id: Uuid,
    pub sender: String,
    pub content: String,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct KeyPairResponse {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub sender: String,
    pub content: String,
}

// --- Cryptography ---

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

// --- Infrastructure ---

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
            Err(_) if retry_count < 15 => {
                sleep(Duration::from_secs(5)).await;
                retry_count += 1;
            }
            Err(e) => panic!("Cassandra failed: {:?}", e),
        }
    };
    let scylla_session = Arc::new(session);
    scylla_session.query("CREATE KEYSPACE IF NOT EXISTS influx_ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.users (id UUID PRIMARY KEY, username TEXT, email TEXT)", &[]).await.ok();
    // clustering key for time-based retrieval
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.messages (channel_id TEXT, message_id UUID, sender TEXT, content TEXT, timestamp BIGINT, PRIMARY KEY (channel_id, timestamp)) WITH CLUSTERING ORDER BY (timestamp DESC)", &[]).await.ok();
    scylla_session
}

pub fn create_router(js: nats::jetstream::Context, scylla_session: Arc<Session>) -> Router {
    let js_clone = js.clone();
    let scylla_clone = scylla_session.clone();
    
    Router::new()
        .route("/", get(handler))
        .route("/generate_keys", get(|| async {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            Json(KeyPairResponse {
                public_key: general_purpose::STANDARD.encode(public.as_bytes()),
                private_key: general_purpose::STANDARD.encode(secret.to_bytes()),
            })
        }))
        .route("/publish", post(move |Json(payload): Json<SendMessageRequest>| {
            let js_inner = js_clone.clone();
            let db_inner = scylla_clone.clone();
            async move {
                let msg_id = Uuid::new_v4();
                let ts = chrono::Utc::now().timestamp_millis();
                
                // 1. Persist to Cassandra
                db_inner.query(
                    "INSERT INTO influx_ks.messages (channel_id, message_id, sender, content, timestamp) VALUES ('global', ?, ?, ?, ?)",
                    (msg_id, payload.sender, payload.content, ts)
                ).await.ok();

                // 2. Publish to NATS
                let nats_payload = serde_json::to_vec(&Message {
                    id: msg_id,
                    sender: "system".to_string(), // In real app, derived from auth
                    content: "Message persisted and broadcast".to_string(),
                    timestamp: ts,
                }).unwrap();

                match js_inner.publish("influx.events.global", nats_payload.into()).await {
                    Ok(_) => "Sent".to_string(),
                    Err(_) => "NATS Error".to_string()
                }
            }
        }))
        .route("/messages", get(move || {
            let db_inner = scylla_session.clone();
            async move {
                let result = db_inner.query("SELECT message_id, sender, content, timestamp FROM influx_ks.messages WHERE channel_id = 'global' LIMIT 50", &[]).await;
                match result {
                    Ok(rows) => {
                        let mut messages = Vec::new();
                        if let Some(it) = rows.rows {
                            for row in it {
                                let (id, sender, content, timestamp): (Uuid, String, String, i64) = row.into_typed().unwrap();
                                messages.push(Message { id, sender, content, timestamp });
                            }
                        }
                        Json(messages)
                    },
                    Err(_) => Json(vec![])
                }
            }
        }))
}

pub async fn start_consumer(js: nats::jetstream::Context, stream_name: &str) {
    let stream = js.get_stream(stream_name).await.unwrap();
    let consumer = stream.create_consumer(nats::jetstream::consumer::pull::Config {
        name: Some("msg_store".to_string()),
        ..Default::default()
    }).await.unwrap();
    tokio::spawn(async move {
        let mut messages = consumer.messages().await.unwrap();
        while let Some(Ok(msg)) = messages.next().await {
            msg.ack().await.ok();
        }
    });
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

pub async fn handler() -> String {
    "Hello, InFlux Backend!".to_string()
}
