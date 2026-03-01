use axum::{routing::get, Router, Json};
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

#[derive(Serialize, Deserialize)]
pub struct KeyPairResponse {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub message: String,
    pub recipient_public_key: String,
}

#[derive(Serialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub recipient_private_key: String,
}

// --- E2EE Logic ---

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

// --- Setup Functions ---

pub async fn setup_nats(stream_name: &str, nats_url: &str, subject: &str) -> nats::jetstream::Context {
    let nc = nats::connect(nats_url).await.expect("Failed to connect to NATS");
    let js = jetstream::new(nc);

    match js.get_stream(stream_name).await {
        Ok(_) => println!("Stream {} already exists.", stream_name),
        Err(_) => {
            println!("Creating stream {}.\n", stream_name);
            js.create_stream(StreamConfig {
                name: stream_name.to_string(),
                subjects: vec![subject.to_string()],
                ..Default::default()
            }).await.expect("Failed to create stream");
        }
    };
    js
}

pub async fn setup_cassandra(cassandra_url: &str) -> Arc<Session> {
    let mut retry_count = 0;
    let max_retries = 15;
    let session = loop {
        match SessionBuilder::new()
            .known_nodes(&[cassandra_url])
            .build()
            .await {
                Ok(s) => break s,
                Err(e) => {
                    if retry_count >= max_retries {
                        panic!("Failed to connect to Cassandra after {} retries: {:?}", max_retries, e);
                    }
                    println!("Cassandra not ready, retrying in 5s... ({}/{})", retry_count + 1, max_retries);
                    sleep(Duration::from_secs(5)).await;
                    retry_count += 1;
                }
            }
    };

    let scylla_session = Arc::new(session);
    scylla_session.query("CREATE KEYSPACE IF NOT EXISTS influx_ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}", &[]).await.ok();
    scylla_session.query("CREATE TABLE IF NOT EXISTS influx_ks.users (id UUID PRIMARY KEY, username TEXT, email TEXT)", &[]).await.ok();
    scylla_session
}

pub fn create_router(js: nats::jetstream::Context, scylla_session: Arc<Session>) -> Router {
    let js_clone = js.clone();
    let scylla_session_clone = scylla_session.clone();
    
    Router::new()
        .route("/", get(handler))
        .route("/publish", get(move || {
            let js_inner = js_clone.clone();
            async move {
                let unique_subject = format!("influx.events.test.{}", uuid::Uuid::new_v4());
                match js_inner.publish(unique_subject, "Hello from Axum!".into()).await {
                    Ok(_) => "Message published to NATS JetStream!".to_string(),
                    Err(e) => format!("Error: {:?}", e)
                }
            }
        }))
        .route("/add_user", get(move || {
            let session_clone = scylla_session_clone.clone();
            async move {
                let id = uuid::Uuid::new_v4();
                let username = "test_user";
                let email = "test@example.com";
                match session_clone.query("INSERT INTO influx_ks.users (id, username, email) VALUES (?, ?, ?)", (id, username, email)).await {
                    Ok(_) => format!("User {} added to Cassandra!", username),
                    Err(e) => format!("Error: {:?}", e)
                }
            }
        }))
        .route("/generate_keys", get(|| async {
            let alice_secret = StaticSecret::random_from_rng(OsRng);
            let alice_public = PublicKey::from(&alice_secret);
            
            Json(KeyPairResponse {
                public_key: general_purpose::STANDARD.encode(alice_public.as_bytes()),
                private_key: general_purpose::STANDARD.encode(alice_secret.to_bytes()),
            })
        }))
}

pub async fn start_consumer(js: nats::jetstream::Context, stream_name: &str) {
    let stream = js.get_stream(stream_name).await.unwrap();
    let consumer_config = nats::jetstream::consumer::pull::Config {
        name: Some("my_consumer".to_string()),
        deliver_policy: DeliverPolicy::All,
        ..Default::default()
    };
    let consumer = stream.create_consumer(consumer_config).await.unwrap();
    tokio::spawn(async move {
        let mut messages = consumer.messages().await.unwrap();
        while let Some(Ok(msg)) = messages.next().await {
            println!("Received message: {:?}", msg.payload);
            msg.ack().await.unwrap();
        }
    });
}

#[tokio::main]
async fn main() {
    let stream_name = "influx_events";
    let js = setup_nats(stream_name, "nats://nats:4222", "influx.events.>").await;
    let scylla_session = setup_cassandra("cassandra:9042").await;
    let app = create_router(js.clone(), scylla_session);

    start_consumer(js, stream_name).await;

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

pub async fn handler() -> String {
    "Hello, InFlux Backend!".to_string()
}
