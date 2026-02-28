use axum::{routing::get, Router};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig, consumer::DeliverPolicy};
use sqlx::postgres::PgPoolOptions;
use futures::StreamExt;
use std::sync::Arc;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;
use rand::rngs::OsRng;

pub fn encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce); // 12-byte nonce

    cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce); // 12-byte nonce

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {:?}", e))
}

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

pub async fn setup_postgres(postgres_url: &str) -> sqlx::PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(postgres_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, username TEXT, email TEXT)"
    )
    .execute(&pool)
    .await
    .expect("Failed to create table");

    pool
}

pub fn create_router(js: nats::jetstream::Context, pool: sqlx::PgPool) -> Router {
    let js_clone = js.clone();
    let pool_clone = pool.clone();
    Router::new()
        .route("/", get(handler))
        .route("/publish", get(move || async move {
            js_clone.publish("influx.events.test", "Hello from Axum!".into()).await.unwrap();
            "Message published to NATS JetStream!".to_string()
        }))
        .route("/add_user", get(move || {
            let pool_inner = pool_clone.clone();
            async move {
                let id = uuid::Uuid::new_v4();
                let username = "test_user";
                let email = "test@example.com";
                sqlx::query(
                    "INSERT INTO users (id, username, email) VALUES ($1, $2, $3)"
                )
                .bind(id)
                .bind(username)
                .bind(email)
                .execute(&pool_inner)
                .await
                .unwrap();
                format!("User {} added to PostgreSQL!", username)
            }
        }))
        .route("/encrypt_message", get(|| async {
            let plaintext = b"This is a secret message.";
            let mut key_bytes = [0u8; 32];
            let mut csprng = OsRng;
            csprng.fill_bytes(&mut key_bytes);
            let mut nonce_bytes = [0u8; 12];
            csprng.fill_bytes(&mut nonce_bytes);

            let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();
            let decrypted = decrypt(&encrypted, &key_bytes, &nonce_bytes).unwrap();

            format!("Original: {:?}\nEncrypted: {:?}\nDecrypted: {:?}", plaintext, encrypted, decrypted)
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
    let pool = setup_postgres("postgres://influx:password@postgres:5432/influx_db").await;
    let app = create_router(js.clone(), pool);

    start_consumer(js, stream_name).await;

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await
        .unwrap();
}

pub async fn handler() -> String {
    "Hello, InFlux Backend!".to_string()
}
