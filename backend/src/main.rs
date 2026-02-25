use axum::{routing::get, Router};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig};
use scylla::{Session, SessionBuilder};
use std::sync::Arc;
use tokio::task;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use rand_core::RngCore;

// Placeholder for Olm/Megolm integration
// In a real application, this would involve a complex E2E encryption protocol
// with key exchange, session management, and message encryption using Olm/Megolm libraries.
// This example uses AES-GCM as a simple symmetric encryption placeholder.
fn encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::<Aes256Gcm>::from_slice(nonce); // 96-bit nonce

    cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))
}

fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::<Aes256Gcm>::from_slice(nonce); // 96-bit nonce

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {:?}", e))
}

#[tokio::main]
async fn main() {
    // Initialize NATS connection and JetStream context
    let nc = nats::connect("nats://nats:4222").await.unwrap();
    let js = jetstream::new(nc);

    // Ensure a stream exists (e.g., "influx_events")
    let stream_name = "influx_events";
    match js.get_stream(stream_name).await {
        Ok(_) => println!("Stream {} already exists.", stream_name),
        Err(_) => {
            println!("Creating stream {}.\n", stream_name);
            js.create_stream(StreamConfig {
                name: stream_name.to_string(),
                subjects: vec!["influx.events.>".to_string()],
                ..Default::default()
            }).await.unwrap();
        }
    };

    // Initialize ScyllaDB connection
    let scylla_session = Arc::new(
        SessionBuilder::new()
            .known_nodes(&["scylla:9042"])
            .build()
            .await
            .unwrap(),
    );

    // Create keyspace and table
    scylla_session
        .query(
            "CREATE KEYSPACE IF NOT EXISTS influx_ks WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 1}",
            &[],
        )
        .await
        .unwrap();
    scylla_session
        .query(
            "CREATE TABLE IF NOT EXISTS influx_ks.users (id UUID PRIMARY KEY, username TEXT, email TEXT)",
            &[],
        )
        .await
        .unwrap();

    // Publish a test message on a specific route
    let js_clone = js.clone();
    let scylla_session_clone = scylla_session.clone();
    let app = Router::new()
        .route("/", get(handler))
        .route("/publish", get(move || async move {
            js_clone.publish("influx.events.test", "Hello from Axum!".into()).await.unwrap();
            "Message published to NATS JetStream!".to_string()
        }))
        .route("/add_user", get(move || {
            let session_clone = scylla_session_clone.clone();
            async move {
                let id = uuid::Uuid::new_v4();
                let username = "test_user";
                let email = "test@example.com";
                session_clone.query(
                    "INSERT INTO influx_ks.users (id, username, email) VALUES (?, ?, ?)",
                    (id, username, email),
                ).await.unwrap();
                format!("User {} added to ScyllaDB!", username)
            }
        }))
        .route("/encrypt_message", get(|| async {
            let plaintext = b"This is a secret message.";
            let mut key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut key_bytes);
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);

            let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();
            let decrypted = decrypt(&encrypted, &key_bytes, &nonce_bytes).unwrap();

            format!("Original: {:?}\nEncrypted: {:?}\nDecrypted: {:?}", plaintext, encrypted, decrypted)
        }));

    // Subscribe to messages from the stream
    let consumer = js.get_or_create_consumer(stream_name, "my_consumer").await.unwrap();
    tokio::spawn(async move {
        let mut messages = consumer.messages().await.unwrap();
        while let Some(Ok(msg)) = messages.next().await {
            println!("Received message: {:?}", msg.payload);
            msg.ack().await.unwrap();
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler() -> String {
    "Hello, InFlux Backend!".to_string()
}
