use axum::{routing::get, Router};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig, consumer::DeliverPolicy};
use scylla::SessionBuilder;
use futures::StreamExt;
use std::sync::Arc;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;
use rand::rngs::OsRng;

fn encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce); // 12-byte nonce

    cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))
}

fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce); // 12-byte nonce

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
                subjects: vec!["influx.events.>".to_string(), "influx.events.*".to_string()],
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
            let mut csprng = OsRng;
            csprng.fill_bytes(&mut key_bytes);
            let mut nonce_bytes = [0u8; 12];
            csprng.fill_bytes(&mut nonce_bytes);

            let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();
            let decrypted = decrypt(&encrypted, &key_bytes, &nonce_bytes).unwrap();

            format!("Original: {:?}\nEncrypted: {:?}\nDecrypted: {:?}", plaintext, encrypted, decrypted)
        }));

    // Subscribe to messages from the stream
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

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await
        .unwrap();
}

async fn handler() -> String {
    "Hello, InFlux Backend!".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let plaintext = b"This is a test message.";
        let mut key_bytes = [0u8; 32];
        let mut csprng = OsRng;
        csprng.fill_bytes(&mut key_bytes);
        let mut nonce_bytes = [0u8; 12];
        csprng.fill_bytes(&mut nonce_bytes);

        let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();
        let decrypted = decrypt(&encrypted, &key_bytes, &nonce_bytes).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encryption_failure() {
        let plaintext = b"Short message";
        let key_bytes = [0u8; 32];
        let nonce_bytes = [0u8; 12];

        let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();

        // Corrupt the ciphertext to test decryption failure
        let mut corrupted_ciphertext = encrypted.clone();
        corrupted_ciphertext[0] ^= 0x01;

        let result = decrypt(&corrupted_ciphertext, &key_bytes, &nonce_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_failure() {
        let plaintext = b"Another message";
        let key_bytes = [0u8; 32];
        let nonce_bytes = [0u8; 12];

        let encrypted = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();

        // Use an incorrect key for decryption
        let incorrect_key_bytes = [1u8; 32];

        let result = decrypt(&encrypted, &incorrect_key_bytes, &nonce_bytes);
        assert!(result.is_err());
    }
}
