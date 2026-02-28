use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use influx_backend::*;
use rand::rngs::OsRng;
use rand::RngCore;

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

#[tokio::test]
async fn test_handler() {
    let response = handler().await;
    assert_eq!(response, "Hello, InFlux Backend!");
}

#[tokio::test]
async fn test_create_router() {
    let stream_name = "test_router_events";
    let js = setup_nats(stream_name, "nats://localhost:4222", "test.router.>").await;
    let pool = setup_postgres("postgres://influx:password@localhost:5432/influx_db").await;
    let _app = create_router(js, pool);
    // Just asserting that it creates the router without panicking
    assert!(true);
}


