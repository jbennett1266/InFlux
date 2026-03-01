use influx_backend::*;
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::{Engine as _, engine::general_purpose};

#[test]
fn test_asymmetric_handshake_and_encryption() {
    // 1. Generate Alice's Keys
    let alice_secret = StaticSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);

    // 2. Generate Bob's Keys
    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    // 3. Perform DH Exchange
    let alice_shared = derive_shared_secret(&alice_secret, &bob_public);
    let bob_shared = derive_shared_secret(&bob_secret, &alice_public);

    // 4. Verify shared secrets match
    assert_eq!(alice_shared, bob_shared);

    // 5. Encrypt with shared secret
    let message = b"Secret message from Alice to Bob";
    let (ciphertext, nonce) = symmetric_encrypt(message, &alice_shared);

    // 6. Decrypt with shared secret
    let decrypted = symmetric_decrypt(&ciphertext, &bob_shared, &nonce).unwrap();
    assert_eq!(message.to_vec(), decrypted);
}

#[tokio::test]
async fn test_handler() {
    let response = handler().await;
    assert_eq!(response, "Hello, InFlux Backend!");
}

#[tokio::test]
async fn test_generate_keys_logic() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let encoded_pub = general_purpose::STANDARD.encode(public.as_bytes());
    assert!(!encoded_pub.is_empty());
}

#[tokio::test]
async fn test_create_router() {
    let stream_name = "unit_test_stream_e2ee";
    let js = setup_nats(stream_name, "nats://localhost:4222", "unit.e2ee.test.>").await;
    let scylla_session = setup_cassandra("localhost:9042").await;
    let _app = create_router(js, scylla_session);
    assert!(true);
}
