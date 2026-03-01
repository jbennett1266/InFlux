use influx_backend::*;
use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use base64::{Engine as _, engine::general_purpose};

#[test]
fn test_asymmetric_handshake_and_encryption() {
    let alice_secret = StaticSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = StaticSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared = derive_shared_secret(&alice_secret, &bob_public);
    let bob_shared = derive_shared_secret(&bob_secret, &alice_public);

    assert_eq!(alice_shared, bob_shared);

    let message = b"Secret message from Alice to Bob";
    let (ciphertext, nonce) = symmetric_encrypt(message, &alice_shared);

    let decrypted = symmetric_decrypt(&ciphertext, &bob_shared, &nonce).unwrap();
    assert_eq!(message.to_vec(), decrypted);
}

#[tokio::test]
async fn test_jwt_generation() {
    let token = create_jwt("test_user", 60);
    assert!(!token.is_empty());
}

#[tokio::test]
async fn test_handler() {
    let response = handler().await;
    assert_eq!(response, "Hello, InFlux Backend!");
}
