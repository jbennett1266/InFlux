# InFlux

InFlux is an end-to-end encrypted messaging application designed for semi-security conscious individuals who desire anonymity when communicating. It focuses on providing a secure platform for high-frequency, small messages, ensuring all traffic is encrypted in transit and never stored in plaintext except on the end device.

## Core Features

*   **E2E Encrypted Messaging:** Supports high-frequency, small messages with end-to-end encryption.
*   **Secure Communication:** All traffic is encrypted in transit and never stored in plaintext.
*   **Account-Based Service:** Users can sign up for accounts, making it a service accessible globally, not limited by proximity.

## Technical Stack

The following technical stack has been chosen for InFlux:

*   **Backend Framework:** Rust with Axum (web framework) and Tokio (asynchronous runtime)
*   **Real-time Messaging:** NATS JetStream for high-throughput, low-latency message streaming with persistence.
*   **Database:** ScyllaDB for high-performance, horizontally scalable NoSQL database for metadata.
*   **Encryption:** Olm/Megolm protocols for robust end-to-end encryption in one-to-one and group conversations.
*   **Frontend:** To be determined (Next.js/Tauri was suggested, but not yet finalized).

## Getting Started

Further instructions will be provided for setting up the development environment and scaffolding the initial project structure.

## Next Steps

1.  **Backend Scaffolding:** Set up the initial Rust backend project with Axum and Tokio.
2.  **NATS Integration:** Configure NATS JetStream for message handling.
3.  **ScyllaDB Setup:** Implement database connection and schema for ScyllaDB.
4.  **Olm/Megolm Implementation:** Integrate Olm/Megolm for end-to-end encryption.
5.  **Frontend Development:** Begin developing the frontend application with the chosen framework (e.g., Next.js/Tauri).
