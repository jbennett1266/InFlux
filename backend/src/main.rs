use axum::{routing::get, Router};
use std::net::SocketAddr;
use async_nats as nats;
use nats::jetstream::{self, stream::Config as StreamConfig};

#[tokio::main]
async fn main() {
    // Initialize NATS connection and JetStream context
    let nc = nats::connect("nats://localhost:4222").await.unwrap();
    let js = jetstream::new(nc);

    // Ensure a stream exists (e.g., "influx_events")
    let stream_name = "influx_events";
    match js.get_stream(stream_name).await {
        Ok(_) => println!("Stream {} already exists.", stream_name),
        Err(_) => {
            println!("Creating stream {}.
", stream_name);
            js.create_stream(StreamConfig {
                name: stream_name.to_string(),
                subjects: vec!["influx.events.>".to_string()],
                ..Default::default()
            }).await.unwrap();
        }
    };

    // Publish a test message on a specific route
    let js_clone = js.clone();
    let app = Router::new()
        .route("/", get(handler))
        .route("/publish", get(move || async move {
            js_clone.publish("influx.events.test", "Hello from Axum!".into()).await.unwrap();
            "Message published to NATS JetStream!".to_string()
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
