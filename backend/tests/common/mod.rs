use tokio::sync::OnceCell;
use scylla::{Session, SessionBuilder};
use tokio::time::{sleep, Duration};
use influx_backend::*;
use axum_test::TestServer;
use std::sync::Arc;
use async_nats::jetstream::Context as NatsContext;

pub struct SharedResources {
    pub nats: NatsContext,
    pub session: Arc<Session>,
}

static RESOURCES: OnceCell<SharedResources> = OnceCell::const_new();

pub async fn get_resources() -> &'static SharedResources {
    RESOURCES.get_or_init(|| async {
        let nats_url = "nats://localhost:4222";
        let cassandra_url = "localhost:9042";

        wait_for_cassandra(cassandra_url).await;

        let stream_name = "shared_test_stream_auth";
        let nats = setup_nats(stream_name, nats_url, "shared.auth.test.>").await;
        let session = setup_cassandra(cassandra_url).await;

        // Ensure fresh schema for auth tests
        session.query("DROP TABLE IF EXISTS influx_ks.users", &[]).await.ok();
        session.query("CREATE TABLE IF NOT EXISTS influx_ks.users (username TEXT PRIMARY KEY, password_hash TEXT, public_key TEXT)", &[]).await.ok();

        SharedResources {
            nats,
            session,
        }
    }).await
}

pub async fn create_test_server() -> TestServer {
    let res = get_resources().await;
    let app = create_router(res.nats.clone(), res.session.clone());
    TestServer::new(app).expect("Failed to create test server")
}

async fn wait_for_cassandra(url: &str) {
    let mut retry = 0;
    while retry < 30 {
        if SessionBuilder::new().known_nodes(&[url]).build().await.is_ok() {
            return;
        }
        sleep(Duration::from_secs(2)).await;
        retry += 1;
    }
    panic!("Cassandra never became reachable at {}", url);
}

pub async fn cleanup_database(session: &Session) {
    session.query("TRUNCATE influx_ks.users", &[]).await.ok();
    session.query("TRUNCATE influx_ks.messages", &[]).await.ok();
    sleep(Duration::from_millis(200)).await;
}
