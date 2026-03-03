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
        let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
        let cassandra_url = std::env::var("CASSANDRA_URL").unwrap_or_else(|_| "localhost:9042".to_string());

        wait_for_cassandra(&cassandra_url).await;

        let stream_name = "shared_test_stream_auth";
        let nats = setup_nats(stream_name, &nats_url, "shared.auth.test.>").await;
        let session = setup_cassandra(&cassandra_url).await;

        // Ensure fresh schema for auth tests
        session.query("DROP TABLE IF EXISTS influx_ks.users", &[]).await.ok();
        session.query("DROP TABLE IF EXISTS influx_ks.threads", &[]).await.ok();
        session.query("DROP TABLE IF EXISTS influx_ks.user_threads", &[]).await.ok();
        session.query("CREATE TABLE IF NOT EXISTS influx_ks.users (username TEXT PRIMARY KEY, password_hash TEXT, public_key TEXT)", &[]).await.ok();
        session.query("CREATE TABLE IF NOT EXISTS influx_ks.threads (id TEXT PRIMARY KEY, name TEXT, is_group BOOLEAN, owner TEXT)", &[]).await.ok();
        session.query("CREATE TABLE IF NOT EXISTS influx_ks.user_threads (username TEXT, thread_id TEXT, thread_name TEXT, is_group BOOLEAN, PRIMARY KEY (username, thread_id))", &[]).await.ok();

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
    session.query("TRUNCATE influx_ks.threads", &[]).await.ok();
    session.query("TRUNCATE influx_ks.user_threads", &[]).await.ok();
    sleep(Duration::from_millis(200)).await;
}
