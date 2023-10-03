//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-async-sqlx-session
//! ```

use async_sqlx_session::SqliteSessionStore;
use axum::{routing::get, Router};
use axum_sessions::{extractors::Session, SessionLayer};
use rand::Rng;

#[tokio::main]
async fn main() {
    let store = SqliteSessionStore::new("sqlite::memory:")
        .await
        .expect("Could not connect to SQLite.");
    store
        .migrate()
        .await
        .expect("Could not migrate session store.");
    let secret = rand::thread_rng().gen::<[u8; 128]>();
    let session_layer = SessionLayer::new(store, &secret);

    async fn increment_count_handler(mut session: Session) {
        let previous: usize = session.get("counter").unwrap_or_default();
        session
            .insert("counter", previous + 1)
            .expect("Could not store counter.");
    }

    async fn handler(session: Session) -> String {
        format!(
            "Counter: {}",
            session.get::<usize>("counter").unwrap_or_default()
        )
    }

    let app = Router::new()
        .route("/increment", get(increment_count_handler))
        .route("/", get(handler))
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
