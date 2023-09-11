//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-regenerate
//! ```

use async_session_memory_store::MemoryStore;
use axum::{routing::get, Router};
use axum_sessions::{extractors::Session, SessionLayer};
use rand::Rng;

#[tokio::main]
async fn main() {
    let store = MemoryStore::new();
    let secret = rand::thread_rng().gen::<[u8; 128]>();
    let session_layer = SessionLayer::new(store, &secret);

    async fn regenerate_handler(mut session: Session) {
        // NB: This DOES NOT update the store, meaning that both sessions will still be
        // found.
        session.regenerate();
    }

    async fn insert_handler(mut session: Session) {
        session
            .insert("foo", 42)
            .expect("Could not store the answer.");
    }

    async fn handler(session: Session) -> String {
        session
            .get::<usize>("foo")
            .map(|answer| format!("{}", answer))
            .unwrap_or_else(|| "Nothing in session yet; try /insert.".to_string())
    }

    let app = Router::new()
        .route("/regenerate", get(regenerate_handler))
        .route("/insert", get(insert_handler))
        .route("/", get(handler))
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
