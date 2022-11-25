//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-counter
//! ```

use axum::{response::IntoResponse, routing::get, Router};
use axum_sessions::{
    async_session::MemoryStore,
    extractors::{ReadableSession, WritableSession},
    SessionLayer,
};
use rand::Rng;

#[tokio::main]
async fn main() {
    let store = MemoryStore::new();
    let secret = rand::thread_rng().gen::<[u8; 128]>();
    let session_layer = SessionLayer::new(store, &secret).with_secure(false);

    async fn display_handler(session: ReadableSession) -> impl IntoResponse {
        let mut count = 0;
        count = session.get("count").unwrap_or(count);
        format!(
            "Count is: {}; visit /inc to increment and /reset to reset",
            count
        )
    }

    async fn increment_handler(mut session: WritableSession) -> impl IntoResponse {
        let mut count = 1;
        count = session.get("count").map(|n: i32| n + 1).unwrap_or(count);
        session.insert("count", count).unwrap();
        format!("Count is: {}", count)
    }

    async fn reset_handler(mut session: WritableSession) -> impl IntoResponse {
        session.destroy();
        "Count reset"
    }

    let app = Router::new()
        .route("/", get(display_handler))
        .route("/inc", get(increment_handler))
        .route("/reset", get(reset_handler))
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
