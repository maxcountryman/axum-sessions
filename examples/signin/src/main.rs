//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-signin
//! ```

use axum::{routing::get, Router};
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
    let session_layer = SessionLayer::new(store, &secret);

    async fn signin_handler(mut session: WritableSession) {
        session
            .insert("signed_in", true)
            .expect("Could not sign in.");
    }

    async fn signout_handler(mut session: WritableSession) {
        session.destroy();
    }

    async fn protected_handler(session: ReadableSession) -> &'static str {
        if session
            .get::<bool>("signed_in")
            .map_or(false, |signed_in| signed_in)
        {
            "Shh, it's secret!"
        } else {
            "Nothing to see here."
        }
    }

    let app = Router::new()
        .route("/signin", get(signin_handler))
        .route("/signout", get(signout_handler))
        .route("/protected", get(protected_handler))
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
