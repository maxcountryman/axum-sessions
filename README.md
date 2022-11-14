<h1 align="center">
axum-sessions
</h1>

<p align="center">
🥠 Cookie-based sessions for Axum via async-session.
</p>

<div align="center">
<a href="https://crates.io/crates/axum-sessions">
<img src="https://img.shields.io/crates/v/axum-sessions.svg" />
</a>
<a href="https://docs.rs/axum-sessions">
<img src="https://docs.rs/axum-sessions/badge.svg" />
</a>
<a href="https://github.com/maxcountryman/axum-sessions/actions/workflows/rust.yml">
<img src="https://github.com/maxcountryman/axum-sessions/actions/workflows/rust.yml/badge.svg" />
</a>
</div>

## 🎨 Overview

`axum-sessions` is a middleware providing cookie-based sessions for `axum` applications.

- Cryptographically-signed cookies, ensuring integrity and authenticity
- Wraps `async-session`, enabling flexible cookie storage (e.g. `async-sqlx-session`)
- Convenient extractor-based API (i.e. `ReadableSession` and `WritableSession`)
- Can be used as a generic Tower middleware

## 📦 Install

To use the crate in your project, add the following to your `Cargo.toml` file:

```toml
[dependencies]
axum-sessions = "0.3.1"
```

## 🤸 Usage

`axum` applications can use the middleware via the session layer.

### `axum` Example

```rust
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
```

You can find this [example][signin-example] as well as other example projects in the [example directory][examples].

See the [crate documentation][docs] for more usage information.

[signin-example]: https://github.com/maxcountryman/axum-sessions/tree/main/examples/signin
[examples]: https://github.com/maxcountryman/axum-sessions/tree/main/examples
[docs]: https://docs.rs/axum-sessions
