> [!IMPORTANT]
> **Migrating to [`tower-sessions`](https://github.com/maxcountryman/tower-sessions)**
>
> We have moved development of this crate to `tower-sessions`.
>
> Please **consider migrating** to `tower-sessions` if you use this crate.

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
<a href='https://coveralls.io/github/maxcountryman/axum-sessions?branch=main'>
<img src='https://coveralls.io/repos/github/maxcountryman/axum-sessions/badge.svg?branch=main' alt='Coverage Status' />
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
axum-sessions = "0.5.0"
```

## 🤸 Usage

`axum` applications can use the middleware via the session layer.

### `axum` Example

```rust
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
```

You can find this [example][counter-example] as well as other example projects in the [example directory][examples].

## Session authentication via `axum-login`

For user session management and authentication and authorization specifically please see [`axum-login`](https://github.com/maxcountryman/axum-login).

See the [crate documentation][docs] for more usage information.

[counter-example]: https://github.com/maxcountryman/axum-sessions/tree/main/examples/counter
[examples]: https://github.com/maxcountryman/axum-sessions/tree/main/examples
[docs]: https://docs.rs/axum-sessions
