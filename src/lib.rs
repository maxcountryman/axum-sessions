//! axum-sessions is a middleware providing cookie-based sessions for axum
//! applications.
//!
//! [`SessionLayer`] provides client sessions via [`async_session`]. Sessions
//! are backed by cryptographically signed cookies. These cookies are generated
//! when they're not found or are otherwise invalid. When a valid, known cookie
//! is received in a request, the session is hydrated from this cookie. The
//! middleware provides sessions via [`SessionHandle`]. Handlers use the
//! [`ReadableSession`](crate::extractors::ReadableSession) and
//! [`WritableSession`](crate::extractors::WritableSession) extractors to read
//! from and write to sessions respectively.
//!
//! # Example
//!
//! Using the middleware with axum is straightforward:
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum_sessions::{
//!     async_session::MemoryStore, extractors::WritableSession, PersistencePolicy, SessionLayer,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = async_session::MemoryStore::new();
//!     let secret = b"..."; // MUST be at least 64 bytes!
//!     let session_layer = SessionLayer::new(store, secret);
//!
//!     async fn handler(mut session: WritableSession) {
//!         session
//!             .insert("foo", 42)
//!             .expect("Could not store the answer.");
//!     }
//!
//!     let app = Router::new().route("/", get(handler)).layer(session_layer);
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! This middleware may also be used as a generic Tower middleware by making use
//! of the [`SessionHandle`] extension:
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use axum::http::header::SET_COOKIE;
//! use axum_sessions::{SessionHandle, SessionLayer};
//! use http::{Request, Response};
//! use hyper::Body;
//! use rand::Rng;
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! async fn handle(request: Request<Body>) -> Result<Response<Body>, Infallible> {
//!     let session_handle = request.extensions().get::<SessionHandle>().unwrap();
//!     let session = session_handle.read().await;
//!     // Use the session as you'd like.
//!
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = async_session::MemoryStore::new();
//! let secret = rand::thread_rng().gen::<[u8; 128]>();
//! let session_layer = SessionLayer::new(store, &secret);
//!
//! let mut service = ServiceBuilder::new()
//!     .layer(session_layer)
//!     .service_fn(handle);
//!
//! let request = Request::builder().body(Body::empty()).unwrap();
//!
//! let response = service.ready().await?.call(request).await?;
//!
//! assert_eq!(
//!     response
//!         .headers()
//!         .get(SET_COOKIE)
//!         .unwrap()
//!         .to_str()
//!         .unwrap()
//!         .split("=")
//!         .collect::<Vec<_>>()[0],
//!     "axum.sid"
//! );
//!
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

pub mod extractors;
mod session;

pub use async_session;
pub use axum_extra::extract::cookie::SameSite;

pub use self::session::{PersistencePolicy, Session, SessionHandle, SessionLayer};
