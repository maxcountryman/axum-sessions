//! axum-sessions is a middleware providing cookie-based sessions for axum
//! applications.
//!
//! [`SessionLayer`] provides client sessions via [`async_session`]. Sessions
//! are backed by cryptographically signed cookies. These cookies are generated
//! when they're not found or otherwise invalid. When a valid, known
//! cookie is received in a request, the session is hydrated from this cookie.
//! The middleware leverages [`http::Extensions`](axum::http::Extensions) to
//! attach an [`async_session::Session`] to the request. Request handlers can
//! then interact with the session.
//!
//! # Example
//!
//! Using the middleware with axum is straightforward:
//!
//! ```rust,no_run
//! use axum::{routing::get, Extension, Router};
//! use axum_sessions::{
//!     async_session::{MemoryStore, Session},
//!     SessionLayer,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = async_session::MemoryStore::new();
//!     let secret = b"..."; // MUST be at least 64 bytes!
//!     let session_layer = SessionLayer::new(store, secret);
//!
//!     async fn handler(Extension(session): Extension<Session>) {
//!         // Use the session in your handler...
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
//! This middleware may also be used as a generic Tower middleware:
//!
//! ```rust
//! use std::convert::Infallible;
//!
//! use axum::http::header::SET_COOKIE;
//! use axum_sessions::SessionLayer;
//! use http::{Request, Response};
//! use hyper::Body;
//! use tower::{Service, ServiceBuilder, ServiceExt};
//!
//! async fn handle(request: Request<Body>) -> Result<Response<Body>, Infallible> {
//!     assert!(request
//!         .extensions()
//!         .get::<async_session::Session>()
//!         .is_some());
//!     Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let store = async_session::MemoryStore::new();
//! let secret: Vec<u8> = ["_"]
//!     .iter()
//!     .cycle()
//!     .take(64)
//!     .flat_map(|s| s.as_bytes().to_owned())
//!     .collect();
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
mod session;

pub use async_session;
pub use axum_extra::extract::cookie::SameSite;

pub use self::session::{Session, SessionLayer};
