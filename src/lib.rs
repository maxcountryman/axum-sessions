//! # **Migration to `tower-sessions`**
//!
//! **Development of this crate has moved to
//! [`tower-sessions`](https://github.com/maxcountryman/tower-sessions).** Please consider
//! migrating.
//!
//! Numerous bugs and a significant design flaw with `axum-sessions` are
//! addressed with `tower-sessions`.

#![deny(missing_docs)]

pub mod extractors;
mod session;

pub use async_session;
pub use axum_extra::extract::cookie::SameSite;

pub use self::session::{PersistencePolicy, Session, SessionHandle, SessionLayer};
