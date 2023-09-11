//! Extractors for sessions.

use std::ops::{Deref, DerefMut};

use axum::{async_trait, extract::FromRequestParts, http::request::Parts, Extension};
use tokio::sync::OwnedMutexGuard;

use crate::SessionHandle;

/// An extractor which provides a readable session. Sessions may have many
/// readers.
#[derive(Debug)]
pub struct Session {
    session_guard: OwnedMutexGuard<async_session::Session>,
}

impl Deref for Session {
    type Target = OwnedMutexGuard<async_session::Session>;

    fn deref(&self) -> &Self::Target {
        &self.session_guard
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_guard
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync + Clone,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        use axum::RequestPartsExt;
        let Extension(session) = parts
            .extract::<Extension<SessionHandle>>()
            .await
            .expect("Session extension missing. Is the session layer installed?");

        let session_guard = session.lock_owned().await;
        Ok(Self { session_guard })
    }
}
