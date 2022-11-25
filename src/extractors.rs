//! Extractors for sessions.

use std::ops::{Deref, DerefMut};

use axum::{async_trait, extract::FromRequestParts, http::request::Parts, Extension};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard};

use crate::SessionHandle;

/// An extractor which provides a readable session. Sessions may have many
/// readers.
#[derive(Debug)]
pub struct ReadableSession {
    session: OwnedRwLockReadGuard<async_session::Session>,
}

impl Deref for ReadableSession {
    type Target = OwnedRwLockReadGuard<async_session::Session>;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ReadableSession
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.read_owned().await;

        Ok(Self { session })
    }
}

/// An extractor which provides a writable session. Sessions may have only one
/// writer.
#[derive(Debug)]
pub struct WritableSession {
    session: OwnedRwLockWriteGuard<async_session::Session>,
}

impl Deref for WritableSession {
    type Target = OwnedRwLockWriteGuard<async_session::Session>;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl DerefMut for WritableSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for WritableSession
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.write_owned().await;

        Ok(Self { session })
    }
}
