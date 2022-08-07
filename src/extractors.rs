use std::ops::{Deref, DerefMut};

use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http, Extension,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard};

use crate::SessionHandle;

/// An extractor which provides a readable session. Sessions may have many
/// readers.
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
impl<B> FromRequest<B> for ReadableSession
where
    B: Send,
{
    type Rejection = http::StatusCode;

    async fn from_request(request: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle> = Extension::from_request(request)
            .await
            .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.read_owned().await;

        Ok(Self { session })
    }
}

/// An extractor which provides a writable session. Sessions may have only one
/// writer.
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
impl<B> FromRequest<B> for WritableSession
where
    B: Send,
{
    type Rejection = http::StatusCode;

    async fn from_request(request: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(session_handle): Extension<SessionHandle> = Extension::from_request(request)
            .await
            .expect("Session extension missing. Is the session layer installed?");
        let session = session_handle.write_owned().await;

        Ok(Self { session })
    }
}
