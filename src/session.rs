// Much of this code is lifted directly from
// `tide::sessions::middleware::SessionMiddleware`. See: https://github.com/http-rs/tide/blob/20fe435a9544c10f64245e883847fc3cd1d50538/src/sessions/middleware.rs

use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_session::{
    base64,
    hmac::{Hmac, Mac, NewMac},
    sha2::Sha256,
    SessionStore,
};
use axum::{
    http::{
        header::{HeaderValue, COOKIE, SET_COOKIE},
        Request, StatusCode,
    },
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, Key, SameSite};
use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tower::{Layer, Service};

const BASE64_DIGEST_LEN: usize = 44;

/// A type alias which provides a handle to the underlying session.
///
/// This is provided via [`http::Extensions`](axum::http::Extensions). Most
/// applications will use the
/// [`ReadableSession`](crate::extractors::ReadableSession) and
/// [`WritableSession`](crate::extractors::WritableSession) extractors rather
/// than using the handle directly. A notable exception is when using this
/// library as a generic Tower middleware: such use cases will consume the
/// handle directly.
pub type SessionHandle = Arc<RwLock<async_session::Session>>;

/// Controls how the session data is persisted and created.
#[derive(Clone)]
pub enum PersistencePolicy {
    /// Always ping the storage layer and store empty "guest" sessions.
    Always,
    /// Do not store empty "guest" sessions, only ping the storage layer if
    /// the session data changed.
    ChangedOnly,
    /// Do not store empty "guest" sessions, always ping the storage layer for existing sessions.
    ExistingOnly,
}

/// Layer that provides cookie-based sessions.
#[derive(Clone)]
pub struct SessionLayer<Store> {
    store: Store,
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    persistence_policy: PersistencePolicy,
    session_ttl: Option<Duration>,
    same_site_policy: SameSite,
    secure: bool,
    key: Key,
}

impl<Store: SessionStore> SessionLayer<Store> {
    /// Creates a layer which will attach a [`SessionHandle`] to requests via an
    /// extension. This session is derived from a cryptographically signed
    /// cookie. When the client sends a valid, known cookie then the session is
    /// hydrated from this. Otherwise a new cookie is created and returned in
    /// the response.
    ///
    /// The default behaviour is to enable "guest" sessions with [`SessionPolicy::Always`].
    ///
    /// # Panics
    ///
    /// `SessionLayer::new` will panic if the secret is less than 64 bytes.
    ///
    /// # Customization
    ///
    /// The configuration of the session may be adjusted according to the needs
    /// of your application:
    ///
    /// ```rust
    /// # use axum_sessions::{PersistencePolicy, SessionLayer, async_session::MemoryStore, SameSite};
    /// # use std::time::Duration;
    /// SessionLayer::new(
    ///     MemoryStore::new(),
    ///     b"please do not hardcode your secret; instead use a
    ///     cryptographically secure value",
    /// )
    /// .with_cookie_name("your.cookie.name")
    /// .with_cookie_path("/some/path")
    /// .with_cookie_domain("www.example.com")
    /// .with_same_site_policy(SameSite::Lax)
    /// .with_session_ttl(Some(Duration::from_secs(60 * 5)))
    /// .with_persistence_policy(PersistencePolicy::Always)
    /// .with_secure(true);
    /// ```
    pub fn new(store: Store, secret: &[u8]) -> Self {
        if secret.len() < 64 {
            panic!("`secret` must be at least 64 bytes.")
        }

        Self {
            store,
            persistence_policy: PersistencePolicy::Always,
            cookie_path: "/".into(),
            cookie_name: "axum.sid".into(),
            cookie_domain: None,
            same_site_policy: SameSite::Strict,
            session_ttl: Some(Duration::from_secs(24 * 60 * 60)),
            secure: true,
            key: Key::from(secret),
        }
    }

    /// When `true`, a session cookie will always be set. When `false` the
    /// session data must be modified in order for it to be set. Defaults to
    /// `true`.
    pub fn with_persistence_policy(mut self, policy: PersistencePolicy) -> Self {
        self.persistence_policy = policy;
        self
    }

    /// Sets a cookie for the session. Defaults to `"/"`.
    pub fn with_cookie_path(mut self, cookie_path: impl AsRef<str>) -> Self {
        self.cookie_path = cookie_path.as_ref().to_owned();
        self
    }

    /// Sets a cookie name for the session. Defaults to `"axum.sid"`.
    pub fn with_cookie_name(mut self, cookie_name: impl AsRef<str>) -> Self {
        self.cookie_name = cookie_name.as_ref().to_owned();
        self
    }

    /// Sets a cookie domain for the session. Defaults to `None`.
    pub fn with_cookie_domain(mut self, cookie_domain: impl AsRef<str>) -> Self {
        self.cookie_domain = Some(cookie_domain.as_ref().to_owned());
        self
    }

    /// Decide if session is presented to the storage layer
    fn should_store(&self, cookie_value: &Option<String>, session_data_changed: bool) -> bool {
        session_data_changed
            || matches!(self.persistence_policy, PersistencePolicy::Always)
            || (matches!(self.persistence_policy, PersistencePolicy::ExistingOnly)
                && cookie_value.is_some())
    }

    /// Sets a cookie same site policy for the session. Defaults to
    /// `SameSite::Strict`.
    pub fn with_same_site_policy(mut self, policy: SameSite) -> Self {
        self.same_site_policy = policy;
        self
    }

    /// Sets a cookie time-to-live (ttl) for the session. Defaults to
    /// `Duration::from_secs(60 * 60 24)`; one day.
    pub fn with_session_ttl(mut self, session_ttl: Option<Duration>) -> Self {
        self.session_ttl = session_ttl;
        self
    }

    /// Sets a cookie secure attribute for the session. Defaults to `true`.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    async fn load_or_create(&self, cookie_value: Option<String>) -> SessionHandle {
        let session = match cookie_value {
            Some(cookie_value) => self.store.load_session(cookie_value).await.ok().flatten(),
            None => None,
        };

        Arc::new(RwLock::new(
            session
                .and_then(async_session::Session::validate)
                .unwrap_or_default(),
        ))
    }

    fn build_cookie(&self, cookie_value: String) -> Cookie<'static> {
        let mut cookie = Cookie::build(self.cookie_name.clone(), cookie_value)
            .http_only(true)
            .same_site(self.same_site_policy)
            .secure(self.secure)
            .path(self.cookie_path.clone())
            .finish();

        if let Some(ttl) = self.session_ttl {
            cookie.set_expires(Some((std::time::SystemTime::now() + ttl).into()));
        }

        if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.set_domain(cookie_domain)
        }

        self.sign_cookie(&mut cookie);

        cookie
    }

    fn build_removal_cookie(&self) -> Cookie<'static> {
        let cookie = Cookie::build(self.cookie_name.clone(), "")
            .http_only(true)
            .path(self.cookie_path.clone());

        let mut cookie = if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.domain(cookie_domain)
        } else {
            cookie
        }
        .finish();

        cookie.make_removal();

        self.sign_cookie(&mut cookie);

        cookie
    }

    // the following is reused verbatim from
    // https://github.com/SergioBenitez/cookie-rs/blob/master/src/secure/signed.rs#L33-L43
    /// Signs the cookie's value providing integrity and authenticity.
    fn sign_cookie(&self, cookie: &mut Cookie<'_>) {
        // Compute HMAC-SHA256 of the cookie's value.
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.signing()).expect("good key");
        mac.update(cookie.value().as_bytes());

        // Cookie's new value is [MAC | original-value].
        let mut new_value = base64::encode(mac.finalize().into_bytes());
        new_value.push_str(cookie.value());
        cookie.set_value(new_value);
    }

    // the following is reused verbatim from
    // https://github.com/SergioBenitez/cookie-rs/blob/master/src/secure/signed.rs#L45-L63
    /// Given a signed value `str` where the signature is prepended to `value`,
    /// verifies the signed value and returns it. If there's a problem, returns
    /// an `Err` with a string describing the issue.
    fn verify_signature(&self, cookie_value: &str) -> Result<String, &'static str> {
        if cookie_value.len() < BASE64_DIGEST_LEN {
            return Err("length of value is <= BASE64_DIGEST_LEN");
        }

        // Split [MAC | original-value] into its two parts.
        let (digest_str, value) = cookie_value.split_at(BASE64_DIGEST_LEN);
        let digest = base64::decode(digest_str).map_err(|_| "bad base64 digest")?;

        // Perform the verification.
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.signing()).expect("good key");
        mac.update(value.as_bytes());
        mac.verify(&digest)
            .map(|_| value.to_string())
            .map_err(|_| "value did not verify")
    }
}

impl<Inner, Store: SessionStore> Layer<Inner> for SessionLayer<Store> {
    type Service = Session<Inner, Store>;

    fn layer(&self, inner: Inner) -> Self::Service {
        Session {
            inner,
            layer: self.clone(),
        }
    }
}

/// Session service container.
#[derive(Clone)]
pub struct Session<Inner, Store: SessionStore> {
    inner: Inner,
    layer: SessionLayer<Store>,
}

impl<Inner, ReqBody, ResBody, Store: SessionStore> Service<Request<ReqBody>>
    for Session<Inner, Store>
where
    Inner: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ResBody: Send + 'static,
    ReqBody: Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let session_layer = self.layer.clone();

        // Multiple cookies may be all concatenated into a single Cookie header
        // separated with semicolons (HTTP/1.1 behaviour) or into multiple separate
        // Cookie headers (HTTP/2 behaviour). Search for the session cookie from
        // all Cookie headers, assuming both forms are possible
        let cookie_value = request
            .headers()
            .get_all(COOKIE)
            .iter()
            .filter_map(|cookie_header| cookie_header.to_str().ok())
            .flat_map(|cookie_header| cookie_header.split(';'))
            .filter_map(|cookie_header| Cookie::parse_encoded(cookie_header.trim()).ok())
            .filter(|cookie| cookie.name() == session_layer.cookie_name)
            .find_map(|cookie| self.layer.verify_signature(cookie.value()).ok());

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let session_handle = session_layer.load_or_create(cookie_value.clone()).await;

            let mut session = session_handle.write().await;
            if let Some(ttl) = session_layer.session_ttl {
                (*session).expire_in(ttl);
            }
            drop(session);

            request.extensions_mut().insert(session_handle.clone());
            let mut response = inner.call(request).await?;

            let session = session_handle.read().await;
            let (session_is_destroyed, session_data_changed) =
                (session.is_destroyed(), session.data_changed());
            drop(session);

            // Pull out the session so we can pass it to the store without `Clone` blowing
            // away the `cookie_value`.
            let session = RwLock::into_inner(
                Arc::try_unwrap(session_handle).expect("Session handle still has owners."),
            );
            if session_is_destroyed {
                if let Err(e) = session_layer.store.destroy_session(session).await {
                    tracing::error!("Failed to destroy session: {:?}", e);
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                }

                let removal_cookie = session_layer.build_removal_cookie();

                response.headers_mut().insert(
                    SET_COOKIE,
                    HeaderValue::from_str(&removal_cookie.to_string()).unwrap(),
                );

            // Store if
            //  - We have guest sessions
            //  - We received a valid cookie and we use the `ExistingOnly` policy.
            //  - If we use the `ChangedOnly` policy, only `session.data_changed()` should trigger this branch.
            } else if session_layer.should_store(&cookie_value, session_data_changed) {
                match session_layer.store.store_session(session).await {
                    Ok(Some(cookie_value)) => {
                        let cookie = session_layer.build_cookie(cookie_value);
                        response.headers_mut().insert(
                            SET_COOKIE,
                            HeaderValue::from_str(&cookie.to_string()).unwrap(),
                        );
                    }

                    Ok(None) => {}

                    Err(e) => {
                        tracing::error!("Failed to reach session storage: {:?}", e);
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    }
                }
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use async_session::{
        serde::{Deserialize, Serialize},
        serde_json,
    };
    use axum::http::{Request, Response};
    use http::{
        header::{COOKIE, SET_COOKIE},
        HeaderValue, StatusCode,
    };
    use hyper::Body;
    use rand::Rng;
    use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

    use crate::{async_session::MemoryStore, SessionHandle, SessionLayer};

    use super::PersistencePolicy;

    #[derive(Deserialize, Serialize, PartialEq, Debug)]
    struct Counter {
        counter: i32,
    }

    enum ExpectedResult {
        Some,
        None,
    }

    #[tokio::test]
    async fn sets_session_cookie() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);
        let mut service = ServiceBuilder::new().layer(session_layer).service_fn(echo);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        assert!(res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("axum.sid="))
    }

    #[tokio::test]
    async fn uses_valid_session() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn multiple_cookies_in_single_header() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        // build a Cookie header that contains two cookies: an unrelated dummy cookie,
        // and the given session cookie
        let request_cookie =
            HeaderValue::from_str(&format!("key=value; {}", session_cookie.to_str().unwrap()))
                .unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.headers_mut().insert(COOKIE, request_cookie);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn multiple_cookie_headers() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(increment);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();
        let dummy_cookie = HeaderValue::from_str("key=value").unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 0 });

        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.headers_mut().append(COOKIE, dummy_cookie);
        request.headers_mut().append(COOKIE, session_cookie);
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let json_bs = &hyper::body::to_bytes(res.into_body()).await.unwrap()[..];
        let counter: Counter = serde_json::from_slice(json_bs).unwrap();
        assert_eq!(counter, Counter { counter: 1 });
    }

    #[tokio::test]
    async fn no_cookie_stored_when_no_session_is_required() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret)
            .with_persistence_policy(PersistencePolicy::ChangedOnly);
        let mut service = ServiceBuilder::new().layer(session_layer).service_fn(echo);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        assert!(res.headers().get(SET_COOKIE).is_none());
    }

    async fn invalid_session_check_cookie_result(
        persistence_policy: PersistencePolicy,
        change_data: bool,
        expect_cookie_header: (ExpectedResult, ExpectedResult),
    ) {
        let (expect_cookie_header_first, expect_cookie_header_second) = expect_cookie_header;
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer =
            SessionLayer::new(store, &secret).with_persistence_policy(persistence_policy);
        let mut service =
            ServiceBuilder::new()
                .layer(&session_layer)
                .service_fn(echo_read_session);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        match expect_cookie_header_first {
            ExpectedResult::Some => assert!(
                res.headers().get(SET_COOKIE).is_some(),
                "Set-Cookie must be present for first response"
            ),
            ExpectedResult::None => assert!(
                res.headers().get(SET_COOKIE).is_none(),
                "Set-Cookie must not be present for first response"
            ),
        }

        let mut service =
            ServiceBuilder::new()
                .layer(session_layer)
                .service_fn(move |req| async move {
                    if change_data {
                        echo_with_session_change(req).await
                    } else {
                        echo_read_session(req).await
                    }
                });
        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, "axum.sid=aW52YWxpZC1zZXNzaW9uLWlk".parse().unwrap());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        match expect_cookie_header_second {
            ExpectedResult::Some => assert!(
                res.headers().get(SET_COOKIE).is_some(),
                "Set-Cookie must be present for second response"
            ),
            ExpectedResult::None => assert!(
                res.headers().get(SET_COOKIE).is_none(),
                "Set-Cookie must not be present for second response"
            ),
        }
    }

    #[tokio::test]
    async fn invalid_session_always_sets_guest_cookie() {
        invalid_session_check_cookie_result(
            PersistencePolicy::Always,
            false,
            (ExpectedResult::Some, ExpectedResult::Some),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_session_sets_new_session_cookie_when_data_changes() {
        invalid_session_check_cookie_result(
            PersistencePolicy::ExistingOnly,
            true,
            (ExpectedResult::None, ExpectedResult::Some),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_session_sets_no_cookie_when_no_data_changes() {
        invalid_session_check_cookie_result(
            PersistencePolicy::ExistingOnly,
            false,
            (ExpectedResult::None, ExpectedResult::None),
        )
        .await;
    }

    #[tokio::test]
    async fn invalid_session_changedonly_sets_cookie_when_changed() {
        invalid_session_check_cookie_result(
            PersistencePolicy::ChangedOnly,
            true,
            (ExpectedResult::None, ExpectedResult::Some),
        )
        .await;
    }

    #[tokio::test]
    async fn destroyed_sessions_sets_removal_cookie() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();
        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);
        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .service_fn(destroy);

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let session_cookie = res
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mut request = Request::get("/destroy").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.parse().unwrap());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(
            res.headers()
                .get(SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .len(),
            121
        );
    }

    #[test]
    #[should_panic]
    fn too_short_secret() {
        let store = MemoryStore::new();
        SessionLayer::new(store, b"");
    }

    async fn echo(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }

    async fn echo_read_session(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle>().unwrap();
            let session = session_handle.write().await;
            let _ = session.get::<String>("signed_in").unwrap_or_default();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn echo_with_session_change(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        {
            let session_handle = req.extensions().get::<SessionHandle>().unwrap();
            let mut session = session_handle.write().await;
            session.insert("signed_in", true).unwrap();
        }
        Ok(Response::new(req.into_body()))
    }

    async fn destroy(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        // Destroy the session if we received a session cookie.
        if req.headers().get(COOKIE).is_some() {
            let session_handle = req.extensions().get::<SessionHandle>().unwrap();
            let mut session = session_handle.write().await;
            session.destroy();
        }

        Ok(Response::new(req.into_body()))
    }

    async fn increment(mut req: Request<Body>) -> Result<Response<Body>, BoxError> {
        let mut counter = 0;

        {
            let session_handle = req.extensions().get::<SessionHandle>().unwrap();
            let mut session = session_handle.write().await;
            counter = session
                .get("counter")
                .map(|count: i32| count + 1)
                .unwrap_or(counter);
            session.insert("counter", counter).unwrap();
        }

        let body = serde_json::to_string(&Counter { counter }).unwrap();
        *req.body_mut() = Body::from(body);

        Ok(Response::new(req.into_body()))
    }
}
