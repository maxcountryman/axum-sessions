// Much of this code is lifted directly from
// `tide::sessions::middleware::SessionMiddleware`. See: https://github.com/http-rs/tide/blob/20fe435a9544c10f64245e883847fc3cd1d50538/src/sessions/middleware.rs

use std::{
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
        Request,
    },
    response::Response,
};
use axum_extra::extract::cookie::{Cookie, Key, SameSite};
use futures::future::BoxFuture;
use tower::{Layer, Service};

const BASE64_DIGEST_LEN: usize = 44;

#[derive(Clone)]
pub struct SessionLayer<Store> {
    store: Store,
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    session_ttl: Option<Duration>,
    save_unchanged: bool,
    same_site_policy: SameSite,
    secure: bool,
    key: Key,
}

impl<Store: SessionStore> SessionLayer<Store> {
    /// Creates a layer which will attach an [`async_session::Session`] to
    /// requests via an extension. This session is derived from a
    /// cryptographically signed cookie. When the client sends a valid,
    /// known cookie then the session is hydrated from this. Otherwise a new
    /// cookie is created and returned in the response.
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
    /// # use axum_sessions::{SessionLayer, async_session::MemoryStore, SameSite};
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
    /// .with_save_unchanged(false)
    /// .with_secure(true);
    /// ```
    pub fn new(store: Store, secret: &[u8]) -> Self {
        if secret.len() < 64 {
            panic!("`secret` must be at least 64 bytes.")
        }

        Self {
            store,
            save_unchanged: true,
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
    pub fn with_save_unchanged(mut self, save_unchanged: bool) -> Self {
        self.save_unchanged = save_unchanged;
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

    async fn load_or_create(&self, cookie_value: Option<String>) -> async_session::Session {
        let session = match cookie_value {
            Some(cookie_value) => self.store.load_session(cookie_value).await.ok().flatten(),
            None => None,
        };

        session
            .and_then(|session| session.validate())
            .unwrap_or_default()
    }

    fn build_cookie(&self, secure: bool, cookie_value: String) -> Cookie<'static> {
        let mut cookie = Cookie::build(self.cookie_name.clone(), cookie_value)
            .http_only(true)
            .same_site(self.same_site_policy)
            .secure(secure)
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

    // the following is reused verbatim from
    // https://github.com/SergioBenitez/cookie-rs/blob/master/src/secure/signed.rs#L33-L43
    /// Signs the cookie's value providing integrity and authenticity.
    fn sign_cookie(&self, cookie: &mut Cookie<'_>) {
        // Compute HMAC-SHA256 of the cookie's value.
        let mut mac = Hmac::<Sha256>::new_from_slice(self.key.signing()).expect("good key");
        mac.update(cookie.value().as_bytes());

        // Cookie's new value is [MAC | original-value].
        let mut new_value = base64::encode(&mac.finalize().into_bytes());
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

impl<S, Store: SessionStore> Layer<S> for SessionLayer<Store> {
    type Service = Session<S, Store>;

    fn layer(&self, inner: S) -> Self::Service {
        Session {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Session<S, Store: SessionStore> {
    inner: S,
    layer: SessionLayer<Store>,
}

impl<S, ReqBody, ResBody, Store: SessionStore> Service<Request<ReqBody>> for Session<S, Store>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ResBody: Send + 'static,
    ReqBody: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let session_layer = self.layer.clone();

        let cookie_values = request
            .headers()
            .get(COOKIE)
            .map(|cookies| cookies.to_str());

        let cookie_value = if let Some(Ok(cookies)) = cookie_values {
            cookies
                .split(';')
                .map(|cookie| cookie.trim())
                .filter_map(|cookie| Cookie::parse_encoded(cookie).ok())
                .filter(|cookie| cookie.name() == session_layer.cookie_name)
                .find_map(|cookie| self.layer.verify_signature(cookie.value()).ok())
        } else {
            None
        };

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut session = session_layer.load_or_create(cookie_value).await;

            if let Some(ttl) = session_layer.session_ttl {
                session.expire_in(ttl);
            }

            request.extensions_mut().insert(session.clone());
            let mut response = inner.call(request).await?;

            if session.is_destroyed() {
                session_layer
                    .store
                    .destroy_session(session)
                    .await
                    .expect("Could not destroy session.");
            } else if session_layer.save_unchanged || session.data_changed() {
                let cookie = session_layer
                    .store
                    .store_session(session)
                    .await
                    .expect("Could not store session.")
                    .map(|cookie_value| {
                        session_layer.build_cookie(session_layer.secure, cookie_value)
                    });

                if let Some(cookie) = cookie {
                    response.headers_mut().insert(
                        SET_COOKIE,
                        HeaderValue::from_str(&cookie.to_string()).unwrap(),
                    );
                }
            }

            Ok(response)
        })
    }
}
