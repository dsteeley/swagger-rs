//! Authentication and authorization data structures

use crate::context::Push;
use futures::future::FutureExt;
use hyper::service::Service;
use hyper::{HeaderMap, Request};
use headers::authorization::{Basic, Bearer};
// pub use hyper_old_types::header::Authorization as Header;
// use hyper_old_types::header::Header as HeaderTrait;
// pub use hyper_old_types::header::{Basic, Bearer};
// use hyper_old_types::header::{Raw, Scheme};
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::string::ToString;

use headers::HeaderMapExt;


/// Authorization scopes.
#[derive(Clone, Debug, PartialEq)]
pub enum Scopes {
    /// Some set of scopes.
    Some(BTreeSet<String>),
    /// All possible scopes, authorization checking disabled.
    All,
}

/// Storage of authorization parameters for an incoming request, used for
/// REST API authorization.
#[derive(Clone, Debug, PartialEq)]
pub struct Authorization {
    /// Subject for which authorization is granted
    /// (i.e., what may be accessed.)
    pub subject: String,

    /// Scopes for which authorization is granted
    /// (i.e., what types of access are permitted).
    pub scopes: Scopes,

    /// Identity of the party to whom authorization was granted, if available
    /// (i.e., who is responsible for the access).
    ///
    /// In an OAuth environment, this is the identity of the client which
    /// issued an authorization request to the resource owner (end-user),
    /// and which has been directly authorized by the resource owner
    /// to access the protected resource. If the client delegates that
    /// authorization to another service (e.g., a proxy or other delegate),
    /// the `issuer` is still the original client which was authorized by
    /// the resource owner.
    pub issuer: Option<String>,
}

/// Storage of raw authentication data, used both for storing incoming
/// request authentication, and for authenticating outgoing client requests.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthData {
    /// Http Basic authentication data.
    Basic(Basic),
    /// Http Bearer authentication data.
    Bearer(Bearer),
    /// API key authentication data.
    ApiKey(String),
}

impl AuthData {
    /// Set basic auth
    pub fn basic(username: &str, password: &str) -> Self {
        AuthData::Basic(headers::authorization::Authorization::basic(username, password).0)
    }

    // TODO fixup unwrap
    /// Set bearer auth
    pub fn bearer(token: &str) -> Self {
        AuthData::Bearer(headers::authorization::Authorization::bearer(token).unwrap().0)
    }

    /// Set ApiKey authentication
    pub fn apikey(apikey: &str) -> Self {
        AuthData::ApiKey(apikey.to_owned())
    }
}

/// Bound for Request Context for MakeService wrappers
pub trait RcBound: Push<Option<Authorization>> + Send + 'static {}

impl<T> RcBound for T where T: Push<Option<Authorization>> + Send + 'static {}

/// Dummy Authenticator, that blindly inserts authorization data, allowing all
/// access to an endpoint with the specified subject.
#[derive(Debug)]
pub struct MakeAllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound,
    RC::Result: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    inner: Inner,
    subject: String,
    marker: PhantomData<fn(RC, ReqBody, RespBody)>,
}

impl<Inner, RC, ReqBody, RespBody> MakeAllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound,
    RC::Result: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    /// Create a middleware that authorizes with the configured subject.
    pub fn new<U: Into<String>>(inner: Inner, subject: U) -> Self {
        MakeAllowAllAuthenticator {
            inner,
            subject: subject.into(),
            marker: PhantomData,
        }
    }
}

impl<Inner, RC, Target, ReqBody, RespBody> Service<Target> for MakeAllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound,
    RC::Result: Send + 'static,
    Inner: Service<Target>,
    Inner::Future: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    type Error = Inner::Error;
    type Response = AllowAllAuthenticator<Inner::Response, RC, ReqBody, RespBody>;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, target: Target) -> Self::Future {
        let subject = self.subject.clone();
        Box::pin(
            self.inner
                .call(target)
                .map(|s| Ok(AllowAllAuthenticator::new(s?, subject))),
        )
    }
}

/// Dummy Authenticator, that blindly inserts authorization data, allowing all
/// access to an endpoint with the specified subject.
#[derive(Debug)]
pub struct AllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound,
    RC::Result: Send + 'static,
{
    inner: Inner,
    subject: String,
    marker: PhantomData<fn(RC, ReqBody, RespBody)>,
}

impl<Inner, RC, ReqBody, RespBody> AllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound,
    RC::Result: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    /// Create a middleware that authorizes with the configured subject.
    pub fn new<U: Into<String>>(inner: Inner, subject: U) -> Self {
        AllowAllAuthenticator {
            inner,
            subject: subject.into(),
            marker: PhantomData,
        }
    }
}

impl<Inner, RC, ReqBody, RespBody> Clone for AllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    Inner: Clone,
    RC: RcBound,
    RC::Result: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            subject: self.subject.clone(),
            marker: PhantomData,
        }
    }
}

impl<Inner, RC, ReqBody, RespBody> Service<(Request<ReqBody>, RC)> for AllowAllAuthenticator<Inner, RC, ReqBody, RespBody>
where
    RC: RcBound + 'static,
    RC::Result: Send + 'static,
    Inner: Service<(Request<ReqBody>, RC::Result), Response = hyper::Response<RespBody>> + Send + 'static,
    Inner::Future: Send + 'static,
    Inner::Error: Send + 'static,
    ReqBody: hyper::body::Body,
    RespBody: hyper::body::Body,
{
    type Response = hyper::Response<RespBody>;
    type Error = Inner::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: (Request<ReqBody>, RC)) -> Self::Future {
        let (request, context) = req;
        let context = context.push(Some(Authorization {
            subject: self.subject.clone(),
            scopes: Scopes::All,
            issuer: None,
        }));

        Box::pin(self.inner.call((request, context)))
    }
}

/// Retrieve an authorization scheme data from a set of headers
pub fn from_headers<S: headers::authorization::Credentials>(headers: &HeaderMap) -> Option<S> {
    headers
        .typed_get::<headers::Authorization<S>>()
        .map(|auth| auth.0)
}

/// Retrieve an API key from a header
pub fn api_key_from_header(headers: &HeaderMap, header: &str) -> Option<String> {
    headers
        .get(header)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContextBuilder, Has};
    use crate::EmptyContext;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::Service;
    use hyper::Response;

    struct MakeTestService;

    type ReqWithAuth = (
        Request<Full<Bytes>>,
        ContextBuilder<Option<Authorization>, EmptyContext>,
    );

    impl<Target> Service<Target> for MakeTestService
    {
        type Response = TestService;
        type Error = ();
        type Future = futures::future::Ready<Result<Self::Response, Self::Error>>;

        fn call(&self, _target: Target) -> Self::Future {
            futures::future::ok(TestService)
        }
    }

    struct TestService;

    impl Service<ReqWithAuth> for TestService
    {
        type Response = Response<Full<Bytes>>;
        type Error = String;
        type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn call(&self, req: ReqWithAuth) -> Self::Future {
            Box::pin(async move {
                let auth: &Option<Authorization> = req.1.get();
                let expected = Some(Authorization {
                    subject: "foo".to_string(),
                    scopes: Scopes::All,
                    issuer: None,
                });

                if *auth == expected {
                    Ok(Response::new(Full::default()))
                } else {
                    Err(format!("{:?} != {:?}", auth, expected))
                }
            })
        }
    }

    #[tokio::test]
    async fn test_make_service() {
        let make_svc = MakeTestService;

        let a: MakeAllowAllAuthenticator<_, EmptyContext, _, _> =
            MakeAllowAllAuthenticator::new(make_svc, "foo");

        let service = a.call(&()).await.unwrap();

        let response = service
            .call((
                Request::get("http://localhost")
                    .body(Full::default())
                    .unwrap(),
                EmptyContext::default(),
            ))
            .await;

        response.unwrap();
    }
}
