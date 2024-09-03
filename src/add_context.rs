//! Hyper service that adds a context to an incoming request and passes it on
//! to a wrapped service.

use crate::{Push, XSpanIdString};
use futures::future::FutureExt;
use hyper::body::Body;
use hyper::Request;
use std::marker::PhantomData;

/// Middleware wrapper service, that should be used as the outermost layer in a
/// stack of hyper services. Adds a context to a plain `hyper::Request` that can be
/// used by subsequent layers in the stack.
#[derive(Debug)]
pub struct AddContextMakeService<T, C, ReqBody, RespBody>
where
    C: Default + Push<XSpanIdString> + 'static + Send,
    C::Result: Send + 'static,
{
    inner: T,
    marker: PhantomData<fn(C, ReqBody, RespBody)>,
}

impl<T, C, ReqBody, RespBody> AddContextMakeService<T, C, ReqBody, RespBody>
where
    C: Default + Push<XSpanIdString> + 'static + Send,
    C::Result: Send + 'static,
{
    /// Create a new AddContextMakeService struct wrapping a value
    pub fn new(inner: T) -> Self {
        AddContextMakeService {
            inner,
            marker: PhantomData,
        }
    }
}

impl<Inner, Context, Target, ReqBody, RespBody> hyper::service::Service<Target>
    for AddContextMakeService<Inner, Context, ReqBody, RespBody>
where
    Context: Default + Push<XSpanIdString> + 'static + Send,
    Context::Result: Send + 'static,
    Inner: hyper::service::Service<Target>,
    Inner::Future: Send + 'static,
    ReqBody: Body,
    RespBody: Body,
{
    type Error = Inner::Error;
    type Response = AddContextService<Inner::Response, Context, ReqBody, RespBody>;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, target: Target) -> Self::Future {
        Box::pin(
            self.inner
                .call(target)
                .map(|s| Ok(AddContextService::new(s?))),
        )
    }
}

/// Middleware wrapper service, that should be used as the outermost layer in a
/// stack of hyper services. Adds a context to a plain `hyper::Request` that can be
/// used by subsequent layers in the stack. The `AddContextService` struct should
/// not usually be used directly - when constructing a hyper stack use
/// `AddContextMakeService`, which will create `AddContextService` instances as needed.
#[derive(Debug)]
pub struct AddContextService<T, C, ReqBody, RespBody>
where
    C: Default + Push<XSpanIdString>,
    C::Result: Send + 'static,
{
    inner: T,
    marker: PhantomData<fn(C, ReqBody, RespBody)>,
}

impl<T, C, ReqBody, RespBody> AddContextService<T, C, ReqBody, RespBody>
where
    C: Default + Push<XSpanIdString>,
    C::Result: Send + 'static,
{
    /// Create a new AddContextService struct wrapping a value
    pub fn new(inner: T) -> Self {
        AddContextService {
            inner,
            marker: PhantomData,
        }
    }
}

impl<Inner, Context, ReqBody, RespBody> hyper::service::Service<Request<ReqBody>>
    for AddContextService<Inner, Context, ReqBody, RespBody>
where
    Context: Default + Push<XSpanIdString> + Send + 'static,
    Context::Result: Send + 'static,
    Inner: hyper::service::Service<(Request<ReqBody>, Context::Result)>,
    ReqBody: Body,
    RespBody: Body,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = Inner::Future;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let x_span_id = XSpanIdString::get_or_generate(&req);
        let context = Context::default().push(x_span_id);

        self.inner.call((req, context))
    }
}
