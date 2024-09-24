//! Hyper service that adds a context to an incoming request and passes it on
//! to a wrapped service.

use crate::{Push, XSpanIdString};
use futures::FutureExt;
use hyper::Request;
use std::marker::PhantomData;

/// Middleware wrapper service, that should be used as the outermost layer in a
/// stack of hyper services. Adds a context to a plain `hyper::Request` that can be
/// used by subsequent layers in the stack.
#[derive(Debug)]
pub struct AddContextMakeService<T, C>
where
    C: Default + Push<XSpanIdString> + 'static + Send,
    C::Result: Send + 'static,
{
    inner: T,
    marker: PhantomData<fn(C)>,
}

impl<T, C> AddContextMakeService<T, C>
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

impl<Inner, Context, Target> hyper::service::Service<Target>
    for AddContextMakeService<Inner, Context>
where
    Context: Default + Push<XSpanIdString> + 'static + Send,
    Context::Result: Send + 'static,
    Inner: hyper::service::Service<Target>,
    Inner::Response: Clone,
    Inner::Future: Send + 'static,
{
    type Error = Inner::Error;
    type Response = AddContextService<Inner::Response, Context>;
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
pub struct AddContextService<T, C>
where
    C: Default + Push<XSpanIdString>,
    C::Result: Send + 'static,
    T: Clone,
{
    inner: T,
    marker: PhantomData<fn(C)>,
}

impl<T, C> Clone for AddContextService<T, C>
where
    C: Default + Push<XSpanIdString>,
    C::Result: Send + 'static,
    T: Clone,
{
    fn clone(&self) -> Self {
        AddContextService {
            inner: self.inner.clone(),
            marker: PhantomData,
        }
    }
}

impl<T, C> AddContextService<T, C>
where
    C: Default + Push<XSpanIdString>,
    C::Result: Send + 'static,
    T: Clone,
{
    /// Create a new AddContextService struct wrapping a value
    pub fn new(inner: T) -> Self {
        AddContextService {
            inner,
            marker: PhantomData,
        }
    }
}

impl<Inner, Context, ReqBody> hyper::service::Service<Request<ReqBody>>
    for AddContextService<Inner, Context>
where
    Context: Default + Push<XSpanIdString> + Send + 'static,
    Context::Result: Send + 'static,
    Inner: hyper::service::Service<(Request<ReqBody>, Context::Result)> + Clone,
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
