use std::convert::Infallible;

use futures::future::{ready, Ready};

/// Turn a service into a make service
#[derive(Debug)]
pub struct IntoMakeService<S> {
    service: S,
}

impl<S> IntoMakeService<S> {
    /// Create a new [`IntoMakeService`] from a service.
    pub const fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S, T> hyper::service::Service<T> for IntoMakeService<S>
where
    S: Clone,
{
    type Response = S;
    type Error = Infallible;
    type Future = Ready<Result<S, Infallible>>;

    fn call(&self, _target: T) -> Self::Future {
        ready(Ok(self.service.clone()))
    }
}
