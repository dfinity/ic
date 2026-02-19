use crate::convert::Convert;
use futures_util::future;
use std::task::{Context, Poll};
use tower::Service;
use tower_layer::Layer;

/// Convert request of a service into another type, where the conversion may fail.
///
/// This [`Layer`] produces instances of the [`ConvertRequest`] service.
///
/// [`Layer`]: tower::Layer
#[derive(Debug, Clone)]
pub struct ConvertRequestLayer<C> {
    converter: C,
}

impl<C> ConvertRequestLayer<C> {
    /// Returns a new [`ConvertRequestLayer`]
    pub fn new(converter: C) -> Self {
        Self { converter }
    }
}

/// Convert requests into another type and forward the converted type to the inner service
/// *only if* the conversion was successful.
#[derive(Debug, Clone)]
pub struct ConvertRequest<S, C> {
    inner: S,
    converter: C,
}

impl<S, C: Clone> Layer<S> for ConvertRequestLayer<C> {
    type Service = ConvertRequest<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            converter: self.converter.clone(),
        }
    }
}

impl<S, Converter, Request, NewRequest, Error> Service<NewRequest> for ConvertRequest<S, Converter>
where
    Converter: Convert<NewRequest, Output = Request>,
    S: Service<Request, Error = Error>,
    Converter::Error: Into<Error>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = future::Either<S::Future, future::Ready<Result<S::Response, S::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, new_req: NewRequest) -> Self::Future {
        match self.converter.try_convert(new_req) {
            Ok(request) => future::Either::Left(self.inner.call(request)),
            Err(err) => future::Either::Right(future::ready(Err(err.into()))),
        }
    }
}
