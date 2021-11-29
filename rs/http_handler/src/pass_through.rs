use futures_util::TryFutureExt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Clone)]
pub(crate) struct PassThroughLayer;

impl<S> Layer<S> for PassThroughLayer {
    type Service = PassThroughService<S>;

    fn layer(&self, service: S) -> Self::Service {
        PassThroughService { service }
    }
}

pub(crate) struct PassThroughService<S> {
    service: S,
}

impl<Req, Res, P, E, S, F> Service<(Req, P)> for PassThroughService<S>
where
    S: Service<Req, Response = Res, Error = E, Future = F>,
    F: Send + Future<Output = Result<Res, E>> + 'static,
    E: 'static + Send,
    P: 'static + Send,
{
    type Response = (S::Response, P);
    type Error = S::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, (req, pass_through): (Req, P)) -> Self::Future {
        Box::pin(
            self.service
                .call(req)
                .map_ok(move |response| (response, pass_through)),
        )
    }
}
