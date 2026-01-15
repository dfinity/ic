use std::future::Future;

/// An implementation of hyper Executor that spawns futures on a tokio runtime
/// handle.
#[derive(Clone, Debug)]
pub struct ExecuteOnTokioRuntime(pub tokio::runtime::Handle);

impl<F> hyper::rt::Executor<F> for ExecuteOnTokioRuntime
where
    F: Future + 'static + Send,
    <F as Future>::Output: Send,
{
    fn execute(&self, fut: F) {
        self.0.spawn(fut);
    }
}
