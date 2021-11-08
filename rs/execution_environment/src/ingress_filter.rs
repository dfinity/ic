use crate::{
    common::{PendingFutureResult, PendingFutureResultInternal},
    ExecutionEnvironmentImpl,
};
use ic_interfaces::state_manager::StateReader;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::ReplicatedState;
use ic_types::{canonical_error::CanonicalError, messages::SignedIngressContent};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tower::Service;

pub(crate) struct IngressFilter {
    exec_env: Arc<ExecutionEnvironmentImpl>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: Arc<Mutex<threadpool::ThreadPool>>,
}

impl IngressFilter {
    pub(crate) fn new(
        threadpool: Arc<Mutex<threadpool::ThreadPool>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        exec_env: Arc<ExecutionEnvironmentImpl>,
    ) -> Self {
        Self {
            exec_env,
            state_reader,
            threadpool,
        }
    }
}

type FutureIngressFilterResult = PendingFutureResult<()>;

impl Default for FutureIngressFilterResult {
    fn default() -> Self {
        let inner = PendingFutureResultInternal {
            result: None,
            waker: None,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl Service<(ProvisionalWhitelist, SignedIngressContent)> for IngressFilter {
    type Response = ();
    type Error = CanonicalError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        (provisional_whitelist, ingress): (ProvisionalWhitelist, SignedIngressContent),
    ) -> Self::Future {
        let exec_env = Arc::clone(&self.exec_env);
        let state_reader = Arc::clone(&self.state_reader);
        let future = FutureIngressFilterResult::default();
        let weak_future = future.weak();
        let threadpool = self.threadpool.lock().unwrap().clone();
        threadpool.execute(move || {
            if let Some(future) = FutureIngressFilterResult::from_weak(weak_future) {
                let state = state_reader.get_latest_state().take();
                let v =
                    exec_env.should_accept_ingress_message(state, &provisional_whitelist, &ingress);
                future.resolve(v);
            }
        });
        Box::pin(future)
    }
}
