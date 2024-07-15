use crate::query_handler::QueryScheduler;
use crate::{metrics::IngressFilterMetrics, ExecutionEnvironment};
use ic_error_types::UserError;
use ic_interfaces::execution_environment::{ExecutionMode, IngressFilterService};
use ic_interfaces_state_manager::StateReader;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::SignedIngressContent;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tower::{util::BoxCloneService, Service};

#[derive(Clone)]
pub(crate) struct IngressFilterServiceImpl {
    exec_env: Arc<ExecutionEnvironment>,
    metrics: Arc<IngressFilterMetrics>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    query_scheduler: QueryScheduler,
}

impl IngressFilterServiceImpl {
    pub(crate) fn new_service(
        query_scheduler: QueryScheduler,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        exec_env: Arc<ExecutionEnvironment>,
        metrics: Arc<IngressFilterMetrics>,
    ) -> IngressFilterService {
        BoxCloneService::new(Self {
            exec_env,
            metrics,
            state_reader,
            query_scheduler,
        })
    }
}

impl Service<(ProvisionalWhitelist, SignedIngressContent)> for IngressFilterServiceImpl {
    type Response = Result<(), UserError>;
    type Error = Infallible;
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
        let metrics = Arc::clone(&self.metrics);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let canister_id = ingress.canister_id();
        self.query_scheduler.push(canister_id, move || {
            let start = std::time::Instant::now();
            if !tx.is_closed() {
                let state = state_reader.get_latest_state().take();
                let v = exec_env.should_accept_ingress_message(
                    state,
                    &provisional_whitelist,
                    &ingress,
                    ExecutionMode::NonReplicated,
                    &metrics,
                );
                let _ = tx.send(Ok(v));
            }
            start.elapsed()
        });
        Box::pin(async move {
            rx.await
                .expect("The sender was dropped before sending the message.")
        })
    }
}
