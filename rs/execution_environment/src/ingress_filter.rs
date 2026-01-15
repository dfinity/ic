use crate::query_handler::QueryScheduler;
use crate::{ExecutionEnvironment, metrics::IngressFilterMetrics};
use ic_interfaces::execution_environment::{
    ExecutionMode, IngressFilterError, IngressFilterInput, IngressFilterResponse,
    IngressFilterService,
};
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tower::{Service, util::BoxCloneService};

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

impl Service<IngressFilterInput> for IngressFilterServiceImpl {
    type Response = IngressFilterResponse;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (provisional_whitelist, raw_ingress): IngressFilterInput) -> Self::Future {
        let exec_env = Arc::clone(&self.exec_env);
        let metrics = Arc::clone(&self.metrics);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let canister_id = raw_ingress.content().canister_id();
        self.query_scheduler.push(canister_id, move || {
            let start = std::time::Instant::now();
            if !tx.is_closed() {
                let result = match state_reader.get_latest_certified_state() {
                    Some(state) => {
                        let v = exec_env.should_accept_ingress_message(
                            state.take(),
                            &provisional_whitelist,
                            &raw_ingress,
                            ExecutionMode::NonReplicated,
                            &metrics,
                        );
                        Ok(v)
                    }
                    None => Err(IngressFilterError::CertifiedStateUnavailable),
                };

                let _ = tx.send(Ok(result));
            }
            start.elapsed()
        });
        Box::pin(async move {
            rx.await
                .expect("The sender was dropped before sending the message.")
        })
    }
}
