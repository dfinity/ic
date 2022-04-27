use crate::ExecutionEnvironmentImpl;
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::AnonymousQueryService;
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult,
    messages::{Blob, InternalQuery, InternalQueryResponse, InternalQueryResponseReply},
    NumInstructions,
};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tower::{util::BoxService, Service, ServiceBuilder};

// Struct that is responsible for handling queries sent by internal IC components.
pub(crate) struct AnonymousQueryHandler {
    exec_env: Arc<ExecutionEnvironmentImpl>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: Arc<Mutex<threadpool::ThreadPool>>,
    max_instructions_per_message: NumInstructions,
}

impl AnonymousQueryHandler {
    pub(crate) fn new_service(
        threads: usize,
        max_buffered_queries: usize,
        threadpool: Arc<Mutex<threadpool::ThreadPool>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        exec_env: Arc<ExecutionEnvironmentImpl>,
        max_instructions_per_message: NumInstructions,
    ) -> AnonymousQueryService {
        let base_service = Self {
            exec_env,
            state_reader,
            threadpool,
            max_instructions_per_message,
        };
        let base_service = BoxService::new(
            ServiceBuilder::new()
                .concurrency_limit(threads)
                .service(base_service),
        );
        ServiceBuilder::new()
            .buffer(max_buffered_queries)
            .service(base_service)
    }
}

impl Service<InternalQuery> for AnonymousQueryHandler {
    type Response = InternalQueryResponse;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, internal_query: InternalQuery) -> Self::Future {
        let instructions_limit = self.max_instructions_per_message;
        let exec_env = Arc::clone(&self.exec_env);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let threadpool = self.threadpool.lock().unwrap().clone();
        threadpool.execute(move || {
            if !tx.is_closed() {
                let state = state_reader.get_latest_state().take();
                let result =
                    exec_env.execute_anonymous_query(internal_query, state, instructions_limit);

                let internal_query_response = match result {
                    Ok(wasm_result) => match wasm_result {
                        WasmResult::Reply(vec) => InternalQueryResponse::Replied {
                            reply: InternalQueryResponseReply { arg: Blob(vec) },
                        },
                        WasmResult::Reject(message) => InternalQueryResponse::Rejected {
                            reject_code: RejectCode::CanisterReject,
                            reject_message: message,
                        },
                    },
                    Err(user_error) => InternalQueryResponse::Rejected {
                        reject_code: user_error.reject_code(),
                        reject_message: user_error.to_string(),
                    },
                };

                let _ = tx.send(Ok(internal_query_response));
            }
        });
        Box::pin(async move {
            rx.await
                .expect("The sender was dropped before sending the message.")
        })
    }
}
