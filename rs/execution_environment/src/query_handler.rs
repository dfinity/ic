//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_allocations;
mod query_context;
#[cfg(test)]
mod tests;

use crate::{
    common::{PendingFutureResult, PendingFutureResultInternal},
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use ic_config::execution_environment::Config;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, LabeledTree::SubTree};
use ic_interfaces::{
    execution_environment::{QueryExecutionService, QueryHandler, SubnetAvailableMemory},
    state_manager::StateReader,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    canonical_error::CanonicalError,
    ingress::WasmResult,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpQueryResponse, HttpQueryResponseReply,
        UserQuery,
    },
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, NumInstructions, SubnetId,
};
use query_allocations::QueryAllocationsUsed;
use serde::Serialize;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
};
use tower::{util::BoxService, Service, ServiceBuilder};

/// Convert an object into CBOR binary.
fn into_cbor<R: Serialize>(r: &R) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("Could not write magic tag.");
    r.serialize(&mut ser).expect("Serialization failed.");
    ser.into_inner()
}

fn get_latest_certified_state_and_data_certificate(
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    certificate_delegation: Option<CertificateDelegation>,
    canister_id: CanisterId,
) -> Option<(Arc<ReplicatedState>, Vec<u8>)> {
    // The path to fetch the data certificate for the canister.
    let path = SubTree(flatmap! {
        label("canister") => SubTree(
            flatmap! {
                label(canister_id.get_ref()) => SubTree(
                    flatmap!(label("certified_data") => LabeledTree::Leaf(()))
                )
            }),
        // NOTE: "time" is added here to ensure that `read_certified_state`
        // returns the certified state. This won't be necessary once non-existence
        // proofs are implemented.
        label("time") => LabeledTree::Leaf(())
    });

    state_reader
        .read_certified_state(&path)
        .map(|(state, tree, cert)| {
            (
                state,
                into_cbor(&Certificate {
                    tree,
                    signature: Blob(cert.signed.signature.signature.get().0),
                    delegation: certificate_delegation,
                }),
            )
        })
}

fn label<T: Into<Label>>(t: T) -> Label {
    t.into()
}

pub(crate) struct InternalHttpQueryHandler {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
    config: Config,
    metrics: QueryHandlerMetrics,
    max_instructions_per_message: NumInstructions,
}

/// Struct that is responsible for handling queries sent by user.
pub(crate) struct HttpQueryHandler {
    internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: Arc<Mutex<threadpool::ThreadPool>>,
}

impl InternalHttpQueryHandler {
    pub(crate) fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: Config,
        metrics_registry: &MetricsRegistry,
        max_instructions_per_message: NumInstructions,
    ) -> Self {
        Self {
            log,
            hypervisor,
            own_subnet_id,
            own_subnet_type,
            query_allocations_used: Arc::new(RwLock::new(QueryAllocationsUsed::new())),
            config,
            metrics: QueryHandlerMetrics::new(metrics_registry),
            max_instructions_per_message,
        }
    }
}

impl QueryHandler for InternalHttpQueryHandler {
    type State = ReplicatedState;

    fn query(
        &self,
        query: UserQuery,
        state: Arc<ReplicatedState>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let measurement_scope = MeasurementScope::root(&self.metrics.query);
        // Note that This assumes that the QueryHandler is always called with the
        // "latest" state.  If and when we start supporting queries against older
        // versions of the state, we will need the caller of the QueryHandler to
        // still supply its view of the "latest" state to allow looking up the
        // "current" time.
        self.query_allocations_used
            .write()
            .unwrap()
            .purge(state.metadata.batch_time);

        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory =
            SubnetAvailableMemory::new(self.config.subnet_memory_capacity.get() as i64);
        let max_canister_memory_size = self.config.max_canister_memory_size;

        let mut context = query_context::QueryContext::new(
            &self.log,
            self.hypervisor.as_ref(),
            self.own_subnet_id,
            self.own_subnet_type,
            state,
            data_certificate,
            self.query_allocations_used.clone(),
            subnet_available_memory,
            max_canister_memory_size,
            self.max_instructions_per_message,
        );
        context.run(query, &self.metrics, &measurement_scope)
    }
}

impl HttpQueryHandler {
    pub(crate) fn new_service(
        max_buffered_queries: usize,
        threads: usize,
        internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
        threadpool: Arc<Mutex<threadpool::ThreadPool>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> QueryExecutionService {
        let base_service = Self {
            internal,
            state_reader,
            threadpool,
        };
        let base_service = BoxService::new(
            ServiceBuilder::new()
                .concurrency_limit(threads)
                .service(base_service),
        );

        // TODO(NET-795): provide documentation on the design of the interface
        ServiceBuilder::new()
            .load_shed()
            .buffer(max_buffered_queries)
            .service(base_service)
    }
}

impl QueryHandler for HttpQueryHandler {
    type State = ReplicatedState;

    fn query(
        &self,
        query: UserQuery,
        state: Arc<Self::State>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.internal.query(query, state, data_certificate)
    }
}

type FutureQueryResult = PendingFutureResult<HttpQueryResponse>;

impl Default for FutureQueryResult {
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

impl Service<(UserQuery, Option<CertificateDelegation>)> for HttpQueryHandler {
    type Response = HttpQueryResponse;
    type Error = CanonicalError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        (query, certificate_delegation): (UserQuery, Option<CertificateDelegation>),
    ) -> Self::Future {
        let internal = Arc::clone(&self.internal);
        let state_reader = Arc::clone(&self.state_reader);
        let future = FutureQueryResult::default();
        let weak_future = future.weak();
        let threadpool = self.threadpool.lock().unwrap().clone();
        threadpool.execute(move || {
            if let Some(future) = FutureQueryResult::from_weak(weak_future) {
                // We managed to upgrade the weak pointer, so the query was not cancelled.
                // Canceling the query after this point will have to effect: the query will
                // be executed anyway. That is fine because the execution will take O(ms).
                let result = match get_latest_certified_state_and_data_certificate(
                    state_reader,
                    certificate_delegation,
                    query.receiver,
                ) {
                    Some((state, cert)) => internal.query(query, state, cert),
                    None => Err(UserError::new(
                        ErrorCode::CertifiedStateUnavailable,
                        "Certified state is not available yet. Please try again...",
                    )),
                };

                let http_query_response = match result {
                    Ok(res) => match res {
                        WasmResult::Reply(vec) => HttpQueryResponse::Replied {
                            reply: HttpQueryResponseReply { arg: Blob(vec) },
                        },
                        WasmResult::Reject(message) => HttpQueryResponse::Rejected {
                            reject_code: RejectCode::CanisterReject as u64,
                            reject_message: message,
                        },
                    },

                    Err(user_error) => HttpQueryResponse::Rejected {
                        reject_code: user_error.reject_code() as u64,
                        reject_message: user_error.to_string(),
                    },
                };

                future.resolve(Ok(http_query_response));
            }
        });
        Box::pin(future)
    }
}
