//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_context;
#[cfg(test)]
mod tests;

use crate::execution_environment::subnet_memory_capacity;
use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use ic_config::execution_environment::Config;
use ic_config::flag_status::FlagStatus;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, LabeledTree::SubTree};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{QueryExecutionService, QueryHandler};
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpQueryResponse, HttpQueryResponseReply,
        UserQuery,
    },
    CanisterId, NumInstructions,
};
use serde::Serialize;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::sync::oneshot;
use tower::{limit::GlobalConcurrencyLimitLayer, util::BoxCloneService, Service, ServiceBuilder};

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

pub struct InternalHttpQueryHandler {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    own_subnet_type: SubnetType,
    config: Config,
    metrics: QueryHandlerMetrics,
    max_instructions_per_query: NumInstructions,
    cycles_account_manager: Arc<CyclesAccountManager>,
    composite_queries: FlagStatus,
}

#[derive(Clone)]
/// Struct that is responsible for handling queries sent by user.
pub(crate) struct HttpQueryHandler {
    internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: Arc<Mutex<threadpool::ThreadPool>>,
}

impl InternalHttpQueryHandler {
    pub fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_type: SubnetType,
        config: Config,
        metrics_registry: &MetricsRegistry,
        max_instructions_per_query: NumInstructions,
        cycles_account_manager: Arc<CyclesAccountManager>,
        composite_queries: FlagStatus,
    ) -> Self {
        Self {
            log,
            hypervisor,
            own_subnet_type,
            config,
            metrics: QueryHandlerMetrics::new(metrics_registry),
            max_instructions_per_query,
            cycles_account_manager,
            composite_queries,
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

        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory = subnet_memory_capacity(&self.config);
        let max_canister_memory_size = self.config.max_canister_memory_size;

        let mut context = query_context::QueryContext::new(
            &self.log,
            self.hypervisor.as_ref(),
            self.own_subnet_type,
            state,
            data_certificate,
            subnet_available_memory,
            max_canister_memory_size,
            self.max_instructions_per_query,
            self.config.max_query_call_depth,
            self.config.max_instructions_per_composite_query_call,
            self.config.instruction_overhead_per_query_call,
            self.composite_queries,
        );
        context.run(
            query,
            &self.metrics,
            Arc::clone(&self.cycles_account_manager),
            &measurement_scope,
        )
    }
}

impl HttpQueryHandler {
    pub(crate) fn new_service(
        concurrency_buffer: GlobalConcurrencyLimitLayer,
        internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
        threadpool: Arc<Mutex<threadpool::ThreadPool>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> QueryExecutionService {
        let base_service = BoxCloneService::new(Self {
            internal,
            state_reader,
            threadpool,
        });
        ServiceBuilder::new()
            .layer(concurrency_buffer)
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

impl Service<(UserQuery, Option<CertificateDelegation>)> for HttpQueryHandler {
    type Response = HttpQueryResponse;
    type Error = Infallible;
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
        let (tx, rx) = oneshot::channel();
        let threadpool = self.threadpool.lock().unwrap().clone();
        threadpool.execute(move || {
            if !tx.is_closed() {
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
                            error_code: ErrorCode::CanisterRejectedMessage.to_string(),
                            reject_code: RejectCode::CanisterReject as u64,
                            reject_message: message,
                        },
                    },

                    Err(user_error) => HttpQueryResponse::Rejected {
                        error_code: user_error.code().to_string(),
                        reject_code: user_error.reject_code() as u64,
                        reject_message: user_error.to_string(),
                    },
                };

                let _ = tx.send(Ok(http_query_response));
            }
        });
        Box::pin(async move {
            rx.await
                .expect("The sender was dropped before sending the message.")
        })
    }
}
