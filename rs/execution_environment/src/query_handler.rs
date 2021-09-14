//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod compilation_cache;
mod query_allocations;
mod query_context;
#[cfg(test)]
mod tests;

use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use compilation_cache::CompilationCache;
use ic_config::execution_environment::Config;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, LabeledTree::SubTree};
use ic_interfaces::{
    execution_environment::{QueryHandler, SubnetAvailableMemory},
    state_manager::StateReader,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult,
    messages::{Blob, Certificate, CertificateDelegation, UserQuery},
    user_error::{ErrorCode, UserError},
    CanisterId, SubnetId,
};
use query_allocations::QueryAllocationsUsed;
use serde::Serialize;
use std::sync::{Arc, RwLock};

const QUERY_EXECUTION_THREADS: usize = 1;

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

struct InternalHttpQueryHandlerImpl {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
    compilation_cache: Arc<RwLock<CompilationCache>>,
    config: Config,
    metrics: QueryHandlerMetrics,
}

/// Struct that is responsible for handling queries sent by user.
pub(crate) struct HttpQueryHandlerImpl {
    internal: Arc<InternalHttpQueryHandlerImpl>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    threadpool: rayon::ThreadPool,
}

impl InternalHttpQueryHandlerImpl {
    fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: Config,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            log,
            hypervisor,
            own_subnet_id,
            own_subnet_type,
            query_allocations_used: Arc::new(RwLock::new(QueryAllocationsUsed::new())),
            compilation_cache: Arc::new(RwLock::new(CompilationCache::new())),
            config,
            metrics: QueryHandlerMetrics::new(metrics_registry),
        }
    }

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
            SubnetAvailableMemory::new(self.config.subnet_memory_capacity);
        let max_canister_memory_size = self.config.max_canister_memory_size;

        let mut context = query_context::QueryContext::new(
            &self.log,
            self.hypervisor.as_ref(),
            self.own_subnet_id,
            self.own_subnet_type,
            state,
            data_certificate,
            self.query_allocations_used.clone(),
            self.compilation_cache.clone(),
            subnet_available_memory,
            max_canister_memory_size,
        );
        context.run(query, &self.metrics, &measurement_scope)
    }
}

impl HttpQueryHandlerImpl {
    pub(crate) fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: Config,
        metrics_registry: &MetricsRegistry,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Self {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(QUERY_EXECUTION_THREADS)
            .thread_name(|idx| format!("query_execution thread index {}", idx))
            .stack_size(8_192_000)
            .build()
            .unwrap();

        Self {
            internal: Arc::new(InternalHttpQueryHandlerImpl::new(
                log,
                hypervisor,
                own_subnet_id,
                own_subnet_type,
                config,
                metrics_registry,
            )),
            state_reader,
            threadpool: pool,
        }
    }
}

impl QueryHandler for HttpQueryHandlerImpl {
    type State = ReplicatedState;

    fn query(
        &self,
        query: UserQuery,
        state: Arc<Self::State>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.internal.query(query, state, data_certificate)
    }

    fn query_latest_certified_state(
        &self,
        query: UserQuery,
        certificate_delegation: Option<CertificateDelegation>,
        callback: Box<dyn FnOnce(Result<WasmResult, UserError>) + Send + 'static>,
    ) {
        let internal = Arc::clone(&self.internal);
        let state_reader = Arc::clone(&self.state_reader);
        self.threadpool.spawn(move || {
            let v = match get_latest_certified_state_and_data_certificate(
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
            callback(v);
        });
    }
}
