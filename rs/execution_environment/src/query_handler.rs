//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_allocations;
mod query_context;
#[cfg(test)]
mod tests;

use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use ic_interfaces::execution_environment::{QueryHandler, SubnetAvailableMemory};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    ingress::WasmResult, messages::UserQuery, user_error::UserError, NumBytes, SubnetId,
};
use query_allocations::QueryAllocationsUsed;
use std::sync::{Arc, RwLock};

const QUERY_EXECUTION_THREADS: usize = 1;

pub(crate) struct InternalHttpQueryHandlerImpl {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
    subnet_memory_capacity: NumBytes,
    pub(crate) metrics: QueryHandlerMetrics,
}

/// Struct that is responsible for handling queries sent by user.
pub struct HttpQueryHandlerImpl {
    internal: Arc<InternalHttpQueryHandlerImpl>,
    threadpool: rayon::ThreadPool,
}

impl InternalHttpQueryHandlerImpl {
    fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        subnet_memory_capacity: NumBytes,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            log,
            hypervisor,
            own_subnet_id,
            own_subnet_type,
            query_allocations_used: Arc::new(RwLock::new(QueryAllocationsUsed::new())),
            subnet_memory_capacity,
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
        let subnet_available_memory = SubnetAvailableMemory::new(self.subnet_memory_capacity);

        let mut context = query_context::QueryContext::new(
            &self.log,
            self.hypervisor.as_ref(),
            self.own_subnet_id,
            self.own_subnet_type,
            state,
            data_certificate,
            self.query_allocations_used.clone(),
            subnet_available_memory,
        );
        context.run(query, &self.metrics, &measurement_scope)
    }
}

impl HttpQueryHandlerImpl {
    pub fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        subnet_memory_capacity: NumBytes,
        metrics_registry: &MetricsRegistry,
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
                subnet_memory_capacity,
                metrics_registry,
            )),
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

    fn non_blocking_query(
        &self,
        query: UserQuery,
        state: Arc<Self::State>,
        data_certificate: Vec<u8>,
        callback: Box<dyn FnOnce(Result<WasmResult, UserError>) + Send + 'static>,
    ) {
        let internal = Arc::clone(&self.internal);
        self.threadpool.spawn(move || {
            let v = internal.query(query, state, data_certificate);
            callback(v);
        });
    }
}
