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

/// Struct that is responsible for handling queries sent by user.
pub struct HttpQueryHandlerImpl {
    log: ReplicaLogger,
    hypervisor: Arc<Hypervisor>,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    query_allocations_used: Arc<RwLock<QueryAllocationsUsed>>,
    subnet_memory_capacity: NumBytes,
    metrics: QueryHandlerMetrics,
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
}

impl QueryHandler for HttpQueryHandlerImpl {
    type State = ReplicatedState;

    fn query(
        &self,
        query: UserQuery,
        state: Arc<Self::State>,
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
