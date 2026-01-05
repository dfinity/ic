//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_cache;
mod query_call_graph;
mod query_context;
mod query_scheduler;
#[cfg(test)]
mod tests;

use crate::execution_environment::full_subnet_memory_capacity;
use crate::{
    CanisterManager,
    canister_logs::fetch_canister_logs,
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use candid::Encode;
use ic_config::flag_status::FlagStatus;
use ic_config::{execution_environment::Config, subnet_config::DEFAULT_REFERENCE_SUBNET_SIZE};
use ic_crypto_tree_hash::{Label, LabeledTree, LabeledTree::SubTree, flatmap};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    QueryExecutionError, QueryExecutionInput, QueryExecutionResponse, QueryExecutionService,
    TransformExecutionInput, TransformExecutionService,
};
use ic_interfaces_state_manager::{Labeled, StateReader};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_query_stats::QueryStatsCollector;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::QueryStatsEpoch;
use ic_types::batch::QueryStats;
use ic_types::messages::CertificateDelegationMetadata;
use ic_types::{
    CanisterId, NumInstructions,
    ingress::WasmResult,
    messages::{Blob, Certificate, CertificateDelegation, Query},
};
use prometheus::{Histogram, histogram_opts, labels};
use serde::Serialize;
use std::convert::Infallible;
use std::str::FromStr;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::sync::oneshot;
use tower::{Service, util::BoxCloneService};

pub(crate) use self::query_scheduler::QueryScheduler;
use ic_management_canister_types_private::{
    CanisterIdRecord, FetchCanisterLogsRequest, Payload, QueryMethod,
};

pub struct DataCertificateWithDelegationMetadata {
    pub data_certificate: Vec<u8>,
    pub certificate_delegation_metadata: Option<CertificateDelegationMetadata>,
}

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
) -> Option<(Labeled<Arc<ReplicatedState>>, Vec<u8>)> {
    // The path to fetch the data certificate for the canister.
    let path = SubTree(flatmap! {
        label("canister") => SubTree(
            flatmap! {
                label(canister_id.get_ref()) => SubTree(
                    flatmap!(label("certified_data") => LabeledTree::Leaf(()))
                )
            }),
        // We must always add the time path to comply with the IC spec.
        label("time") => LabeledTree::Leaf(())
    });

    state_reader
        .read_certified_state(&path)
        .map(|(state, tree, cert)| {
            (
                Labeled::new(cert.height, state),
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
    canister_manager: Arc<CanisterManager>,
    own_subnet_type: SubnetType,
    config: Config,
    metrics: QueryHandlerMetrics,
    max_instructions_per_query: NumInstructions,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_query_execution_stats: QueryStatsCollector,
    query_cache: query_cache::QueryCache,
}

impl InternalHttpQueryHandler {
    pub(crate) fn new(
        log: ReplicaLogger,
        hypervisor: Arc<Hypervisor>,
        canister_manager: Arc<CanisterManager>,
        own_subnet_type: SubnetType,
        config: Config,
        metrics_registry: &MetricsRegistry,
        max_instructions_per_query: NumInstructions,
        cycles_account_manager: Arc<CyclesAccountManager>,
        local_query_execution_stats: QueryStatsCollector,
    ) -> Self {
        let query_cache_capacity = config.query_cache_capacity;
        let query_max_expiry_time = config.query_cache_max_expiry_time;
        let query_data_certificate_expiry_time = config.query_cache_data_certificate_expiry_time;
        Self {
            log,
            hypervisor,
            canister_manager,
            own_subnet_type,
            config,
            metrics: QueryHandlerMetrics::new(metrics_registry),
            max_instructions_per_query,
            cycles_account_manager,
            local_query_execution_stats,
            query_cache: query_cache::QueryCache::new(
                metrics_registry,
                query_cache_capacity,
                query_max_expiry_time,
                query_data_certificate_expiry_time,
            ),
        }
    }

    /// Get query stas for given canister from query stats collector.
    ///
    /// This is used in testing.
    pub fn query_stats_for_testing(&self, canister_id: &CanisterId) -> Option<QueryStats> {
        self.local_query_execution_stats
            .current_query_stats
            .lock()
            .unwrap()
            .get(canister_id)
            .cloned()
    }

    /// Set current epoch in query stats collector
    ///
    /// This is used in testing.
    pub fn query_stats_set_epoch_for_testing(&mut self, epoch: QueryStatsEpoch) {
        self.local_query_execution_stats.set_epoch(epoch);
    }

    /// Handle a query of type `Query`.
    pub fn query(
        &self,
        query: Query,
        state: Labeled<Arc<ReplicatedState>>,
        data_certificate_with_delegation_metadata: Option<DataCertificateWithDelegationMetadata>,
        enable_query_stats_tracking: bool,
    ) -> Result<WasmResult, UserError> {
        let measurement_scope = MeasurementScope::root(&self.metrics.query);

        // Update the query receiver if the query is for the management canister.
        if query.receiver == CanisterId::ic_00() {
            match QueryMethod::from_str(&query.method_name) {
                Ok(QueryMethod::FetchCanisterLogs) => {
                    let since = Instant::now(); // Start logging execution time.
                    let response = fetch_canister_logs(
                        query.source(),
                        state.get_ref(),
                        FetchCanisterLogsRequest::decode(&query.method_payload)?,
                        self.config.log_memory_store_feature,
                    )?;
                    let result = Ok(WasmResult::Reply(Encode!(&response).unwrap()));
                    self.metrics.observe_subnet_query_message(
                        QueryMethod::FetchCanisterLogs,
                        since.elapsed().as_secs_f64(),
                        &result,
                    );
                    return result;
                }
                Ok(QueryMethod::CanisterStatus) => {
                    let args = CanisterIdRecord::decode(&query.method_payload)?;
                    let canister_id = args.get_canister_id();
                    let ready_for_migration = state.get_ref().ready_for_migration(&canister_id);
                    let canister =
                        state
                            .get_ref()
                            .canister_state(&canister_id)
                            .ok_or_else(|| {
                                UserError::new(
                                    ErrorCode::CanisterNotFound,
                                    format!("Canister {canister_id} not found"),
                                )
                            })?;
                    let since = Instant::now(); // Start logging execution time.
                    let response = self.canister_manager.get_canister_status(
                        query.source(),
                        canister,
                        state
                            .get_ref()
                            .metadata
                            .network_topology
                            .get_subnet_size(&self.hypervisor.subnet_id())
                            .unwrap_or(DEFAULT_REFERENCE_SUBNET_SIZE),
                        state.get_ref().get_own_cost_schedule(),
                        ready_for_migration,
                    )?;
                    let result = Ok(WasmResult::Reply(Encode!(&response).unwrap()));
                    self.metrics.observe_subnet_query_message(
                        QueryMethod::CanisterStatus,
                        since.elapsed().as_secs_f64(),
                        &result,
                    );
                    return result;
                }
                Err(_) => {
                    return Err(UserError::new(
                        ErrorCode::CanisterMethodNotFound,
                        format!("Query method {} not found.", query.method_name),
                    ));
                }
            };
        }

        let query_stats_collector = if self.config.query_stats_aggregation == FlagStatus::Enabled
            && enable_query_stats_tracking
        {
            Some(&self.local_query_execution_stats)
        } else {
            None
        };

        // Check the query cache first (if the query caching is enabled).
        // If a valid cache entry found, the result will be immediately returned.
        // Otherwise, the key will be kept for the `push` below.
        let cache_entry_key = if self.config.query_caching == FlagStatus::Enabled {
            let certificate_delegation_metadata = data_certificate_with_delegation_metadata
                .as_ref()
                .and_then(|data_certificate_with_delegation_metadata| {
                    data_certificate_with_delegation_metadata.certificate_delegation_metadata
                });
            let key = query_cache::EntryKey::new(&query, certificate_delegation_metadata);
            let state = state.get_ref().as_ref();
            if let Some(result) =
                self.query_cache
                    .get_valid_result(&key, state, query_stats_collector)
            {
                return result;
            }
            Some(key)
        } else {
            None
        };

        // Letting the canister grow arbitrarily when executing the
        // query is fine as we do not persist state modifications.
        let subnet_available_memory = full_subnet_memory_capacity(&self.config);
        // Letting the canister use the full subnet memory reservation
        // is fine as we do not persist state modifications.
        let subnet_memory_reservation = self.config.subnet_memory_reservation;
        // We apply the (rather high) subnet soft limit for callbacks because the
        // instruction limit for the whole composite query tree imposes a much lower
        // implicit bound anyway.
        let subnet_available_callbacks = self.config.subnet_callback_soft_limit as i64;

        let data_certificate = data_certificate_with_delegation_metadata.map(
            |data_certificate_with_delegation_metadata| {
                data_certificate_with_delegation_metadata.data_certificate
            },
        );
        let mut context = query_context::QueryContext::new(
            &self.log,
            self.hypervisor.as_ref(),
            self.own_subnet_type,
            // For composite queries, the set of evaluated canisters is not known in advance,
            // so the whole state is needed to capture later the state of the call graph.
            // The clone should not be expensive, as the state is `Labeled<Arc<ReplicatedState>>`.
            state.clone(),
            data_certificate,
            subnet_available_memory,
            subnet_available_callbacks,
            subnet_memory_reservation,
            self.config.canister_guaranteed_callback_quota as u64,
            self.max_instructions_per_query,
            self.config.max_query_call_graph_depth,
            self.config.max_query_call_graph_instructions,
            self.config.max_query_call_walltime,
            self.config.instruction_overhead_per_query_call,
            self.config.composite_queries,
            query.receiver,
            &self.metrics.query_critical_error,
            query_stats_collector,
            Arc::clone(&self.cycles_account_manager),
        );

        let result = context.run(query, &self.metrics, &measurement_scope);
        context.accumulate_transient_errors_from_result(result.as_ref());
        context.observe_metrics(&self.metrics);

        // Add the query execution result to the query cache (if the query caching is enabled).
        // Query caching is disabled if the key is set to `None`.
        if let Some(key) = cache_entry_key {
            let state = state.get_ref().as_ref();
            let counters = context.system_api_call_counters();
            let stats = context.evaluated_canister_stats();
            let errors = context.transient_errors();
            self.query_cache
                .push(key, &result, state, counters, stats, errors);
        }
        result
    }
}

#[derive(Clone)]
struct HttpQueryHandlerMetrics {
    pub height_diff_during_query_scheduling: Histogram,
}

impl HttpQueryHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry, namespace: &str) -> Self {
        Self {
            height_diff_during_query_scheduling: metrics_registry.register(
                Histogram::with_opts(histogram_opts!(
                    "execution_query_height_diff_during_query_scheduling",
                    "The height difference between the latest certified height before query scheduling and state height used for execution",
                    vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 20.0, 50.0, 100.0],
                    labels! {"query_type".to_string() => namespace.to_string()}
                )).unwrap(),
            ),
        }
    }
}

#[derive(Clone)]
/// Struct that is responsible for handling queries sent by user.
pub(crate) struct HttpQueryHandler {
    internal: Arc<InternalHttpQueryHandler>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    query_scheduler: QueryScheduler,
    metrics: Arc<HttpQueryHandlerMetrics>,
    enable_query_stats_tracking: bool,
}

impl HttpQueryHandler {
    pub(crate) fn new_query_service(
        internal: Arc<InternalHttpQueryHandler>,
        query_scheduler: QueryScheduler,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        namespace: &str,
        enable_query_stats_tracking: bool,
    ) -> QueryExecutionService {
        BoxCloneService::new(Self {
            internal,
            state_reader,
            query_scheduler,
            metrics: Arc::new(HttpQueryHandlerMetrics::new(metrics_registry, namespace)),
            enable_query_stats_tracking,
        })
    }

    pub(crate) fn new_transform_service(
        internal: Arc<InternalHttpQueryHandler>,
        query_scheduler: QueryScheduler,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
        namespace: &str,
        enable_query_stats_tracking: bool,
    ) -> TransformExecutionService {
        BoxCloneService::new(Self {
            internal,
            state_reader,
            query_scheduler,
            metrics: Arc::new(HttpQueryHandlerMetrics::new(metrics_registry, namespace)),
            enable_query_stats_tracking,
        })
    }
}

impl Service<QueryExecutionInput> for HttpQueryHandler {
    type Response = QueryExecutionResponse;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        QueryExecutionInput {
            query,
            certificate_delegation_with_metadata,
        }: QueryExecutionInput,
    ) -> Self::Future {
        let internal = Arc::clone(&self.internal);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let canister_id = query.receiver;
        let latest_certified_height_pre_schedule = state_reader.latest_certified_height();
        let http_query_handler_metrics = Arc::clone(&self.metrics);
        let enable_query_stats_tracking = self.enable_query_stats_tracking;
        self.query_scheduler.push(canister_id, move || {
            let start = std::time::Instant::now();
            if !tx.is_closed() {
                // We managed to upgrade the weak pointer, so the query was not cancelled.
                // Canceling the query after this point will have no effect: the query will
                // be executed anyway. That is fine because the execution will take O(ms).

                // Retrieving the state must be done here in the query handler, and should be immediately used.
                // Otherwise, retrieving the state in the Query service in `http_endpoints` can lead to queries being queued up,
                // with a reference to older states which can cause out-of-memory crashes.

                let (certificate_delegation, certificate_delegation_metadata) =
                    match certificate_delegation_with_metadata {
                        Some((delegation, metadata)) => (Some(delegation), Some(metadata)),
                        None => (None, None),
                    };

                let result = match get_latest_certified_state_and_data_certificate(
                    state_reader,
                    certificate_delegation,
                    query.receiver,
                ) {
                    Some((state, cert)) => {
                        let time = state.get_ref().metadata.batch_time;

                        let certified_height_used_for_execution = state.height();
                        let height_diff = certified_height_used_for_execution
                            .get()
                            .saturating_sub(latest_certified_height_pre_schedule.get());
                        http_query_handler_metrics
                            .height_diff_during_query_scheduling
                            .observe(height_diff as f64);

                        let data_certificate_with_delegation_metadata =
                            DataCertificateWithDelegationMetadata {
                                data_certificate: cert,
                                certificate_delegation_metadata,
                            };

                        let response = internal.query(
                            query,
                            state,
                            Some(data_certificate_with_delegation_metadata),
                            enable_query_stats_tracking,
                        );

                        Ok((response, time))
                    }
                    None => Err(QueryExecutionError::CertifiedStateUnavailable),
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

impl Service<TransformExecutionInput> for HttpQueryHandler {
    type Response = QueryExecutionResponse;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, TransformExecutionInput { query }: TransformExecutionInput) -> Self::Future {
        let internal = Arc::clone(&self.internal);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let canister_id = query.receiver;
        let latest_certified_height_pre_schedule = state_reader.latest_certified_height();
        let http_query_handler_metrics = Arc::clone(&self.metrics);
        let enable_query_stats_tracking = self.enable_query_stats_tracking;
        self.query_scheduler.push(canister_id, move || {
            let start = std::time::Instant::now();
            if !tx.is_closed() {
                // We managed to upgrade the weak pointer, so the query was not cancelled.
                // Canceling the query after this point will have no effect: the query will
                // be executed anyway. That is fine because the execution will take O(ms).

                // Retrieving the state must be done here in the query handler, and should be immediately used.
                // Otherwise, retrieving the state in the Query service in `http_endpoints` can lead to queries being queued up,
                // with a reference to older states which can cause out-of-memory crashes.

                let result = match state_reader.get_latest_certified_state() {
                    Some(state) => {
                        let time = state.get_ref().metadata.batch_time;

                        let certified_height_used_for_execution = state.height();
                        let height_diff = certified_height_used_for_execution
                            .get()
                            .saturating_sub(latest_certified_height_pre_schedule.get());
                        http_query_handler_metrics
                            .height_diff_during_query_scheduling
                            .observe(height_diff as f64);

                        let response =
                            internal.query(query, state, None, enable_query_stats_tracking);

                        Ok((response, time))
                    }
                    None => Err(QueryExecutionError::CertifiedStateUnavailable),
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
