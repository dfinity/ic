//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_cache;
mod query_call_graph;
mod query_context;
mod query_scheduler;
#[cfg(test)]
mod tests;

use crate::execution_environment::subnet_memory_capacity;
use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use candid::Encode;
use ic_config::execution_environment::Config;
use ic_config::flag_status::FlagStatus;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, LabeledTree::SubTree};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{
    QueryExecutionError, QueryExecutionResponse, QueryExecutionService,
};
use ic_interfaces_state_manager::{Labeled, StateReader};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_query_stats::QueryStatsCollector;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::batch::QueryStats;
use ic_types::QueryStatsEpoch;
use ic_types::{
    ingress::WasmResult,
    messages::{Blob, Certificate, CertificateDelegation, Query},
    CanisterId, NumInstructions, PrincipalId,
};
use prometheus::Histogram;
use serde::Serialize;
use std::convert::Infallible;
use std::str::FromStr;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::oneshot;
use tower::{util::BoxCloneService, Service};

pub(crate) use self::query_scheduler::{QueryScheduler, QuerySchedulerFlag};
use ic_management_canister_types::{
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2, Payload, QueryMethod,
};

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
    own_subnet_type: SubnetType,
    config: Config,
    metrics: QueryHandlerMetrics,
    max_instructions_per_query: NumInstructions,
    cycles_account_manager: Arc<CyclesAccountManager>,
    local_query_execution_stats: QueryStatsCollector,
    query_cache: query_cache::QueryCache,
}

#[derive(Clone)]
struct HttpQueryHandlerMetrics {
    pub height_diff_during_query_scheduling: Histogram,
}

impl HttpQueryHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            height_diff_during_query_scheduling: metrics_registry.histogram(
                "execution_query_height_diff_during_query_scheduling",
                "The height difference between the latest certified height before query scheduling and state height used for execution",
                vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 20.0, 50.0, 100.0],
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
        local_query_execution_stats: QueryStatsCollector,
    ) -> Self {
        let query_cache_capacity = config.query_cache_capacity;
        let query_max_expiry_time = config.query_cache_max_expiry_time;
        let query_data_certificate_expiry_time = config.query_cache_data_certificate_expiry_time;
        Self {
            log,
            hypervisor,
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
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let measurement_scope = MeasurementScope::root(&self.metrics.query);

        // Update the query receiver if the query is for the management canister.
        if query.receiver == CanisterId::ic_00() {
            match QueryMethod::from_str(&query.method_name) {
                Ok(QueryMethod::FetchCanisterLogs) => {
                    return fetch_canister_logs(
                        query.source(),
                        state.get_ref(),
                        FetchCanisterLogsRequest::decode(&query.method_payload)?,
                    );
                }
                Err(_) => {
                    return Err(UserError::new(
                        ErrorCode::CanisterMethodNotFound,
                        format!("Query method {} not found.", query.method_name),
                    ));
                }
            };
        }

        let query_stats_collector = if self.config.query_stats_aggregation == FlagStatus::Enabled {
            Some(&self.local_query_execution_stats)
        } else {
            None
        };

        // Check the query cache first (if the query caching is enabled).
        // If a valid cache entry found, the result will be immediately returned.
        // Otherwise, the key will be kept for the `push` below.
        let cache_entry_key = if self.config.query_caching == FlagStatus::Enabled {
            let key = query_cache::EntryKey::from(&query);
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
        let subnet_available_memory = subnet_memory_capacity(&self.config);
        let max_canister_memory_size = self.config.max_canister_memory_size;

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
            max_canister_memory_size,
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

// TODO(EXC-1678): remove after release.
/// Feature flag to enable/disable allowed viewers for canister log visibility.
const ALLOWED_VIEWERS_ENABLED: bool = false;

fn fetch_canister_logs(
    sender: PrincipalId,
    state: &ReplicatedState,
    args: FetchCanisterLogsRequest,
) -> Result<WasmResult, UserError> {
    let canister_id = args.get_canister_id();
    let canister = state.canister_state(&canister_id).ok_or_else(|| {
        UserError::new(
            ErrorCode::CanisterNotFound,
            format!("Canister {canister_id} not found"),
        )
    })?;

    let log_visibility = match canister.log_visibility() {
        // If the feature is disabled override `AllowedViewers` with default value.
        LogVisibilityV2::AllowedViewers(_) if !ALLOWED_VIEWERS_ENABLED => {
            &LogVisibilityV2::default()
        }
        other => other,
    };
    match log_visibility {
        LogVisibilityV2::Public => Ok(()),
        LogVisibilityV2::Controllers if canister.controllers().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(principals) if principals.get().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(_) if canister.controllers().contains(&sender) => Ok(()),
        LogVisibilityV2::AllowedViewers(_) | LogVisibilityV2::Controllers => Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "Caller {} is not allowed to query ic00 method {}",
                sender,
                QueryMethod::FetchCanisterLogs
            ),
        )),
    }?;

    let response = FetchCanisterLogsResponse {
        canister_log_records: canister
            .system_state
            .canister_log
            .records()
            .iter()
            .cloned()
            .collect(),
    };
    Ok(WasmResult::Reply(Encode!(&response).unwrap()))
}

impl HttpQueryHandler {
    pub(crate) fn new_service(
        internal: Arc<InternalHttpQueryHandler>,
        query_scheduler: QueryScheduler,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        metrics_registry: &MetricsRegistry,
    ) -> QueryExecutionService {
        BoxCloneService::new(Self {
            internal,
            state_reader,
            query_scheduler,
            metrics: Arc::new(HttpQueryHandlerMetrics::new(metrics_registry)),
        })
    }
}

impl Service<(Query, Option<CertificateDelegation>)> for HttpQueryHandler {
    type Response = QueryExecutionResponse;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        (query, certificate_delegation): (Query, Option<CertificateDelegation>),
    ) -> Self::Future {
        let internal = Arc::clone(&self.internal);
        let state_reader = Arc::clone(&self.state_reader);
        let (tx, rx) = oneshot::channel();
        let canister_id = query.receiver;
        let latest_certified_height_pre_schedule = state_reader.latest_certified_height();
        let http_query_handler_metrics = Arc::clone(&self.metrics);
        self.query_scheduler.push(canister_id, move || {
            let start = std::time::Instant::now();
            if !tx.is_closed() {
                // We managed to upgrade the weak pointer, so the query was not cancelled.
                // Canceling the query after this point will have no effect: the query will
                // be executed anyway. That is fine because the execution will take O(ms).

                // Retrieving the state must be done here in the query handler, and should be immediately used.
                // Otherwise, retrieving the state in the Query service in `http_endpoints` can lead to queries being queued up,
                // with a reference to older states which can cause out-of-memory crashes.
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

                        let response = internal.query(query, state, cert);

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
