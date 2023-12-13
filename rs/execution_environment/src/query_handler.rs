//! This module implements the `QueryHandler` trait which is used to execute
//! query methods via query calls.

mod query_cache;
mod query_call_graph;
mod query_context;
mod query_scheduler;
pub mod query_stats;
#[cfg(test)]
mod tests;

use crate::execution_environment::subnet_memory_capacity;
use crate::{
    hypervisor::Hypervisor,
    metrics::{MeasurementScope, QueryHandlerMetrics},
};
use ic_btc_interface::NetworkInRequest as BitcoinNetwork;
use ic_config::execution_environment::Config;
use ic_config::flag_status::FlagStatus;
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, LabeledTree::SubTree};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    QueryExecutionError, QueryExecutionResponse, QueryExecutionService, QueryHandler,
};
use ic_interfaces_state_manager::{Labeled, StateReader};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::batch::QueryStats;
use ic_types::QueryStatsEpoch;
use ic_types::{
    ingress::WasmResult,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpQueryResponse, HttpQueryResponseReply,
        UserQuery,
    },
    CanisterId, NumInstructions,
};
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
use self::query_stats::QueryStatsCollector;
use ic_ic00_types::{BitcoinGetBalanceArgs, BitcoinGetUtxosArgs, Payload, QueryMethod};
use ic_replicated_state::NetworkTopology;

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
/// Struct that is responsible for handling queries sent by user.
pub(crate) struct HttpQueryHandler {
    internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    query_scheduler: QueryScheduler,
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
        let query_cache_max_expiry_time = config.query_cache_max_expiry_time;
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
                query_cache_max_expiry_time,
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
}

fn route_bitcoin_message(
    network: BitcoinNetwork,
    network_topology: &NetworkTopology,
) -> Result<CanisterId, UserError> {
    let canister_id = match network {
        // Route to the bitcoin canister if it exists, otherwise return the error.
        BitcoinNetwork::Testnet
        | BitcoinNetwork::testnet
        | BitcoinNetwork::Regtest
        | BitcoinNetwork::regtest => {
            network_topology
                .bitcoin_testnet_canister_id
                .ok_or(UserError::new(
                    ErrorCode::CanisterNotHostedBySubnet,
                    "Bitcoin testnet canister is not installed.".to_string(),
                ))?
        }
        BitcoinNetwork::Mainnet | BitcoinNetwork::mainnet => network_topology
            .bitcoin_mainnet_canister_id
            .ok_or(UserError::new(
                ErrorCode::CanisterNotHostedBySubnet,
                "Bitcoin mainnet canister is not installed.".to_string(),
            ))?,
    };
    Ok(canister_id)
}

impl QueryHandler for InternalHttpQueryHandler {
    type State = ReplicatedState;

    fn query(
        &self,
        mut query: UserQuery,
        state: Labeled<Arc<ReplicatedState>>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let measurement_scope = MeasurementScope::root(&self.metrics.query);

        // Update the query receiver if the query is for the management canister.
        if query.receiver == CanisterId::ic_00() {
            let network = match QueryMethod::from_str(query.method_name.as_str()) {
                Ok(QueryMethod::BitcoinGetUtxosQuery) => {
                    let args = BitcoinGetUtxosArgs::decode(&query.method_payload)?;
                    args.network
                }
                Ok(QueryMethod::BitcoinGetBalanceQuery) => {
                    let args = BitcoinGetBalanceArgs::decode(&query.method_payload)?;
                    args.network
                }
                Err(_) => {
                    return Err(UserError::new(
                        ErrorCode::CanisterMethodNotFound,
                        format!("Query method {} not found.", query.method_name),
                    ))
                }
            };

            query.receiver =
                route_bitcoin_message(network, &state.get_ref().metadata.network_topology)?;
        }

        // Check the query cache first (if the query caching is enabled).
        // If a valid cache entry found, the result will be immediately returned.
        // Otherwise, the key and the env will be kept for the `push` below.
        let (cache_entry_key, cache_entry_env) = if self.config.query_caching == FlagStatus::Enabled
        {
            let key = query_cache::EntryKey::from(&query);
            let env = query_cache::EntryEnv::try_from((&key, state.get_ref().as_ref()))?;

            if let Some(result) = self.query_cache.get_valid_result(&key, &env) {
                return result;
            }
            (Some(key), Some(env))
        } else {
            (None, None)
        };

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
            self.config.max_query_call_graph_depth,
            self.config.max_query_call_graph_instructions,
            self.config.max_query_call_walltime,
            self.config.instruction_overhead_per_query_call,
            self.config.composite_queries,
            query.receiver,
            &self.metrics.query_critical_error,
            if self.config.query_stats_aggregation == FlagStatus::Enabled {
                Some(&self.local_query_execution_stats)
            } else {
                None
            },
        );

        let result = context.run(
            query,
            &self.metrics,
            Arc::clone(&self.cycles_account_manager),
            &measurement_scope,
        );
        context.observe_system_api_calls(&self.metrics.query_system_api_calls);

        // Add the query execution result to the query cache (if the query caching is enabled).
        if self.config.query_caching == FlagStatus::Enabled {
            if let (Some(key), Some(env)) = (cache_entry_key, cache_entry_env) {
                let call_counters = context.system_api_call_counters();
                self.query_cache.push(key, env, &result, call_counters);
            }
        }
        result
    }
}

impl HttpQueryHandler {
    pub(crate) fn new_service(
        internal: Arc<dyn QueryHandler<State = ReplicatedState>>,
        query_scheduler: QueryScheduler,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> QueryExecutionService {
        BoxCloneService::new(Self {
            internal,
            state_reader,
            query_scheduler,
        })
    }
}

impl QueryHandler for HttpQueryHandler {
    type State = ReplicatedState;

    fn query(
        &self,
        query: UserQuery,
        state: Labeled<Arc<Self::State>>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.internal.query(query, state, data_certificate)
    }
}

impl Service<(UserQuery, Option<CertificateDelegation>)> for HttpQueryHandler {
    type Response = QueryExecutionResponse;
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
        let canister_id = query.receiver;
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
                        let result = internal.query(query, state, cert);

                        let response = match result {
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
