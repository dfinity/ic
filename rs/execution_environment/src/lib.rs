mod canister_manager;
mod canister_settings;
mod common;
mod execution_environment;
mod execution_environment_metrics;
mod history;
mod hypervisor;
mod ingress_filter;
mod metrics;
mod query_handler;
mod scheduler;
mod types;
mod util;

pub use execution_environment::{ExecutionEnvironment, ExecutionEnvironmentImpl};
pub use history::{IngressHistoryReaderImpl, IngressHistoryWriterImpl};
pub use hypervisor::{Hypervisor, HypervisorMetrics};
use ic_config::{execution_environment::Config, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::{
    execution_environment::{
        IngressFilterService, IngressHistoryReader, IngressHistoryWriter, QueryExecutionService,
        QueryHandler, Scheduler,
    },
    state_manager::StateReader,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_system_api::NonReplicatedQueryKind;
use ic_types::{messages::CallContextId, SubnetId};
use ingress_filter::IngressFilter;
use query_handler::{HttpQueryHandler, InternalHttpQueryHandler};
use scheduler::SchedulerImpl;
use std::sync::{Arc, Mutex};

const QUERY_EXECUTION_MAX_BUFFERED_QUERIES: usize = 2000;

/// When executing a wasm method of query type, this enum indicates if we are
/// running in an replicated or non-replicated context. This information is
/// needed for various purposes and in particular to support the CoW memory
/// work.
#[doc(hidden)]
pub enum QueryExecutionType {
    /// The execution is happening in a replicated context (i.e. consensus was
    /// used to agree that this method should be executed). This should
    /// generally indicate that the message being handled in an Ingress or an
    /// inter-canister Request.
    Replicated,

    /// The execution is happening in a non-replicated context (i.e. consensus
    /// was not used to agree that this method should be executed). This should
    /// generally indicate that the message being handled is a Query message.
    NonReplicated {
        call_context_id: CallContextId,
        routing_table: Arc<RoutingTable>,
        query_kind: NonReplicatedQueryKind,
    },
}

/// Helper function to constructs the public facing components that the
/// `ExecutionEnvironment` crate exports.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn setup_execution(
    logger: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    scheduler_config: SchedulerConfig,
    config: Config,
    cycles_account_manager: Arc<CyclesAccountManager>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
) -> (
    IngressFilterService,
    Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    Box<dyn IngressHistoryReader>,
    Arc<dyn QueryHandler<State = ReplicatedState>>,
    QueryExecutionService,
    Box<dyn Scheduler<State = ReplicatedState>>,
) {
    let hypervisor = Arc::new(Hypervisor::new(
        config.clone(),
        metrics_registry,
        own_subnet_id,
        own_subnet_type,
        logger.clone(),
        Arc::clone(&cycles_account_manager),
    ));

    let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
        logger.clone(),
        metrics_registry,
    ));
    let ingress_history_reader = Box::new(IngressHistoryReaderImpl::new(Arc::clone(&state_reader)));

    let exec_env = Arc::new(ExecutionEnvironmentImpl::new(
        logger.clone(),
        Arc::clone(&hypervisor),
        Arc::clone(&ingress_history_writer) as Arc<_>,
        metrics_registry,
        own_subnet_id,
        own_subnet_type,
        scheduler_config.scheduler_cores,
        config.clone(),
        Arc::clone(&cycles_account_manager),
    ));
    let sync_query_handler = Arc::new(InternalHttpQueryHandler::new(
        logger.clone(),
        hypervisor,
        own_subnet_id,
        own_subnet_type,
        config.clone(),
        metrics_registry,
        scheduler_config.max_instructions_per_message,
    ));
    let threadpool = threadpool::Builder::new()
        .num_threads(config.query_execution_threads)
        .thread_name("query_execution".into())
        .thread_stack_size(8_192_000)
        .build();

    let threadpool = Arc::new(Mutex::new(threadpool));

    let async_query_handler = HttpQueryHandler::new_service(
        QUERY_EXECUTION_MAX_BUFFERED_QUERIES,
        config.query_execution_threads,
        Arc::clone(&sync_query_handler) as Arc<_>,
        Arc::clone(&threadpool),
        Arc::clone(&state_reader),
    );

    let ingress_filter = IngressFilter::new_service(
        QUERY_EXECUTION_MAX_BUFFERED_QUERIES,
        config.query_execution_threads,
        threadpool,
        Arc::clone(&state_reader),
        Arc::clone(&exec_env),
    );

    let scheduler = Box::new(SchedulerImpl::new(
        scheduler_config,
        own_subnet_id,
        Arc::clone(&ingress_history_writer) as Arc<_>,
        Arc::clone(&exec_env) as Arc<_>,
        Arc::clone(&cycles_account_manager),
        metrics_registry,
        logger,
    ));

    (
        ingress_filter,
        ingress_history_writer,
        ingress_history_reader,
        sync_query_handler,
        async_query_handler,
        scheduler,
    )
}
