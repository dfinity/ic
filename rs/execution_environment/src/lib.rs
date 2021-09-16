mod canister_manager;
mod canister_settings;
mod execution_environment;
mod execution_environment_metrics;
mod history;
mod hypervisor;
mod ingress_message_filter;
mod metrics;
mod query_handler;
mod scheduler;
mod types;
mod util;

pub use execution_environment::{ExecutionEnvironment, ExecutionEnvironmentImpl};
pub use history::{IngressHistoryReaderImpl, IngressHistoryWriterImpl};
pub use hypervisor::{execute, Hypervisor, HypervisorMetrics};
use ic_config::{execution_environment::Config, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::{
    execution_environment::{
        IngressHistoryReader, IngressHistoryWriter, IngressMessageFilter, QueryHandler, Scheduler,
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
use ingress_message_filter::IngressMessageFilterImpl;
use query_handler::HttpQueryHandlerImpl;
use scheduler::SchedulerImpl;
use std::sync::Arc;

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
    Box<dyn IngressMessageFilter<State = ReplicatedState>>,
    Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    Arc<dyn QueryHandler<State = ReplicatedState>>,
    Box<dyn Scheduler<State = ReplicatedState>>,
    Box<dyn IngressHistoryReader>,
) {
    let hypervisor = Arc::new(Hypervisor::new(
        config.clone(),
        1,
        &metrics_registry,
        own_subnet_id,
        own_subnet_type,
        logger.clone(),
        Arc::clone(&cycles_account_manager),
    ));

    let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
        logger.clone(),
        &metrics_registry,
    ));
    let ingress_history_reader = Box::new(IngressHistoryReaderImpl::new(Arc::clone(&state_reader)));

    let exec_env = Arc::new(ExecutionEnvironmentImpl::new(
        logger.clone(),
        Arc::clone(&hypervisor),
        Arc::clone(&ingress_history_writer) as Arc<_>,
        &metrics_registry,
        own_subnet_id,
        scheduler_config.scheduler_cores,
        config.clone(),
        Arc::clone(&cycles_account_manager),
    ));
    let http_query_handler = Arc::new(HttpQueryHandlerImpl::new(
        logger.clone(),
        hypervisor,
        own_subnet_id,
        own_subnet_type,
        config,
        &metrics_registry,
        Arc::clone(&state_reader),
    ));

    let ingress_message_filter = Box::new(IngressMessageFilterImpl::new(Arc::clone(&exec_env)));

    let scheduler = Box::new(SchedulerImpl::new(
        scheduler_config,
        own_subnet_id,
        Arc::clone(&ingress_history_writer) as Arc<_>,
        Arc::clone(&exec_env) as Arc<_>,
        Arc::clone(&&cycles_account_manager),
        &metrics_registry,
        logger,
    ));

    (
        ingress_message_filter,
        ingress_history_writer,
        http_query_handler,
        scheduler,
        ingress_history_reader,
    )
}
