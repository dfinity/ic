mod canister_manager;
mod canister_settings;
mod execution_environment;
mod execution_environment_metrics;
mod history;
mod hypervisor;
mod query_handler;
mod types;
// TODO(EXC-185): Make this private once scheduler is moved into this crate.
#[doc(hidden)]
pub mod util;

pub use execution_environment::ExecutionEnvironmentImpl;
pub use history::{IngressHistoryReaderImpl, IngressHistoryWriterImpl};
pub use hypervisor::{execute, Hypervisor, HypervisorMetrics};
use ic_config::execution_environment::Config;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{ExecutionEnvironment, IngressHistoryWriter};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_types::{messages::CallContextId, SubnetId};
pub use query_handler::HttpQueryHandlerImpl;
use std::sync::Arc;
// TODO(EXC-185): Remove this once scheduler is moved into this crate.
pub use canister_manager::uninstall_canister;

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
    cores: usize,
    config: Config,
    cycles_account_manager: Arc<CyclesAccountManager>,
) -> (
    Arc<dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>>,
    Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    Arc<HttpQueryHandlerImpl>,
) {
    let hypervisor = Arc::new(Hypervisor::new(
        config.clone(),
        cores,
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

    let exec_env = Arc::new(ExecutionEnvironmentImpl::new(
        logger.clone(),
        Arc::clone(&hypervisor),
        Arc::clone(&ingress_history_writer) as Arc<_>,
        &metrics_registry,
        own_subnet_id,
        own_subnet_type,
        cores,
        config.clone(),
        Arc::clone(&cycles_account_manager),
    ));
    let http_query_handler = Arc::new(HttpQueryHandlerImpl::new(
        logger,
        hypervisor,
        own_subnet_id,
        own_subnet_type,
        config.subnet_memory_capacity,
    ));

    (exec_env, ingress_history_writer, http_query_handler)
}
