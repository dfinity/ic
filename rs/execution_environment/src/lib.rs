mod bitcoin;
mod canister_logs;
mod canister_manager;
mod canister_settings;
pub mod execution;
mod execution_environment;
mod execution_environment_metrics;
mod history;
mod hypervisor;
mod ic00_permissions;
mod ingress_filter;
mod metrics;
mod query_handler;
mod scheduler;
mod types;
pub mod util;

use crate::ingress_filter::IngressFilterServiceImpl;
use canister_manager::{CanisterManager, types::CanisterMgrConfig};
pub use execution_environment::{
    CompilationCostHandling, ExecuteMessageResult, ExecutionEnvironment, ExecutionResponse,
    RoundInstructions, RoundLimits, as_num_instructions, as_round_instructions, execute_canister,
};
pub use history::{IngressHistoryReaderImpl, IngressHistoryWriterImpl};
pub use hypervisor::{Hypervisor, HypervisorMetrics};
use ic_base_types::PrincipalId;
use ic_config::{execution_environment::Config, subnet_config::SubnetConfig};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasm_executor::WasmExecutor;
use ic_interfaces::execution_environment::{
    IngressFilterService, IngressHistoryReader, QueryExecutionService, Scheduler,
    TransformExecutionService,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_query_stats::QueryStatsPayloadBuilderParams;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::PageAllocatorFileDescriptor;
use ic_replicated_state::{CallOrigin, NetworkTopology, ReplicatedState};
use ic_types::{
    Height, SubnetId,
    messages::{CallContextId, MessageId},
};
pub use metrics::IngressFilterMetrics;
pub use query_handler::{DataCertificateWithDelegationMetadata, InternalHttpQueryHandler};
use query_handler::{HttpQueryHandler, QueryScheduler};
pub use scheduler::RoundSchedule;
use scheduler::SchedulerImpl;
use std::{path::Path, sync::Arc};
use tokio::sync::mpsc::Sender;

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
        network_topology: Arc<NetworkTopology>,
        query_kind: NonReplicatedQueryKind,
    },
}

/// This enum indicates whether execution of a non-replicated query
/// should keep track of the state or not.
#[doc(hidden)]
#[derive(Clone, Eq, PartialEq)]
pub enum NonReplicatedQueryKind {
    Stateful { call_origin: CallOrigin },
    Pure { caller: PrincipalId },
}

// This struct holds public facing components that are created by Execution.
pub struct ExecutionServices {
    pub ingress_filter: IngressFilterService,
    pub ingress_history_writer: Arc<IngressHistoryWriterImpl>,
    pub ingress_history_reader: Box<dyn IngressHistoryReader>,
    pub query_execution_service: QueryExecutionService,
    pub transform_execution_service: TransformExecutionService,
    pub scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
    pub query_stats_payload_builder: QueryStatsPayloadBuilderParams,
    pub cycles_account_manager: Arc<CyclesAccountManager>,
}

impl ExecutionServices {
    /// Constructs the public facing components that the
    /// `ExecutionEnvironment` crate exports.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn setup_execution(
        logger: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: Config,
        subnet_config: SubnetConfig,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        completed_execution_messages_tx: Sender<(MessageId, Height)>,
        temp_dir: &Path,
    ) -> ExecutionServices {
        let (
            ingress_filter,
            ingress_history_writer,
            ingress_history_reader,
            sync_query_handler,
            query_scheduler,
            query_stats_payload_builder,
            cycles_account_manager,
            execution_environment,
        ) = setup_execution_helper(
            logger.clone(),
            metrics_registry,
            own_subnet_id,
            own_subnet_type,
            config.clone(),
            subnet_config.clone(),
            Arc::clone(&state_reader),
            Arc::clone(&fd_factory),
            completed_execution_messages_tx,
            temp_dir,
            None,
            RoundSchedule::compute_capacity_percent(subnet_config.scheduler_config.scheduler_cores),
        );

        let sync_query_handler = Arc::new(sync_query_handler);

        // Creating the async services require that a tokio runtime context is available.

        let query_execution_service = HttpQueryHandler::new_query_service(
            Arc::clone(&sync_query_handler) as Arc<_>,
            query_scheduler.clone(),
            Arc::clone(&state_reader),
            metrics_registry,
            "regular",
            true,
        );
        let transform_execution_service = HttpQueryHandler::new_transform_service(
            Arc::clone(&sync_query_handler) as Arc<_>,
            query_scheduler.clone(),
            Arc::clone(&state_reader),
            metrics_registry,
            "https_outcall",
            false,
        );

        let scheduler = Box::new(SchedulerImpl::new(
            subnet_config.scheduler_config,
            config.embedders_config,
            own_subnet_id,
            Arc::clone(&ingress_history_writer) as Arc<_>,
            Arc::clone(&execution_environment) as Arc<_>,
            Arc::clone(&cycles_account_manager),
            metrics_registry,
            logger,
            config.rate_limiting_of_heap_delta,
            config.rate_limiting_of_instructions,
            Arc::clone(&fd_factory),
        ));

        Self {
            ingress_filter,
            ingress_history_writer,
            ingress_history_reader,
            query_execution_service,
            transform_execution_service,
            scheduler,
            query_stats_payload_builder,
            cycles_account_manager,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        IngressFilterService,
        Arc<IngressHistoryWriterImpl>,
        Box<dyn IngressHistoryReader>,
        QueryExecutionService,
        Box<dyn Scheduler<State = ReplicatedState>>,
        Arc<CyclesAccountManager>,
    ) {
        (
            self.ingress_filter,
            self.ingress_history_writer,
            self.ingress_history_reader,
            self.query_execution_service,
            self.scheduler,
            self.cycles_account_manager,
        )
    }
}

/// Wraps the execution services for testing purposes, like
/// `ExecutionTest`, `SchedulerTest`, execution benchmarks
/// and state machine tests.
#[doc(hidden)]
pub struct ExecutionServicesForTesting {
    pub ingress_filter: IngressFilterService,
    pub ingress_history_writer: Arc<IngressHistoryWriterImpl>,
    pub ingress_history_reader: Box<dyn IngressHistoryReader>,
    pub query_execution_service: InternalHttpQueryHandler,
    pub query_stats_payload_builder: QueryStatsPayloadBuilderParams,
    pub cycles_account_manager: Arc<CyclesAccountManager>,
    pub execution_environment: Arc<ExecutionEnvironment>,
}

impl ExecutionServicesForTesting {
    /// Constructs the public facing components that the
    /// `ExecutionEnvironment` crate exports.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn setup_execution(
        logger: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        config: Config,
        subnet_config: SubnetConfig,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        completed_execution_messages_tx: Sender<(MessageId, Height)>,
        temp_dir: &Path,
        wasm_executor: Option<Arc<dyn WasmExecutor>>,
    ) -> ExecutionServicesForTesting {
        let (
            ingress_filter,
            ingress_history_writer,
            ingress_history_reader,
            sync_query_handler,
            _query_scheduler,
            query_stats_payload_builder,
            cycles_account_manager,
            execution_environment,
        ) = setup_execution_helper(
            logger,
            metrics_registry,
            own_subnet_id,
            own_subnet_type,
            config,
            subnet_config,
            state_reader,
            fd_factory,
            completed_execution_messages_tx,
            temp_dir,
            wasm_executor,
            // Compute capacity for 2-core scheduler is 100%
            // TODO(RUN-319): the capacity should be defined based on actual `scheduler_cores`
            100,
        );

        Self {
            ingress_filter,
            ingress_history_writer,
            ingress_history_reader,
            query_execution_service: sync_query_handler,
            query_stats_payload_builder,
            cycles_account_manager,
            execution_environment,
        }
    }
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn setup_execution_helper(
    logger: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    config: Config,
    subnet_config: SubnetConfig,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    completed_execution_messages_tx: Sender<(MessageId, Height)>,
    temp_dir: &Path,
    wasm_executor: Option<Arc<dyn WasmExecutor>>,
    compute_capacity: usize,
) -> (
    IngressFilterService,
    Arc<IngressHistoryWriterImpl>,
    Box<dyn IngressHistoryReader>,
    InternalHttpQueryHandler,
    QueryScheduler,
    QueryStatsPayloadBuilderParams,
    Arc<CyclesAccountManager>,
    Arc<ExecutionEnvironment>,
) {
    let scheduler_config = subnet_config.scheduler_config;

    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        scheduler_config.max_instructions_per_message,
        own_subnet_type,
        own_subnet_id,
        subnet_config.cycles_account_manager_config,
    ));

    let hypervisor = Arc::new(match wasm_executor {
        None => Hypervisor::new(
            config.clone(),
            metrics_registry,
            own_subnet_id,
            logger.clone(),
            Arc::clone(&cycles_account_manager),
            scheduler_config.dirty_page_overhead,
            Arc::clone(&fd_factory),
            Arc::clone(&state_reader),
            temp_dir,
        ),
        Some(wasm_executor) => Hypervisor::new_for_testing(
            metrics_registry,
            own_subnet_id,
            logger.clone(),
            Arc::clone(&cycles_account_manager),
            wasm_executor,
            config.embedders_config.cost_to_compile_wasm_instruction,
            config.embedders_config.dirty_page_overhead,
            config.canister_guaranteed_callback_quota,
        ),
    });

    let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
        config.clone(),
        logger.clone(),
        metrics_registry,
        completed_execution_messages_tx,
        Arc::clone(&state_reader),
    ));
    let ingress_history_reader = Box::new(IngressHistoryReaderImpl::new(Arc::clone(&state_reader)));

    let (query_stats_collector, query_stats_payload_builder) =
        ic_query_stats::init_query_stats(logger.clone(), &config, metrics_registry);

    let canister_manager_config: CanisterMgrConfig = CanisterMgrConfig::new(
        config.subnet_memory_capacity,
        config.default_provisional_cycles_balance,
        config.default_freeze_threshold,
        own_subnet_id,
        own_subnet_type,
        config.max_controllers,
        compute_capacity,
        config.rate_limiting_of_instructions,
        config.allocatable_compute_capacity_in_percent,
        config.rate_limiting_of_heap_delta,
        scheduler_config.heap_delta_rate_limit,
        scheduler_config.upload_wasm_chunk_instructions,
        config.embedders_config.wasm_max_size,
        scheduler_config.canister_snapshot_baseline_instructions,
        scheduler_config.canister_snapshot_data_baseline_instructions,
        config.default_wasm_memory_limit,
        config.max_number_of_snapshots_per_canister,
        config.max_environment_variables,
        config.max_environment_variable_name_length,
        config.max_environment_variable_value_length,
    );
    let canister_manager = Arc::new(CanisterManager::new(
        Arc::clone(&hypervisor),
        logger.clone(),
        canister_manager_config,
        Arc::clone(&cycles_account_manager),
        Arc::clone(&ingress_history_writer) as Arc<_>,
        Arc::clone(&fd_factory),
        config.environment_variables,
    ));

    let exec_env = Arc::new(ExecutionEnvironment::new(
        logger.clone(),
        Arc::clone(&hypervisor),
        Arc::clone(&canister_manager),
        Arc::clone(&ingress_history_writer) as Arc<_>,
        metrics_registry,
        own_subnet_id,
        own_subnet_type,
        config.clone(),
        Arc::clone(&cycles_account_manager),
        scheduler_config.scheduler_cores,
    ));
    let sync_query_handler = InternalHttpQueryHandler::new(
        logger.clone(),
        hypervisor,
        canister_manager,
        own_subnet_type,
        config.clone(),
        metrics_registry,
        scheduler_config.max_instructions_per_query_message,
        Arc::clone(&cycles_account_manager),
        query_stats_collector,
    );

    let query_scheduler = QueryScheduler::new(
        config.query_execution_threads_total,
        config.embedders_config.query_execution_threads_per_canister,
        config.query_scheduling_time_slice_per_canister,
        metrics_registry,
    );

    let ingress_filter_metrics: Arc<_> = IngressFilterMetrics::new(metrics_registry).into();

    let ingress_filter = IngressFilterServiceImpl::new_service(
        query_scheduler.clone(),
        Arc::clone(&state_reader),
        Arc::clone(&exec_env),
        ingress_filter_metrics.clone(),
    );

    (
        ingress_filter,
        ingress_history_writer,
        ingress_history_reader,
        sync_query_handler,
        query_scheduler,
        query_stats_payload_builder,
        cycles_account_manager,
        exec_env,
    )
}
