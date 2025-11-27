use std::{convert::TryFrom, rc::Rc, sync::Arc};

use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_config::{embedders::Config as EmbeddersConfig, subnet_config::SchedulerConfig};
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_embedders::wasmtime_embedder::system_api::{
    ApiType, DefaultOutOfInstructionsHandler, ExecutionParameters, InstructionLimits,
    SystemApiImpl, sandbox_safe_system_state::SandboxSafeSystemState,
};
use ic_interfaces::execution_environment::{
    ExecutionMode, MessageMemoryUsage, SubnetAvailableMemory,
};
use ic_logger::replica_logger::no_op_logger;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, Memory, NetworkTopology, NumWasmPages, SubnetTopology, SystemState,
};
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::ids::{
    call_context_test_id, canister_test_id, subnet_test_id, user_test_id,
};
use ic_types::{
    ComputeAllocation, Cycles, MemoryAllocation, NumInstructions, PrincipalId, Time,
    batch::CanisterCyclesCostSchedule,
    messages::{CallContextId, CallbackId, NO_DEADLINE, RejectContext},
    methods::SystemMethod,
    time::UNIX_EPOCH,
};
use maplit::btreemap;
use std::collections::BTreeMap;

pub const CANISTER_CURRENT_MEMORY_USAGE: NumBytes = NumBytes::new(0);
pub const CANISTER_CURRENT_MESSAGE_MEMORY_USAGE: MessageMemoryUsage = MessageMemoryUsage::ZERO;

const SUBNET_MEMORY_CAPACITY: i64 = i64::MAX / 2;

pub fn execution_parameters(execution_mode: ExecutionMode) -> ExecutionParameters {
    ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            NumInstructions::from(5_000_000_000),
            NumInstructions::from(5_000_000_000),
        ),
        wasm_memory_limit: None,
        memory_allocation: MemoryAllocation::default(),
        canister_guaranteed_callback_quota: 50,
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode,
        subnet_memory_saturation: ResourceSaturation::default(),
    }
}

fn make_network_topology(own_subnet_id: SubnetId, own_subnet_type: SubnetType) -> NetworkTopology {
    let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => own_subnet_id,
        }).unwrap());
    NetworkTopology {
        routing_table,
        subnets: btreemap! {
            own_subnet_id => SubnetTopology {
                subnet_type: own_subnet_type,
                ..SubnetTopology::default()
            }
        },
        ..NetworkTopology::default()
    }
}

// Not used in all test crates
#[allow(dead_code)]
pub fn default_network_topology() -> NetworkTopology {
    make_network_topology(subnet_test_id(1), SubnetType::Application)
}

pub struct ApiTypeBuilder;

// Note some methods of the builder might be unused in different test crates
#[allow(dead_code)]
#[allow(clippy::new_without_default)]
impl ApiTypeBuilder {
    pub fn build_update_api() -> ApiType {
        ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            user_test_id(1).get(),
            CallContextId::from(1),
        )
    }

    pub fn build_system_task_api() -> ApiType {
        ApiType::system_task(
            SystemMethod::CanisterHeartbeat,
            UNIX_EPOCH,
            CallContextId::from(1),
        )
    }

    pub fn build_replicated_query_api() -> ApiType {
        ApiType::replicated_query(
            UNIX_EPOCH,
            vec![],
            user_test_id(1).get(),
            CallContextId::new(1),
        )
    }

    pub fn build_non_replicated_query_api() -> ApiType {
        ApiType::non_replicated_query(
            UNIX_EPOCH,
            user_test_id(1).get(),
            subnet_test_id(1),
            vec![],
            Some(vec![1]),
        )
    }

    pub fn build_composite_query_api() -> ApiType {
        ApiType::composite_query(
            UNIX_EPOCH,
            user_test_id(1).get(),
            subnet_test_id(1),
            vec![],
            Some(vec![1]),
            CallContextId::from(1),
        )
    }

    pub fn build_reply_api(incoming_cycles: Cycles) -> ApiType {
        ApiType::reply_callback(
            UNIX_EPOCH,
            PrincipalId::new_anonymous(),
            vec![],
            incoming_cycles,
            CallContextId::new(1),
            false,
            0.into(),
        )
    }

    pub fn build_composite_reply_api(incoming_cycles: Cycles) -> ApiType {
        ApiType::composite_reply_callback(
            UNIX_EPOCH,
            PrincipalId::new_anonymous(),
            vec![],
            incoming_cycles,
            CallContextId::new(1),
            false,
            0.into(),
        )
    }

    pub fn build_reject_api(reject_context: RejectContext) -> ApiType {
        ApiType::reject_callback(
            UNIX_EPOCH,
            PrincipalId::new_anonymous(),
            reject_context,
            Cycles::zero(),
            call_context_test_id(1),
            false,
            0.into(),
        )
    }

    pub fn build_composite_reject_api(reject_context: RejectContext) -> ApiType {
        ApiType::composite_reject_callback(
            UNIX_EPOCH,
            PrincipalId::new_anonymous(),
            reject_context,
            Cycles::zero(),
            call_context_test_id(1),
            false,
            0.into(),
        )
    }

    pub fn build_inspect_message_api() -> ApiType {
        ApiType::inspect_message(
            PrincipalId::new_anonymous(),
            "test".to_string(),
            vec![],
            UNIX_EPOCH,
        )
    }

    pub fn build_start_api() -> ApiType {
        ApiType::start(UNIX_EPOCH)
    }

    pub fn build_init_api() -> ApiType {
        ApiType::init(UNIX_EPOCH, vec![], user_test_id(1).get())
    }

    pub fn build_pre_upgrade_api() -> ApiType {
        ApiType::pre_upgrade(UNIX_EPOCH, user_test_id(1).get())
    }
}

pub fn get_system_api(
    api_type: ApiType,
    system_state: &SystemState,
    cycles_account_manager: CyclesAccountManager,
) -> SystemApiImpl {
    let mut execution_parameters = execution_parameters(api_type.execution_mode());
    execution_parameters.subnet_type = cycles_account_manager.subnet_type();
    let sandbox_safe_system_state = SandboxSafeSystemState::new_for_testing(
        system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        execution_parameters.compute_allocation,
        execution_parameters.canister_guaranteed_callback_quota,
        Default::default(),
        api_type.caller(),
        api_type.call_context_id(),
        CanisterCyclesCostSchedule::Normal,
    );
    SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        CANISTER_CURRENT_MESSAGE_MEMORY_USAGE,
        execution_parameters,
        SubnetAvailableMemory::new_for_testing(
            SUBNET_MEMORY_CAPACITY,
            SUBNET_MEMORY_CAPACITY,
            SUBNET_MEMORY_CAPACITY,
        ),
        &EmbeddersConfig::default(),
        Memory::new_for_testing(),
        NumWasmPages::from(0),
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    )
}

pub fn get_system_state() -> SystemState {
    let mut env_vars = BTreeMap::new();
    env_vars.insert("TEST_VAR_1".to_string(), "Hello World".to_string());
    env_vars.insert("PATH".to_string(), "/usr/local/bin:/usr/bin".to_string());
    let mut system_state = SystemStateBuilder::new()
        .environment_variables(env_vars)
        .build();
    system_state
        .new_call_context(
            CallOrigin::CanisterUpdate(
                canister_test_id(33),
                CallbackId::from(5),
                NO_DEADLINE,
                String::from(""),
            ),
            Cycles::new(50),
            Time::from_nanos_since_unix_epoch(0),
            Default::default(),
        )
        .unwrap();
    system_state
}

pub fn get_cmc_system_state() -> SystemState {
    let mut system_state = get_system_state();
    system_state.canister_id = CYCLES_MINTING_CANISTER_ID;
    system_state
}
