use std::{collections::BTreeMap, sync::Arc};

use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{ExecutionParameters, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, SystemState};
use ic_system_api::{ApiType, SystemApiImpl, SystemStateAccessor, SystemStateAccessorDirect};
use ic_test_utilities::{
    mock_time,
    types::ids::{subnet_test_id, user_test_id},
};
use ic_types::{messages::CallContextId, ComputeAllocation, Cycles, NumInstructions};
use maplit::btreemap;

pub const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
pub const CANISTER_CURRENT_MEMORY_USAGE: NumBytes = NumBytes::new(0);

pub fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: NumInstructions::new(5_000_000_000),
        canister_memory_limit: NumBytes::new(4 << 30),
        subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
    }
}

pub fn setup() -> (
    SubnetId,
    SubnetType,
    Arc<RoutingTable>,
    Arc<BTreeMap<SubnetId, SubnetType>>,
) {
    let subnet_id = subnet_test_id(1);
    let subnet_type = SubnetType::Application;
    let routing_table = Arc::new(RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    }));
    let subnet_records = Arc::new(btreemap! {
        subnet_id => subnet_type,
    });

    (subnet_id, subnet_type, routing_table, subnet_records)
}

pub fn get_update_api_type() -> ApiType {
    let (subnet_id, subnet_type, routing_table, subnet_records) = setup();
    ApiType::update(
        mock_time(),
        vec![],
        Cycles::from(0),
        user_test_id(1).get(),
        CallContextId::from(1),
        subnet_id,
        subnet_type,
        routing_table,
        subnet_records,
    )
}

pub fn get_system_api(
    api_type: ApiType,
    system_state: SystemState,
    cycles_account_manager: CyclesAccountManager,
) -> SystemApiImpl<SystemStateAccessorDirect> {
    let system_state_accessor = SystemStateAccessorDirect::new(
        system_state,
        Arc::new(cycles_account_manager),
        &Memory::default(),
    );
    SystemApiImpl::new(
        system_state_accessor.canister_id(),
        api_type,
        system_state_accessor,
        CANISTER_CURRENT_MEMORY_USAGE,
        execution_parameters(),
        no_op_logger(),
    )
}
