use std::{collections::BTreeMap, sync::Arc};

use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{ExecutionParameters, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{Memory, SystemState};
use ic_system_api::{ApiType, StaticSystemState, SystemApiImpl, SystemStateAccessorDirect};
use ic_test_utilities::{
    mock_time,
    types::ids::{call_context_test_id, subnet_test_id, user_test_id},
};
use ic_types::{
    messages::{CallContextId, RejectContext},
    ComputeAllocation, Cycles, NumInstructions,
};
use maplit::btreemap;

pub const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
pub const CANISTER_CURRENT_MEMORY_USAGE: NumBytes = NumBytes::new(0);

pub fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: NumInstructions::new(5_000_000_000),
        canister_memory_limit: NumBytes::new(4 << 30),
        subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
    }
}

pub struct ApiTypeBuilder {
    pub own_subnet_id: SubnetId,
    pub own_subnet_type: SubnetType,
    pub nns_subnet_id: SubnetId,
    pub routing_table: Arc<RoutingTable>,
    pub subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
}

// Note some methods of the builder might be unused in different test crates
#[allow(dead_code)]
impl ApiTypeBuilder {
    pub fn new() -> Self {
        let own_subnet_id = subnet_test_id(1);
        let own_subnet_type = SubnetType::Application;
        let nns_subnet_id = subnet_test_id(0x101);
        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => own_subnet_id,
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => nns_subnet_id,
        }));
        let subnet_records = Arc::new(btreemap! {
            own_subnet_id => own_subnet_type,
            nns_subnet_id => SubnetType::System,
        });
        Self {
            own_subnet_id,
            own_subnet_type,
            nns_subnet_id,
            routing_table,
            subnet_records,
        }
    }

    pub fn with_nns_subnet_id(mut self, nns_subnet_id: SubnetId) -> Self {
        self.nns_subnet_id = nns_subnet_id;
        self
    }

    pub fn build_update_api(self) -> ApiType {
        ApiType::update(
            mock_time(),
            vec![],
            Cycles::from(0),
            user_test_id(1).get(),
            CallContextId::from(1),
            self.own_subnet_id,
            self.own_subnet_type,
            self.nns_subnet_id,
            self.routing_table,
            self.subnet_records,
        )
    }

    pub fn build_heartbeat_api(self) -> ApiType {
        ApiType::heartbeat(
            mock_time(),
            CallContextId::from(1),
            self.own_subnet_id,
            self.own_subnet_type,
            self.nns_subnet_id,
            self.routing_table,
            self.subnet_records,
        )
    }

    pub fn build_reply_api(self, incoming_cycles: Cycles) -> ApiType {
        ApiType::reply_callback(
            mock_time(),
            vec![],
            incoming_cycles,
            CallContextId::new(1),
            false,
            self.own_subnet_id,
            self.own_subnet_type,
            self.nns_subnet_id,
            self.routing_table,
            self.subnet_records,
        )
    }

    pub fn build_reject_api(self, reject_context: RejectContext) -> ApiType {
        ApiType::reject_callback(
            mock_time(),
            reject_context,
            Cycles::from(0),
            call_context_test_id(1),
            false,
            self.own_subnet_id,
            self.own_subnet_type,
            self.nns_subnet_id,
            self.routing_table,
            self.subnet_records,
        )
    }
}

pub fn get_system_api(
    api_type: ApiType,
    system_state: SystemState,
    cycles_account_manager: CyclesAccountManager,
) -> SystemApiImpl<SystemStateAccessorDirect> {
    let static_system_state =
        StaticSystemState::new(&system_state, cycles_account_manager.subnet_type());
    let system_state_accessor =
        SystemStateAccessorDirect::new(system_state, Arc::new(cycles_account_manager));
    SystemApiImpl::new(
        api_type,
        system_state_accessor,
        static_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        execution_parameters(),
        Memory::default(),
        no_op_logger(),
    )
}
