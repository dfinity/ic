use std::{convert::TryFrom, sync::Arc};

use ic_base_types::{CanisterId, NumBytes, SubnetId};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{
    ExecutionMode, ExecutionParameters, SubnetAvailableMemory,
};
use ic_logger::replica_logger::no_op_logger;
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CallOrigin, Memory, NetworkTopology, SubnetTopology, SystemState};
use ic_system_api::{sandbox_safe_system_state::SandboxSafeSystemState, ApiType, SystemApiImpl};
use ic_test_utilities::{
    mock_time,
    types::ids::{call_context_test_id, subnet_test_id, user_test_id},
};
use ic_test_utilities::{state::SystemStateBuilder, types::ids::canister_test_id};
use ic_types::{
    messages::{CallContextId, CallbackId, RejectContext},
    ComputeAllocation, Cycles, NumInstructions, Time,
};
use maplit::btreemap;

pub const CANISTER_CURRENT_MEMORY_USAGE: NumBytes = NumBytes::new(0);

pub fn execution_parameters() -> ExecutionParameters {
    ExecutionParameters {
        instruction_limit: NumInstructions::new(5_000_000_000),
        canister_memory_limit: NumBytes::new(4 << 30),
        subnet_available_memory: SubnetAvailableMemory::new(i64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    }
}

pub struct ApiTypeBuilder {
    pub own_subnet_id: SubnetId,
    pub own_subnet_type: SubnetType,
    pub network_topology: Arc<NetworkTopology>,
}

// Note some methods of the builder might be unused in different test crates
#[allow(dead_code)]
#[allow(clippy::new_without_default)]
impl ApiTypeBuilder {
    pub fn new() -> Self {
        let own_subnet_id = subnet_test_id(1);
        let own_subnet_type = SubnetType::Application;
        let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => own_subnet_id,
        }).unwrap());
        let network_topology = Arc::new(NetworkTopology {
            routing_table,
            subnets: btreemap! {
                own_subnet_id => SubnetTopology {
                    subnet_type: own_subnet_type,
                    ..SubnetTopology::default()
                }
            },
            ..NetworkTopology::default()
        });
        Self {
            own_subnet_id,
            own_subnet_type,
            network_topology,
        }
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
            self.network_topology,
        )
    }

    pub fn build_heartbeat_api(self) -> ApiType {
        ApiType::heartbeat(
            mock_time(),
            CallContextId::from(1),
            self.own_subnet_id,
            self.own_subnet_type,
            self.network_topology,
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
            self.network_topology,
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
            self.network_topology,
        )
    }
}

pub fn get_system_api(
    api_type: ApiType,
    system_state: &SystemState,
    cycles_account_manager: CyclesAccountManager,
) -> SystemApiImpl {
    let sandbox_safe_system_state =
        SandboxSafeSystemState::new(system_state, cycles_account_manager);
    SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        execution_parameters(),
        Memory::default(),
        no_op_logger(),
    )
}

pub fn get_system_state() -> SystemState {
    let mut system_state = SystemStateBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5)),
            Cycles::from(50),
            Time::from_nanos_since_unix_epoch(0),
        );
    system_state
}

pub fn get_cmc_system_state() -> SystemState {
    let mut system_state = get_system_state();
    system_state.canister_id = CYCLES_MINTING_CANISTER_ID;
    system_state
}
