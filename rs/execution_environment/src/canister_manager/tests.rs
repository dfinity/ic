use crate::{
    canister_manager::{
        canister_layout, uninstall_canister, CanisterManager, CanisterManagerError,
        CanisterMgrConfig, StopCanisterResult,
    },
    canister_settings::CanisterSettings,
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
    IngressHistoryWriterImpl, QueryExecutionType,
};
use assert_matches::assert_matches;
use ic_base_types::NumSeconds;
use ic_config::execution_environment::Config;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_interfaces::execution_environment::{HypervisorError, SubnetAvailableMemory};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::testing::CanisterStateTesting;
use ic_replicated_state::{
    page_map, CallContextManager, CallOrigin, CanisterStatus, NumWasmPages, PageMap,
    ReplicatedState,
};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::{
        get_running_canister, get_running_canister_with_args, get_stopped_canister,
        get_stopped_canister_with_controller, get_stopping_canister,
        get_stopping_canister_with_controller, CallContextBuilder, CanisterStateBuilder,
        ReplicatedStateBuilder,
    },
    types::{
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::{InstallCodeContextBuilder, RequestBuilder, SignedIngressBuilder},
    },
    with_test_replica_logger,
};
use ic_types::messages::StopCanisterContext;
use ic_types::nominal_cycles::NominalCycles;
use ic_types::{
    funds::icp::Tap as ICPTap,
    ingress::{IngressStatus, WasmResult},
    messages::{CallbackId, CanisterInstallMode, RequestOrResponse},
    user_error::{ErrorCode, UserError},
    CanisterId, CanisterStatusType, ComputeAllocation, Cycles, Funds, InstallCodeContext,
    MemoryAllocation, NumBytes, NumInstructions, QueryAllocation, SubnetId, ICP,
};
use ic_wasm_types::WasmValidationError;
use lazy_static::lazy_static;
use maplit::{btreemap, btreeset};
use std::{collections::BTreeSet, convert::TryFrom, path::Path, sync::Arc};

const CANISTER_CREATION_FEE: Cycles = Cycles::new(1_000_000_000_000);
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const CYCLES_LIMIT_PER_CANISTER: Cycles = Cycles::new(100_000_000_000_000);
const DEFAULT_PROVISIONAL_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const MEMORY_CAPACITY: NumBytes = NumBytes::new(8 * 1024 * 1024 * 1024); // 8GiB
const MAX_GLOBALS: usize = 200;
const MAX_FUNCTIONS: usize = 6000;

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(NumBytes::new(std::u64::MAX));
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
}

struct CanisterManagerBuilder {
    cycles_account_manager: CyclesAccountManager,
    subnet_id: SubnetId,
}

impl CanisterManagerBuilder {
    fn with_subnet_id(mut self, subnet_id: SubnetId) -> Self {
        self.subnet_id = subnet_id;
        self
    }

    fn with_cycles_account_manager(mut self, cycles_account_manager: CyclesAccountManager) -> Self {
        self.cycles_account_manager = cycles_account_manager;
        self
    }

    fn build(self) -> CanisterManager {
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            no_op_logger(),
            &metrics_registry,
        ));
        let cycles_account_manager = Arc::new(self.cycles_account_manager);
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            self.subnet_id,
            subnet_type,
            no_op_logger(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        CanisterManager::new(
            hypervisor,
            1,
            self.subnet_id,
            subnet_type,
            no_op_logger(),
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        )
    }
}

impl Default for CanisterManagerBuilder {
    fn default() -> Self {
        Self {
            cycles_account_manager: CyclesAccountManagerBuilder::new().build(),
            subnet_id: subnet_test_id(1),
        }
    }
}

fn canister_manager_config() -> CanisterMgrConfig {
    CanisterMgrConfig::new(
        MEMORY_CAPACITY,
        Some(CYCLES_LIMIT_PER_CANISTER),
        DEFAULT_PROVISIONAL_BALANCE,
        NumSeconds::from(100_000),
        MAX_GLOBALS,
        MAX_FUNCTIONS,
    )
}

fn initial_state(path: &Path, subnet_id: SubnetId) -> ReplicatedState {
    let routing_table = RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    });
    let mut state =
        ReplicatedState::new_rooted_at(subnet_id, SubnetType::Application, path.to_path_buf());
    state.metadata.network_topology.routing_table = routing_table;
    state.metadata.network_topology.nns_subnet_id = subnet_id;
    state
}

fn with_setup<F>(f: F)
where
    F: FnOnce(CanisterManager, ReplicatedState, SubnetId),
{
    let subnet_id = subnet_test_id(1);
    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .build();
    let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
    f(
        canister_manager,
        initial_state(tmpdir.path(), subnet_id),
        subnet_id,
    )
}

#[test]
fn install_canister_makes_subnet_oversubscribed() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();
        let canister_id2 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();
        let canister_id3 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id1)
                    .compute_allocation(ComputeAllocation::try_from(50).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id2)
                    .compute_allocation(ComputeAllocation::try_from(25).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());
        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id3)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .compute_allocation(ComputeAllocation::try_from(30).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: ComputeAllocation::try_from(30).unwrap(),
                    available: 24
                })
            )
        );

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id3).is_some());
    });
}

#[test]
fn upgrade_non_existing_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .mode(CanisterInstallMode::Upgrade)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::CanisterNotFound(canister_id))
            )
        );
    });
}

#[test]
fn upgrade_canister_with_no_wasm_fails() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .mode(CanisterInstallMode::Upgrade)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::Hypervisor(
                    canister_id,
                    HypervisorError::WasmModuleNotFound
                ))
            )
        );
    });
}

#[test]
fn can_update_compute_allocation_during_upgrade() {
    with_setup(|canister_manager, mut state, _| {
        // Create a new canister.
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Install the canister with allocation of 60%.
        let res = canister_manager.install_code(
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id1)
                .compute_allocation(ComputeAllocation::try_from(60).unwrap())
                .build(),
            &mut state,
            MAX_NUM_INSTRUCTIONS,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        assert!(res.1.is_ok());

        assert_eq!(
            state
                .canister_state(&canister_id1)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(60).unwrap()
        );

        // Upgrade the canister to allocation of 80%.
        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id1)
                    .compute_allocation(ComputeAllocation::try_from(80).unwrap())
                    .mode(CanisterInstallMode::Upgrade)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        assert_eq!(
            state
                .canister_state(&canister_id1)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(80).unwrap()
        );
    });
}

#[test]
fn upgrading_canister_makes_subnet_oversubscribed() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(27).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();
        let canister_id2 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();
        let canister_id3 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id1)
                    .compute_allocation(ComputeAllocation::try_from(50).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id2)
                    .compute_allocation(ComputeAllocation::try_from(25).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id3)
                    .compute_allocation(ComputeAllocation::try_from(20).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id3)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .compute_allocation(ComputeAllocation::try_from(30).unwrap())
                    .mode(CanisterInstallMode::Upgrade)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: ComputeAllocation::try_from(30).unwrap(),
                    available: 24,
                })
            )
        );

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id3).is_some());

        assert_eq!(
            state
                .canister_state(&canister_id1)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(50).unwrap()
        );
        assert_eq!(
            state
                .canister_state(&canister_id2)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(25).unwrap()
        );
        assert_eq!(
            state
                .canister_state(&canister_id3)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(20).unwrap()
        );
    });
}

#[test]
fn install_canister_fails_if_memory_capacity_exceeded() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(13).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let canister_id2 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let canister_id3 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id1)
                    .memory_allocation(
                        MemoryAllocation::try_from(NumBytes::from(MEMORY_CAPACITY.get() / 2))
                            .unwrap(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id2)
                    .memory_allocation(
                        MemoryAllocation::try_from(NumBytes::from(MEMORY_CAPACITY.get() / 2))
                            .unwrap(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id3)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .memory_allocation(MemoryAllocation::try_from(NumBytes::from(1)).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: NumBytes::from(1),
                    available: NumBytes::from(0),
                })
            )
        );

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id3).is_some());
    });
}

#[test]
fn can_update_memory_allocation_during_upgrade() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(13).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let initial_memory_allocation =
            MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap();
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .compute_allocation(ComputeAllocation::try_from(60).unwrap())
                    .memory_allocation(initial_memory_allocation)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .memory_allocation()
                .unwrap(),
            initial_memory_allocation.get()
        );

        let final_memory_allocation = MemoryAllocation::try_from(NumBytes::from(2 << 30)).unwrap();
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .compute_allocation(ComputeAllocation::try_from(60).unwrap())
                    .memory_allocation(final_memory_allocation)
                    .mode(CanisterInstallMode::Upgrade)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .memory_allocation()
                .unwrap(),
            final_memory_allocation.get()
        );
    });
}

#[test]
fn install_code_preserves_messages() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = 0;
        let num_messages = 10;
        let sender = canister_test_id(1).get();

        // Create a new canister.
        let mut canister_state_builder = CanisterStateBuilder::new()
            .with_controller(sender)
            .with_canister_id(canister_test_id(canister_id))
            .with_cycles(*INITIAL_CYCLES);

        for i in 0..num_messages {
            canister_state_builder = canister_state_builder.with_ingress(
                SignedIngressBuilder::new()
                    .canister_id(canister_test_id(canister_id))
                    .nonce(i)
                    .build()
                    .into(),
            );
        }
        state.put_canister_state(canister_state_builder.build());

        // Install the canister with new wasm.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_test_id(0))
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Check the ingress messages are still in the queue.
        let canister = state
            .canister_state(&canister_test_id(0))
            .expect("Failed to find the canister");
        assert_eq!(canister.ingress_queue_size() as u64, num_messages);
    });
}

#[test]
fn can_create_canister() {
    with_setup(|canister_manager, mut state, _| {
        let canister = canister_test_id(50).get();
        let sender_subnet_id = subnet_test_id(1);
        let expected_generated_id1 = CanisterId::from(0);
        let expected_generated_id2 = CanisterId::from(1);

        assert_eq!(
            canister_manager
                .create_canister(
                    canister,
                    sender_subnet_id,
                    Funds::new(*INITIAL_CYCLES, ICP::zero()),
                    CanisterSettings::default(),
                    &mut state,
                )
                .0
                .unwrap(),
            expected_generated_id1
        );
        assert_eq!(
            canister_manager
                .create_canister(
                    canister,
                    sender_subnet_id,
                    Funds::new(*INITIAL_CYCLES, ICP::zero()),
                    CanisterSettings::default(),
                    &mut state,
                )
                .0
                .unwrap(),
            expected_generated_id2
        );
        assert_eq!(state.canister_states.len(), 2);
    });
}

#[test]
fn create_canister_fails_if_not_enough_cycles_are_sent_with_the_request() {
    with_setup(|canister_manager, mut state, _| {
        let canister = canister_test_id(50).get();
        let sender_subnet_id = subnet_test_id(1);

        assert_eq!(
            canister_manager.create_canister(
                canister,
                sender_subnet_id,
                Funds::new(Cycles::from(100), ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            ),
            (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: Cycles::from(100),
                    required: CANISTER_CREATION_FEE
                }),
                Funds::new(Cycles::from(100), ICP::zero()),
            ),
        );
        assert_eq!(state.canister_states.len(), 0);
    });
}

#[test]
fn can_create_canister_with_extra_funds() {
    with_setup(|canister_manager, mut state, _| {
        let canister = canister_test_id(30).get();
        let sender_subnet_id = subnet_test_id(1);
        let expected_generated_id1 = CanisterId::from(0);
        let cycles: u64 = 1_000_000_000_200;
        let icp = 50;

        assert_eq!(
            canister_manager
                .create_canister(
                    canister,
                    sender_subnet_id,
                    Funds::new(Cycles::from(cycles), ICPTap::mint(icp)),
                    CanisterSettings::default(),
                    &mut state,
                )
                .0
                .unwrap(),
            expected_generated_id1
        );
        assert_eq!(state.canister_states.len(), 1);
    });
}

#[test]
fn cannot_install_non_empty_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Install a wasm module. Should succeed.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Install again. Should fail.
        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::CanisterNonEmpty(canister_id))
            )
        );

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id).is_some());
    });
}

#[test]
fn install_code_with_wrong_controller_fails() {
    with_setup(|canister_manager, mut state, _| {
        // Create a canister with canister_test_id 1 as controller.
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        for mode in CanisterInstallMode::iter() {
            // Try to install_code with canister_test_id 2. Should fail.
            assert_eq!(
                canister_manager.install_code(
                    InstallCodeContextBuilder::default()
                        .sender(canister_test_id(2).get())
                        .canister_id(canister_id)
                        .wasm_module(
                            ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                        )
                        .mode(*mode)
                        .build(),
                    &mut state,
                    MAX_NUM_INSTRUCTIONS,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                ),
                (
                    MAX_NUM_INSTRUCTIONS,
                    Err(CanisterManagerError::CanisterInvalidController {
                        canister_id,
                        controllers_expected: btreeset! {canister_test_id(1).get()},
                        controller_provided: canister_test_id(2).get(),
                    })
                )
            );

            // Canister should still be in the replicated state.
            assert!(state.canister_state(&canister_id).is_some());
        }
    });
}

#[test]
fn create_canister_sets_correct_allocations() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let canister = state.canister_state(&canister_id).unwrap();
        assert_eq!(canister.memory_allocation(), None);
        assert_eq!(
            canister.scheduler_state.compute_allocation,
            ComputeAllocation::try_from(0).unwrap()
        );
    });
}

#[test]
fn create_canister_updates_consumed_cycles_metric_correctly() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let creation_fee = cycles_account_manager.canister_creation_fee();
        let canister = state.canister_state(&canister_id).unwrap();
        assert_eq!(
            canister
                .system_state
                .canister_metrics
                .consumed_cycles_since_replica_started
                .get(),
            creation_fee.get()
        );
        assert_eq!(
            canister.system_state.cycles_balance,
            *INITIAL_CYCLES - creation_fee
        )
    });
}

#[test]
fn provisional_create_canister_has_no_creation_fee() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_manager
            .create_canister_with_funds(
                canister_test_id(1).get(),
                Some(INITIAL_CYCLES.get() as u64),
                ICP::zero().balance(),
                CanisterSettings::default(),
                &mut state,
                &ProvisionalWhitelist::All,
            )
            .unwrap();

        let canister = state.canister_state(&canister_id).unwrap();
        assert_eq!(
            canister
                .system_state
                .canister_metrics
                .consumed_cycles_since_replica_started
                .get(),
            NominalCycles::default().get()
        );
        assert_eq!(canister.system_state.cycles_balance, *INITIAL_CYCLES)
    });
}

#[test]
fn reinstall_on_empty_canister_succeeds() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(42).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_test_id(1),
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Reinstalling an empty canister should succeed.
        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .mode(CanisterInstallMode::Reinstall)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id).is_some());
    });
}

const COUNTER_WAT: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (func $inc
            ;; Increment a counter.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 1))))
        (func $read
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 4)) ;; length
            (call $msg_reply))
        (func $canister_init
            ;; Increment the counter by 41 in canister_init.
            (i32.store
                (i32.const 0)
                (i32.add (i32.load (i32.const 0)) (i32.const 41))))
        (start $inc)    ;; Increments counter by 1 in canister_start
        (memory $memory 1)
        (export "canister_query read" (func $read))
        (export "canister_init" (func $canister_init))
    )"#;

#[test]
fn reinstall_calls_canister_start_and_canister_init() {
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );

        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Install a wasm module with no exported functions.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Reinstalling with new code.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(wabt::wat2wasm(COUNTER_WAT).unwrap())
                    .mode(CanisterInstallMode::Reinstall)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // If canister_start and canister_init were called, then the counter
        // should be initialized to 42.
        let canister = state.take_canister_state(&canister_id).unwrap();
        let user_id = user_test_id(0);
        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    &"read",
                    &[],
                    user_id.get(),
                    MAX_NUM_INSTRUCTIONS,
                    canister,
                    None,
                    mock_time(),
                )
                .get_no_pause()
                .2
                .unwrap(),
            Some(WasmResult::Reply(vec![42, 0, 0, 0]))
        );
    });
}

#[test]
fn install_calls_canister_start_and_canister_init() {
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));

        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(wabt::wat2wasm(COUNTER_WAT).unwrap())
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // If canister_start and canister_init were called, then the counter
        // should be initialized to 42.
        let canister = state.take_canister_state(&canister_id).unwrap();
        let user_id = user_test_id(0);
        assert_eq!(
            hypervisor
                .execute_query(
                    QueryExecutionType::Replicated,
                    &"read",
                    &[],
                    user_id.get(),
                    MAX_NUM_INSTRUCTIONS,
                    canister,
                    None,
                    mock_time(),
                )
                .get_no_pause()
                .2
                .unwrap(),
            Some(WasmResult::Reply(vec![42, 0, 0, 0]))
        );
    });
}

#[test]
fn install_puts_canister_back_after_invalid_wasm() {
    with_setup(|canister_manager, mut state, _| {
        // Use an invalid wasm code (import memory from an invalid module).
        let wasm =
            wabt::wat2wasm(r#"(module (import "foo" "memory" (memory (;0;) 529)))"#).unwrap();

        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Installation should be rejected.
        assert_eq!(
            canister_manager.install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(wasm)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::Hypervisor(
                    canister_id,
                    HypervisorError::InvalidWasm(WasmValidationError::InvalidImportSection(
                        "Only memory imported from env.memory is allowed.".to_string()
                    ))
                ))
            )
        );

        // Canister should still be in the replicated state.
        assert!(state.canister_state(&canister_id).is_some());
    });
}

#[test]
fn reinstall_clears_stable_memory() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Write something into the canister's stable memory.
        let mut canister = state.take_canister_state(&canister_id).unwrap();
        assert_eq!(
            canister.system_state.stable_memory_size,
            NumWasmPages::new(0)
        );
        canister.system_state.stable_memory_size = NumWasmPages::new(1);
        let mut buf = page_map::Buffer::new(PageMap::default());
        buf.write(&[1; 10], 0);
        canister.system_state.stable_memory = buf.into_page_map();

        state.put_canister_state(canister);

        // Reinstall the canister.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .mode(CanisterInstallMode::Reinstall)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Stable memory should now be empty.
        let canister = state.take_canister_state(&canister_id).unwrap();
        assert_eq!(
            canister.system_state.stable_memory_size,
            NumWasmPages::new(0)
        );
    });
}

#[test]
fn stop_a_running_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1);
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender.get(),
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // When created, a canister is initially running.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );

        // Stop the canister.
        let stop_context = StopCanisterContext::Canister {
            sender,
            reply_callback: CallbackId::new(0),
            funds: Funds::zero(),
        };
        assert_eq!(
            canister_manager.stop_canister(canister_id, stop_context.clone(), &mut state),
            StopCanisterResult::RequestAccepted
        );

        // Canister should now have the "stopping" status with empty call contexts.
        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .system_state
                .status,
            CanisterStatus::Stopping {
                stop_contexts: vec![stop_context],
                call_context_manager: CallContextManager::default(),
            }
        );

        // It should also be ready to stop.
        assert!(state
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .ready_to_stop());
    });
}

#[test]
fn stop_a_stopped_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1);
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister(canister_id);
        state.put_canister_state(canister);

        // Canister should be stopped.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Stopped
        );

        let stop_context = StopCanisterContext::Ingress {
            sender,
            message_id: message_test_id(0),
        };
        assert_eq!(
            canister_manager.stop_canister(canister_id, stop_context, &mut state),
            StopCanisterResult::AlreadyStopped {
                funds_to_return: Funds::zero()
            }
        );

        // Canister should still be stopped.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Stopped
        );
    });
}

#[test]
fn stop_a_stopped_canister_from_another_canister() {
    with_setup(|canister_manager, mut state, _| {
        let controller = canister_test_id(1);
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister_with_controller(canister_id, controller.get());
        state.put_canister_state(canister);

        // Canister should be stopped.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Stopped
        );

        let cycles = 20;
        let icp = 10;
        let stop_context = StopCanisterContext::Canister {
            sender: controller,
            reply_callback: CallbackId::from(0),
            funds: Funds::new(Cycles::from(cycles), ICPTap::mint(icp)),
        };
        assert_eq!(
            canister_manager.stop_canister(canister_id, stop_context, &mut state),
            StopCanisterResult::AlreadyStopped {
                funds_to_return: Funds::new(Cycles::from(cycles), ICPTap::mint(icp))
            }
        );

        // Canister should still be stopped.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Stopped
        );
    });
}

#[test]
fn stop_a_canister_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let msg_id = message_test_id(0);
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // When created, a canister is initially running.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );

        // Stop the canister by a sender who isn't the controller.
        let other_sender = user_test_id(1);
        let stop_context = StopCanisterContext::Ingress {
            sender: other_sender,
            message_id: msg_id,
        };

        assert_eq!(
            canister_manager.stop_canister(canister_id, stop_context, &mut state),
            StopCanisterResult::Failure {
                funds_to_return: Funds::zero(),
                error: CanisterManagerError::CanisterInvalidController {
                    canister_id,
                    controllers_expected: btreeset! {sender},
                    controller_provided: other_sender.get(),
                }
            }
        );
    });
}

#[test]
fn stop_a_non_existing_canister() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);

        assert_eq!(
            canister_manager.stop_canister(
                canister_id,
                StopCanisterContext::Ingress {
                    sender: user_test_id(1),
                    message_id: message_test_id(0),
                },
                &mut state
            ),
            StopCanisterResult::Failure {
                funds_to_return: Funds::zero(),
                error: CanisterManagerError::CanisterNotFound(canister_id),
            }
        );
    });
}

#[test]
fn start_a_non_existing_canister() {
    with_setup(|canister_manager, mut state, _| {
        assert_eq!(
            canister_manager.start_canister(canister_test_id(0), user_test_id(0).get(), &mut state),
            Err(CanisterManagerError::CanisterNotFound(canister_test_id(0)))
        );
    });
}

#[test]
fn start_a_canister_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Start the canister by a sender who isn't the controller.
        let other_sender = user_test_id(1).get();
        assert_eq!(
            canister_manager.start_canister(canister_id, other_sender, &mut state),
            Err(CanisterManagerError::CanisterInvalidController {
                canister_id,
                controllers_expected: btreeset! {sender},
                controller_provided: other_sender,
            })
        );
    });
}

#[test]
fn starting_an_already_running_canister_keeps_it_running() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // When created, a canister is initially running.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );

        // Start the canister. Since it's already running, the canister should
        // remain running.
        canister_manager
            .start_canister(canister_id, sender, &mut state)
            .unwrap();

        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );
    });
}

#[test]
fn start_a_stopped_canister_succeeds() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1).get();
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister(canister_id);
        state.put_canister_state(canister);

        // Canister should be stopped.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Stopped
        );

        // Start the canister.
        canister_manager
            .start_canister(canister_id, sender, &mut state)
            .unwrap();

        // Canister should now be running.
        assert_eq!(
            state.canister_state(&canister_id).unwrap().status(),
            CanisterStatusType::Running
        );
    });
}

#[test]
fn start_a_stopping_canister_with_no_stop_contexts() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1).get();
        let canister_id = canister_test_id(0);
        let canister = get_stopping_canister(canister_id);

        state.put_canister_state(canister);

        assert_eq!(
            canister_manager.start_canister(canister_id, sender, &mut state),
            Ok(Vec::new())
        );
    });
}

#[test]
fn start_a_stopping_canister_with_stop_contexts() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1).get();
        let canister_id = canister_test_id(0);
        let mut canister = get_stopping_canister(canister_id);
        let stop_context = StopCanisterContext::Ingress {
            sender: user_test_id(1),
            message_id: message_test_id(0),
        };
        canister.system_state.add_stop_context(stop_context.clone());

        state.put_canister_state(canister);

        assert_eq!(
            canister_manager.start_canister(canister_id, sender, &mut state),
            Ok(vec![stop_context])
        );
    });
}

#[test]
fn get_canister_status_of_non_existing_canister() {
    with_setup(|canister_manager, mut state, _| {
        assert_eq!(
            canister_manager.get_canister_status(
                canister_test_id(0),
                user_test_id(0).get(),
                &mut state
            ),
            Err(CanisterManagerError::CanisterNotFound(canister_test_id(0)))
        );
    });
}

#[test]
fn get_canister_status_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Get the status of the canister by a sender who isn't the controller.
        let other_sender = user_test_id(1).get();
        assert_eq!(
            canister_manager.get_canister_status(canister_id, other_sender, &mut state),
            Err(CanisterManagerError::CanisterInvalidController {
                canister_id,
                controllers_expected: btreeset! {sender},
                controller_provided: other_sender,
            })
        );
    });
}

#[test]
fn get_canister_status_of_running_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let status = canister_manager
            .get_canister_status(canister_id, sender, &mut state)
            .unwrap()
            .status();
        assert_eq!(status, CanisterStatusType::Running);
    });
}

#[test]
fn get_canister_status_of_stopped_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1).get();
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister(canister_id);
        state.put_canister_state(canister);

        let status = canister_manager
            .get_canister_status(canister_id, sender, &mut state)
            .unwrap()
            .status();
        assert_eq!(status, CanisterStatusType::Stopped);
    });
}

#[test]
fn get_canister_status_of_stopping_canister() {
    with_setup(|canister_manager, mut state, _| {
        let sender = user_test_id(1).get();
        let canister_id = canister_test_id(0);
        let canister = get_stopping_canister(canister_id);
        state.put_canister_state(canister);

        let status = canister_manager
            .get_canister_status(canister_id, sender, &mut state)
            .unwrap()
            .status();
        assert_eq!(status, CanisterStatusType::Stopping);
    });
}

#[test]
fn set_controller_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);

        state.put_canister_state(canister);

        let wrong_controller = user_test_id(0).get();
        let right_controller = user_test_id(1).get();
        let new_controller = user_test_id(2).get();

        // Set the controller from the wrong controller. Should fail.
        assert_eq!(
            canister_manager.set_controller(
                wrong_controller,
                canister_id,
                new_controller,
                &mut state
            ),
            Err(CanisterManagerError::CanisterInvalidController {
                canister_id,
                controllers_expected: btreeset! {right_controller},
                controller_provided: wrong_controller,
            })
        );

        // Controller hasn't changed.
        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .system_state
                .controllers,
            btreeset! {right_controller}
        );
    });
}

#[test]
fn set_controller_with_correct_controller() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        state.put_canister_state(canister);

        let controller = user_test_id(1).get();
        let new_controller = user_test_id(2).get();

        // Set the controller from the correct controller. Should succeed.
        assert!(canister_manager
            .set_controller(controller, canister_id, new_controller, &mut state)
            .is_ok());

        // Controller is now the new controller.
        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .system_state
                .controllers,
            btreeset! {new_controller}
        );
    });
}

#[test]
fn delete_non_existing_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let controller = canister_test_id(1);
        let state_before = state.clone();

        assert_eq!(
            canister_manager.delete_canister(controller.get(), canister_id, &mut state),
            Err(CanisterManagerError::CanisterNotFound(canister_id))
        );

        // Assert that state hasn't changed
        assert_eq!(state, state_before);
    });
}

#[test]
fn delete_canister_with_incorrect_controller_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let canister = get_stopped_canister_with_controller(canister_id, canister_test_id(1).get());
        state.put_canister_state(canister);

        let wrong_controller = canister_test_id(2);
        let right_controller = canister_test_id(1).get();

        assert_eq!(
            canister_manager.delete_canister(wrong_controller.get(), canister_id, &mut state),
            Err(CanisterManagerError::CanisterInvalidController {
                canister_id,
                controllers_expected: btreeset! {right_controller},
                controller_provided: wrong_controller.get(),
            })
        );

        // Canister should still be there.
        assert_matches!(state.canister_state(&canister_id), Some(_));
        assert!(!canister_layout(state.path(), &canister_id).is_marked_deleted())
    });
}

#[test]
fn delete_running_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let controller_id = canister_test_id(1);

        let canister =
            get_running_canister_with_args(canister_id, canister_test_id(1).get(), *INITIAL_CYCLES);
        let controller_canister = get_running_canister(controller_id);

        state.put_canister_state(canister);
        state.put_canister_state(controller_canister);

        assert_eq!(
            canister_manager.delete_canister(controller_id.get(), canister_id, &mut state),
            Err(CanisterManagerError::DeleteCanisterNotStopped(canister_id))
        );

        // Canister should still be there.
        assert_matches!(state.canister_state(&canister_id), Some(_));
        assert!(!canister_layout(state.path(), &canister_id).is_marked_deleted())
    });
}

#[test]
fn delete_stopping_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let controller_id = canister_test_id(1);

        let canister =
            get_stopping_canister_with_controller(canister_id, canister_test_id(1).get());
        let controller_canister = get_running_canister(controller_id);

        state.put_canister_state(canister);
        state.put_canister_state(controller_canister);

        assert_eq!(
            canister_manager.delete_canister(controller_id.get(), canister_id, &mut state),
            Err(CanisterManagerError::DeleteCanisterNotStopped(canister_id))
        );

        // Canister should still be there.
        assert_matches!(state.canister_state(&canister_id), Some(_));
        assert!(!canister_layout(state.path(), &canister_id).is_marked_deleted())
    });
}

#[test]
fn delete_stopped_canister_succeeds() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let controller_id = canister_test_id(1);

        let canister = get_stopped_canister_with_controller(canister_id, canister_test_id(1).get());
        let controller_canister = get_running_canister(controller_id);

        state.put_canister_state(canister);
        state.put_canister_state(controller_canister);

        let controller = canister_test_id(1);

        assert_eq!(
            canister_manager.delete_canister(controller.get(), canister_id, &mut state),
            Ok(())
        );

        // Canister should no longer be there.
        assert_eq!(state.canister_state(&canister_id), None);
        assert!(canister_layout(state.path(), &canister_id).is_marked_deleted())
    });
}

#[test]
fn install_canister_with_query_allocation() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();
        let query_allocation = QueryAllocation::try_from(50).unwrap();
        assert!(canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .query_allocation(query_allocation)
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .is_ok());
        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .scheduler_state
                .query_allocation,
            query_allocation
        );
    });
}

#[test]
fn deposit_cycles_to_non_existing_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let state_before = state.clone();
        let cycles = Cycles::from(5);

        let (cycles_to_return, res) =
            canister_manager.deposit_cycles(canister_id, cycles, &mut state);
        assert_eq!(cycles_to_return, cycles);
        assert_eq!(
            res,
            Err(CanisterManagerError::CanisterNotFound(canister_id))
        );
        // Assert that state hasn't changed
        assert_eq!(state, state_before);
    });
}

#[test]
fn create_canister_with_funds_sender_in_whitelist() {
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );

        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let sender = canister_test_id(1).get();
        let canister_id = canister_manager
            .create_canister_with_funds(
                sender,
                Some(123),
                456,
                CanisterSettings::default(),
                &mut state,
                &ProvisionalWhitelist::Set(btreeset! { canister_test_id(1).get() }),
            )
            .unwrap();

        let canister = state.take_canister_state(&canister_id).unwrap();

        // Verify funds are set as expected.
        assert_eq!(canister.system_state.cycles_balance, Cycles::from(123),);
    });
}

#[test]
fn can_get_canister_balance() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let sender = canister_test_id(1).get();
        let gas = Cycles::from(100);
        let canister = get_running_canister_with_args(canister_id, sender, gas);
        state.put_canister_state(canister);

        assert_matches!(
            canister_manager.get_canister_status(canister_id, sender, &mut state),
            Ok(res) if res.cycles() == gas.get()
        );
    });
}

#[test]
fn add_cycles_sender_in_whitelist() {
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );

        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );

        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        let sender = canister_test_id(1).get();

        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let initial_cycles = canister.system_state.cycles_balance;
        state.put_canister_state(canister);
        canister_manager
            .add_cycles(
                sender,
                canister_id,
                Some(123),
                &mut state,
                &ProvisionalWhitelist::Set(btreeset! { canister_test_id(1).get() }),
            )
            .unwrap();

        // Verify cycles are set as expected.
        let canister = state.take_canister_state(&canister_id).unwrap();
        assert_eq!(
            canister.system_state.cycles_balance,
            initial_cycles + Cycles::from(123),
        );
    });
}

#[test]
fn add_cycles_sender_not_in_whitelist() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        let sender = canister_test_id(1).get();

        state.put_canister_state(canister);

        // By default, the `CanisterManager`'s whitelist is set to `None`.
        // A call to `add_cycles` should fail.
        assert_eq!(
            canister_manager.add_cycles(
                sender,
                canister_id,
                Some(123),
                &mut state,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
            ),
            Err(CanisterManagerError::SenderNotInWhitelist(sender))
        );
    });
}

#[test]
fn installing_a_canister_with_not_enough_memory_allocation_fails() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        // Give just 10 bytes of memory allocation which should result in an error.
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(10)).unwrap();
        let res = canister_manager.install_code(
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .memory_allocation(memory_allocation)
                .build(),
            &mut state,
            MAX_NUM_INSTRUCTIONS,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        assert_eq!(res.0, MAX_NUM_INSTRUCTIONS);
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );

        // Install the canister.
        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Attempt to re-install with low memory allocation should fail.
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(50)).unwrap();
        let res = canister_manager.install_code(
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .mode(CanisterInstallMode::Reinstall)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .memory_allocation(memory_allocation)
                .build(),
            &mut state,
            MAX_NUM_INSTRUCTIONS,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        assert_eq!(res.0, MAX_NUM_INSTRUCTIONS);
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    });
}

#[test]
fn upgrading_a_canister_with_not_enough_memory_allocation_fails() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContextBuilder::default()
                    .sender(sender)
                    .canister_id(canister_id)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        // Give just 10 bytes which should be small enough.
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(10)).unwrap();
        assert_matches!(
            canister_manager
                .install_code(
                    InstallCodeContextBuilder::default()
                        .sender(sender)
                        .canister_id(canister_id)
                        .wasm_module(
                            ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec()
                        )
                        .memory_allocation(memory_allocation)
                        .mode(CanisterInstallMode::Upgrade)
                        .build(),
                    &mut state,
                    MAX_NUM_INSTRUCTIONS,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                )
                .1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    });
}

#[test]
fn installing_a_canister_with_not_enough_cycles_fails() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                // Give the new canister a relatively small number of cycles so it doesn't have
                // enough to be installed.
                Funds::new(CANISTER_CREATION_FEE + Cycles::from(100), ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        let res = canister_manager.install_code(
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            MAX_NUM_INSTRUCTIONS,
            MAX_SUBNET_AVAILABLE_MEMORY.clone(),
        );
        assert_eq!(res.0, MAX_NUM_INSTRUCTIONS);
        assert_matches!(res.1, Err(CanisterManagerError::CanisterOutOfCycles { .. }));
    });
}

#[test]
fn uninstall_canister_doesnt_respond_to_responded_call_contexts() {
    assert_eq!(
        uninstall_canister(
            &no_op_logger(),
            &mut CanisterStateBuilder::new()
                .with_call_context(CallContextBuilder::new().with_responded(true).build())
                .build(),
            &Path::new(""),
            mock_time(),
        ),
        Vec::new()
    );
}

#[test]
fn uninstall_canister_responds_to_unresponded_call_contexts() {
    assert_eq!(
        uninstall_canister(
            &no_op_logger(),
            &mut CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(789))
                .with_call_context(
                    CallContextBuilder::new()
                        .with_call_origin(CallOrigin::Ingress(
                            user_test_id(123),
                            message_test_id(456)
                        ))
                        .with_responded(false)
                        .build()
                )
                .build(),
            &Path::new(""),
            mock_time(),
        )[0],
        Response::Ingress(IngressResponse {
            message_id: message_test_id(456),
            status: IngressStatus::Failed {
                receiver: canister_test_id(789).get(),
                user_id: user_test_id(123),
                error: UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "Canister has been uninstalled.",
                ),
                time: mock_time()
            }
        })
    );
}

#[test]
fn failed_upgrade_hooks_consume_instructions() {
    fn run(initial_wasm: Vec<u8>, upgrade_wasm: Vec<u8>) {
        with_test_replica_logger(|log| {
            let subnet_id = subnet_test_id(1);
            let subnet_type = SubnetType::Application;
            let metrics_registry = MetricsRegistry::new();
            let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
            let hypervisor = Arc::new(Hypervisor::new(
                Config::default(),
                1,
                &metrics_registry,
                subnet_id,
                subnet_type,
                log.clone(),
                Arc::clone(&cycles_account_manager),
            ));
            let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
                log.clone(),
                &metrics_registry,
            ));
            let canister_manager = CanisterManager::new(
                Arc::clone(&hypervisor) as Arc<_>,
                1,
                subnet_id,
                subnet_type,
                log,
                canister_manager_config(),
                cycles_account_manager,
                ingress_history_writer,
            );
            let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
            let mut state = initial_state(tmpdir.path(), subnet_id);
            let sender = canister_test_id(100).get();
            let canister_id = canister_manager
                .create_canister(
                    sender,
                    subnet_id,
                    Funds::new(*INITIAL_CYCLES, ICP::zero()),
                    CanisterSettings::default(),
                    &mut state,
                )
                .0
                .unwrap();

            canister_manager
                .install_code(
                    InstallCodeContext {
                        sender,
                        canister_id,
                        wasm_module: initial_wasm,
                        arg: vec![],
                        compute_allocation: None,
                        memory_allocation: None,
                        mode: CanisterInstallMode::Install,
                        query_allocation: QueryAllocation::default(),
                    },
                    &mut state,
                    MAX_NUM_INSTRUCTIONS,
                    MAX_SUBNET_AVAILABLE_MEMORY.clone(),
                )
                .1
                .unwrap();

            let (instructions_left, result) = canister_manager.install_code(
                InstallCodeContext {
                    sender,
                    canister_id,
                    wasm_module: upgrade_wasm,
                    arg: vec![],
                    compute_allocation: None,
                    memory_allocation: None,
                    mode: CanisterInstallMode::Upgrade,
                    query_allocation: QueryAllocation::default(),
                },
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
            assert!(
                MAX_NUM_INSTRUCTIONS - instructions_left == NumInstructions::from(1),
                "initial instructions {} left {} diff {}",
                MAX_NUM_INSTRUCTIONS,
                instructions_left,
                MAX_NUM_INSTRUCTIONS - instructions_left
            );
            assert_matches!(result, Err(CanisterManagerError::Hypervisor(_, _)));
        })
    }
    let initial_wasm = r#"
    (module
        (func $canister_pre_upgrade
          unreachable
        )
        (memory $memory 1)
        (export "canister_pre_upgrade" (func $canister_pre_upgrade))
    )"#;
    let initial_wasm = wabt::wat2wasm(initial_wasm).unwrap();
    let upgrade_wasm = r#"
    (module
        (memory $memory 1)
    )"#;
    let upgrade_wasm = wabt::wat2wasm(upgrade_wasm).unwrap();
    run(initial_wasm, upgrade_wasm);

    let initial_wasm = r#"
    (module
        (memory $memory 1)
    )"#;
    let initial_wasm = wabt::wat2wasm(initial_wasm).unwrap();
    let upgrade_wasm = r#"
    (module
        (func $canister_post_upgrade
          unreachable
        )
        (memory $memory 1)
        (export "canister_post_upgrade" (func $canister_post_upgrade))
    )"#;
    let upgrade_wasm = wabt::wat2wasm(upgrade_wasm).unwrap();
    run(initial_wasm, upgrade_wasm);

    let initial_wasm = r#"
    (module
        (memory $memory 1)
    )"#;
    let initial_wasm = wabt::wat2wasm(initial_wasm).unwrap();
    let upgrade_wasm = r#"
    (module
        (func $start
          unreachable
        )
        (memory $memory 1)
        (start $start)
    )"#;
    let upgrade_wasm = wabt::wat2wasm(upgrade_wasm).unwrap();
    run(initial_wasm, upgrade_wasm);
}

#[test]
fn failed_install_hooks_consume_instructions() {
    fn run(wasm: Vec<u8>) {
        with_test_replica_logger(|log| {
            let subnet_id = subnet_test_id(1);
            let subnet_type = SubnetType::Application;
            let metrics_registry = MetricsRegistry::new();
            let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
            let hypervisor = Arc::new(Hypervisor::new(
                Config::default(),
                1,
                &metrics_registry,
                subnet_id,
                subnet_type,
                log.clone(),
                Arc::clone(&cycles_account_manager),
            ));
            let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
                log.clone(),
                &metrics_registry,
            ));
            let canister_manager = CanisterManager::new(
                Arc::clone(&hypervisor) as Arc<_>,
                1,
                subnet_id,
                subnet_type,
                log,
                canister_manager_config(),
                cycles_account_manager,
                ingress_history_writer,
            );
            let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
            let mut state = initial_state(tmpdir.path(), subnet_id);
            let sender = canister_test_id(100).get();
            let canister_id = canister_manager
                .create_canister(
                    sender,
                    subnet_id,
                    Funds::new(*INITIAL_CYCLES, ICP::zero()),
                    CanisterSettings::default(),
                    &mut state,
                )
                .0
                .unwrap();

            let (instructions_left, result) = canister_manager.install_code(
                InstallCodeContext {
                    sender,
                    canister_id,
                    wasm_module: wasm,
                    arg: vec![],
                    compute_allocation: None,
                    memory_allocation: None,
                    mode: CanisterInstallMode::Install,
                    query_allocation: QueryAllocation::default(),
                },
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            );
            assert_matches!(result, Err(CanisterManagerError::Hypervisor(_, _)));
            assert!(
                MAX_NUM_INSTRUCTIONS - instructions_left == NumInstructions::from(1),
                "initial instructions {} left {} diff {}",
                MAX_NUM_INSTRUCTIONS,
                instructions_left,
                MAX_NUM_INSTRUCTIONS - instructions_left
            );
        })
    }

    let wasm = r#"
    (module
        (func $start
          unreachable
        )
        (memory $memory 1)
        (start $start)
    )"#;
    let wasm = wabt::wat2wasm(wasm).unwrap();
    run(wasm);
    let wasm = r#"
    (module
        (func $canister_init
          unreachable
        )
        (memory $memory 1)
        (export "canister_init" (func $canister_init))
    )"#;
    let wasm = wabt::wat2wasm(wasm).unwrap();
    run(wasm);
}

#[test]
fn install_code_preserves_system_state_and_scheduler_state() {
    let canister_manager = CanisterManagerBuilder::default()
        .with_cycles_account_manager(
            CyclesAccountManagerBuilder::new()
                // Make it free so we don't have to worry about cycles when
                // making assertions.
                .with_update_message_execution_fee(Cycles::from(0))
                .with_ten_update_instructions_execution_fee(Cycles::from(0))
                .build(),
        )
        .build();

    let controller = canister_test_id(123);
    let canister_id = canister_test_id(456);

    // Create a canister with various attributes to later ensure they are preserved.
    let original_canister = CanisterStateBuilder::new()
        .with_canister_id(canister_id)
        .with_status(CanisterStatusType::Running)
        .with_controller(controller)
        .with_call_context(CallContextBuilder::new().build())
        .with_input(RequestOrResponse::Request(
            RequestBuilder::default().receiver(canister_id).build(),
        ))
        .build();

    let mut state = ReplicatedStateBuilder::new()
        .with_canister(original_canister.clone())
        .build();

    // 1. INSTALL

    let (instructions_left, res) = canister_manager.install_code(
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Install)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        MAX_NUM_INSTRUCTIONS,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    );

    // Installation is free, since there is no `(start)` or `canister_init` to run.
    assert_eq!(instructions_left, MAX_NUM_INSTRUCTIONS);

    // No heap delta.
    assert_eq!(res.unwrap(), NumBytes::from(0));

    // Verify the system state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().system_state,
        original_canister.system_state
    );

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );

    // 2. REINSTALL

    let (instructions_left, res) = canister_manager.install_code(
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Reinstall)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        MAX_NUM_INSTRUCTIONS,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    );

    // Installation is free, since there is no `(start)` or `canister_init` to run.
    assert!(instructions_left == MAX_NUM_INSTRUCTIONS);

    // No heap delta.
    assert_eq!(res.unwrap(), NumBytes::from(0));

    // Verify the system state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().system_state,
        original_canister.system_state
    );

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );

    // 3. UPGRADE

    let (instructions_left, res) = canister_manager.install_code(
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Upgrade)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        MAX_NUM_INSTRUCTIONS,
        MAX_SUBNET_AVAILABLE_MEMORY.clone(),
    );

    // Installation is free, since there is no `canister_pre/post_upgrade`
    assert!(instructions_left == MAX_NUM_INSTRUCTIONS);

    // No heap delta.
    assert_eq!(res.unwrap(), NumBytes::from(0));

    // Verify the system state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().system_state,
        original_canister.system_state
    );

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );
}

#[test]
fn lowering_memory_allocation_than_usage_fails() {
    let wasm = r#"
    (module
        (memory $memory 1)
    )"#;
    let wasm = wabt::wat2wasm(wasm).unwrap();
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Arc::new(Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        ));
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let sender = canister_test_id(100).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                CanisterSettings::default(),
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContext {
                    sender,
                    canister_id,
                    wasm_module: wasm.clone(),
                    arg: vec![],
                    compute_allocation: None,
                    memory_allocation: None,
                    mode: CanisterInstallMode::Install,
                    query_allocation: QueryAllocation::default(),
                },
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();

        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(2)).unwrap()),
            None,
        );

        assert_matches!(
            canister_manager.update_settings(sender, canister_id, settings, &mut state),
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    })
}

#[test]
fn lowering_memory_allocation_than_usage_install_fails() {
    let wasm = ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec();
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Arc::new(Hypervisor::new(
            Config::default(),
            1,
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        ));
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            1,
            subnet_id,
            subnet_type,
            log,
            canister_manager_config(),
            cycles_account_manager,
            ingress_history_writer,
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let mut state = initial_state(tmpdir.path(), subnet_id);
        let sender = canister_test_id(100).get();
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(2)).unwrap()),
            None,
        );
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                Funds::new(*INITIAL_CYCLES, ICP::zero()),
                settings,
                &mut state,
            )
            .0
            .unwrap();

        canister_manager
            .install_code(
                InstallCodeContext {
                    sender,
                    canister_id,
                    wasm_module: wasm.clone(),
                    arg: vec![],
                    compute_allocation: None,
                    memory_allocation: None,
                    mode: CanisterInstallMode::Install,
                    query_allocation: QueryAllocation::default(),
                },
                &mut state,
                MAX_NUM_INSTRUCTIONS,
                MAX_SUBNET_AVAILABLE_MEMORY.clone(),
            )
            .1
            .unwrap();
    })
}
