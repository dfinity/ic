use crate::{
    as_num_instructions,
    canister_manager::{
        uninstall_canister, CanisterManager, CanisterManagerError, CanisterMgrConfig,
        InstallCodeContext, StopCanisterResult,
    },
    canister_settings::CanisterSettings,
    execution::test_utilities::{
        get_reply, get_routing_table_with_specified_ids_allocation_range, wasm_compilation_cost,
        wat_compilation_cost, ExecutionTest, ExecutionTestBuilder,
    },
    execution_environment::as_round_instructions,
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
    IngressHistoryWriterImpl, RoundLimits,
};
use assert_matches::assert_matches;
use candid::Decode;
use ic_base_types::{NumSeconds, PrincipalId};
use ic_config::{
    execution_environment::Config, flag_status::FlagStatus, subnet_config::SchedulerConfig,
};
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgs, CanisterStatusType,
    CreateCanisterArgs, EmptyBlob, InstallCodeArgs, Method, Payload, UpdateSettingsArgs,
};
use ic_interfaces::{
    execution_environment::{ExecutionMode, HypervisorError, SubnetAvailableMemory},
    messages::RequestOrIngress,
};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map, testing::CanisterQueuesTesting, CallContextManager, CallOrigin, CanisterState,
    CanisterStatus, NumWasmPages, PageMap, ReplicatedState,
};
use ic_system_api::{ExecutionParameters, InstructionLimits};
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
        messages::{IngressBuilder, RequestBuilder, SignedIngressBuilder},
    },
    universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM},
};
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, StopCanisterContext},
    nominal_cycles::NominalCycles,
    CanisterId, CanisterTimer, ComputeAllocation, Cycles, MemoryAllocation, NumBytes,
    NumInstructions, QueryAllocation, SubnetId, UserId,
};
use ic_wasm_types::{CanisterModule, WasmValidationError};
use lazy_static::lazy_static;
use maplit::{btreemap, btreeset};
use std::{collections::BTreeSet, convert::TryFrom, sync::Arc};

use super::InstallCodeResult;
use prometheus::IntCounter;

const CANISTER_CREATION_FEE: Cycles = Cycles::new(100_000_000_000);
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const DEFAULT_PROVISIONAL_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const MEMORY_CAPACITY: NumBytes = NumBytes::new(8 * 1024 * 1024 * 1024); // 8GiB
const MAX_CONTROLLERS: usize = 10;
const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64KiB
const MAX_NUMBER_OF_CANISTERS: u64 = 0;
// The simplest valid WASM binary: "(module)"
const MINIMAL_WASM: [u8; 8] = [
    0, 97, 115, 109, // \0ASM - magic
    1, 0, 0, 0, //  0x01 - version
];

lazy_static! {
    static ref MAX_SUBNET_AVAILABLE_MEMORY: SubnetAvailableMemory =
        SubnetAvailableMemory::new(i64::MAX / 2, i64::MAX / 2);
    static ref INITIAL_CYCLES: Cycles =
        CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);
    static ref EXECUTION_PARAMETERS: ExecutionParameters = ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            FlagStatus::Disabled,
            MAX_NUM_INSTRUCTIONS,
            MAX_NUM_INSTRUCTIONS
        ),
        canister_memory_limit: NumBytes::new(u64::MAX / 2),
        compute_allocation: ComputeAllocation::default(),
        subnet_type: SubnetType::Application,
        execution_mode: ExecutionMode::Replicated,
    };
}

pub struct InstallCodeContextBuilder {
    ctx: InstallCodeContext,
}

impl InstallCodeContextBuilder {
    pub fn sender(mut self, sender: PrincipalId) -> Self {
        self.ctx.sender = sender;
        self
    }

    pub fn canister_id(mut self, canister_id: CanisterId) -> Self {
        self.ctx.canister_id = canister_id;
        self
    }

    pub fn wasm_module(mut self, wasm_module: Vec<u8>) -> Self {
        self.ctx.wasm_module = CanisterModule::new(wasm_module);
        self
    }

    #[allow(dead_code)]
    pub fn arg(mut self, arg: Vec<u8>) -> Self {
        self.ctx.arg = arg;
        self
    }

    pub fn compute_allocation(mut self, compute_allocation: ComputeAllocation) -> Self {
        self.ctx.compute_allocation = Some(compute_allocation);
        self
    }

    pub fn memory_allocation(mut self, memory_allocation: MemoryAllocation) -> Self {
        self.ctx.memory_allocation = Some(memory_allocation);
        self
    }

    pub fn query_allocation(mut self, query_allocation: QueryAllocation) -> Self {
        self.ctx.query_allocation = query_allocation;
        self
    }

    pub fn mode(mut self, mode: CanisterInstallMode) -> Self {
        self.ctx.mode = mode;
        self
    }

    pub fn build(&self) -> InstallCodeContext {
        self.ctx.clone()
    }
}

impl Default for InstallCodeContextBuilder {
    fn default() -> Self {
        Self {
            ctx: InstallCodeContext {
                sender: PrincipalId::new_user_test_id(0),
                canister_id: canister_test_id(0),
                wasm_module: CanisterModule::new(wabt::wat2wasm(EMPTY_WAT).unwrap()),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
        }
    }
}

struct CanisterManagerBuilder {
    cycles_account_manager: CyclesAccountManager,
    subnet_id: SubnetId,
    rate_limiting_of_instructions: FlagStatus,
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
            Config::default(),
            no_op_logger(),
            &metrics_registry,
        ));
        let cycles_account_manager = Arc::new(self.cycles_account_manager);
        let hypervisor = Hypervisor::new(
            Config::default(),
            &metrics_registry,
            self.subnet_id,
            subnet_type,
            no_op_logger(),
            Arc::clone(&cycles_account_manager),
            SchedulerConfig::application_subnet().dirty_page_overhead,
        );
        let hypervisor = Arc::new(hypervisor);
        CanisterManager::new(
            hypervisor,
            no_op_logger(),
            canister_manager_config(
                self.subnet_id,
                subnet_type,
                self.rate_limiting_of_instructions,
            ),
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
            rate_limiting_of_instructions: FlagStatus::Disabled,
        }
    }
}

fn canister_manager_config(
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    rate_limiting_of_instructions: FlagStatus,
) -> CanisterMgrConfig {
    CanisterMgrConfig::new(
        MEMORY_CAPACITY,
        DEFAULT_PROVISIONAL_BALANCE,
        NumSeconds::from(100_000),
        subnet_id,
        subnet_type,
        MAX_CONTROLLERS,
        // Compute capacity for 2-core scheduler is 100%
        // TODO(RUN-319): the capacity should be defined based on actual `scheduler_cores`
        100,
        rate_limiting_of_instructions,
        100,
    )
}

fn initial_state(subnet_id: SubnetId, use_specified_ids_routing_table: bool) -> ReplicatedState {
    let mut state = ReplicatedState::new(subnet_id, SubnetType::Application);

    state.metadata.network_topology.routing_table = if use_specified_ids_routing_table {
        let routing_table =
            get_routing_table_with_specified_ids_allocation_range(subnet_id).unwrap();
        Arc::new(routing_table)
    } else {
        Arc::new(
            RoutingTable::try_from(btreemap! {
                CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(CANISTER_IDS_PER_SUBNET - 1) } => subnet_id,
            })
            .unwrap(),
        )
    };

    state.metadata.network_topology.nns_subnet_id = subnet_id;
    state.metadata.init_allocation_ranges_if_empty().unwrap();
    state
}

fn install_code(
    canister_manager: &CanisterManager,
    context: InstallCodeContext,
    state: &mut ReplicatedState,
    round_limits: &mut RoundLimits,
) -> (
    NumInstructions,
    Result<InstallCodeResult, CanisterManagerError>,
    Option<CanisterState>,
) {
    let instruction_limit = NumInstructions::new(round_limits.instructions.get() as u64);
    let execution_parameters = ExecutionParameters {
        instruction_limits: InstructionLimits::new(
            FlagStatus::Disabled,
            instruction_limit,
            instruction_limit,
        ),
        ..EXECUTION_PARAMETERS.clone()
    };

    let args = InstallCodeArgs::new(
        context.mode,
        context.canister_id,
        context.wasm_module.as_slice().into(),
        context.arg.clone(),
        None,
        None,
        None,
    );
    let ingress = IngressBuilder::new()
        .source(UserId::from(context.sender))
        .receiver(CanisterId::ic_00())
        .method_name(Method::InstallCode)
        .method_payload(args.encode())
        .build();
    let no_op_counter: IntCounter = IntCounter::new("no_op", "no_op").unwrap();
    let (result, instructions_used, canister) = canister_manager.install_code(
        context,
        RequestOrIngress::Ingress(Arc::new(ingress)),
        state,
        execution_parameters,
        round_limits,
        &no_op_counter,
        SMALL_APP_SUBNET_MAX_SIZE,
    );
    let instructions_left = instruction_limit - instructions_used.min(instruction_limit);
    (instructions_left, result, canister)
}

fn with_setup<F>(f: F)
where
    F: FnOnce(CanisterManager, ReplicatedState, SubnetId),
{
    let subnet_id = subnet_test_id(1);
    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .build();
    f(canister_manager, initial_state(subnet_id, false), subnet_id)
}

#[test]
fn install_canister_makes_subnet_oversubscribed() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let compute_allocation_used = state.total_compute_allocation();
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used,
        };
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        let canister_id2 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        let canister_id3 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id1)
                .compute_allocation(ComputeAllocation::try_from(50).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id2)
                .compute_allocation(ComputeAllocation::try_from(25).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        let instructions_left = as_num_instructions(round_limits.instructions);
        let (num_instructions, res, canister) = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id3)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .compute_allocation(ComputeAllocation::try_from(30).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert_eq!(
            (num_instructions, res),
            (
                instructions_left,
                Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: ComputeAllocation::try_from(30).unwrap(),
                    available: 24
                })
            )
        );

        // Canister state should still be returned.
        assert_eq!(canister.unwrap().canister_id(), canister_id3);
    });
}

#[test]
fn upgrade_non_existing_canister_fails() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_test_id(0);
        assert_eq!(
            install_code(
                &canister_manager,
                InstallCodeContextBuilder::default()
                    .mode(CanisterInstallMode::Upgrade)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .build(),
                &mut state,
                &mut round_limits,
            ),
            (
                MAX_NUM_INSTRUCTIONS,
                Err(CanisterManagerError::CanisterNotFound(canister_id)),
                None
            )
        );
    });
}

#[test]
fn upgrade_canister_with_no_wasm_fails() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .mode(CanisterInstallMode::Upgrade)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert_eq!(
            (res.0, res.1),
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                Cycles::new(2_000_000_000_000_000),
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Install the canister with allocation of 60%.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id1)
                .compute_allocation(ComputeAllocation::try_from(60).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        assert_eq!(
            state
                .canister_state(&canister_id1)
                .unwrap()
                .scheduler_state
                .compute_allocation,
            ComputeAllocation::try_from(60).unwrap()
        );

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id1)
                .compute_allocation(ComputeAllocation::try_from(80).unwrap())
                .mode(CanisterInstallMode::Upgrade)
                .build(),
            &mut state,
            &mut round_limits,
        );
        // Upgrade the canister to allocation of 80%.
        assert!(res.1.is_ok());

        assert_eq!(res.2.as_ref().unwrap().canister_id(), canister_id1);
        assert_eq!(
            res.2.unwrap().scheduler_state.compute_allocation,
            ComputeAllocation::try_from(80).unwrap()
        );
    });
}

#[test]
fn upgrading_canister_makes_subnet_oversubscribed() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(27).get();
        let sender_subnet_id = subnet_test_id(1);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let initial_cycles = Cycles::new(30_000_000_000_000);
        let canister_id1 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                initial_cycles,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        let canister_id2 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                initial_cycles,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        let canister_id3 = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                initial_cycles,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id1)
                .compute_allocation(ComputeAllocation::try_from(50).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        state.put_canister_state(res.2.unwrap());
        assert!(res.1.is_ok());

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id2)
                .compute_allocation(ComputeAllocation::try_from(25).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        state.put_canister_state(res.2.unwrap());
        assert!(res.1.is_ok());

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id3)
                .compute_allocation(ComputeAllocation::try_from(20).unwrap())
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        let instructions_left = as_num_instructions(round_limits.instructions);
        let res = install_code(
            &canister_manager,
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
            &mut round_limits,
        );
        assert_eq!(
            (res.0, res.1),
            (
                instructions_left,
                Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: ComputeAllocation::try_from(30).unwrap(),
                    available: 24,
                })
            )
        );

        state.put_canister_state(res.2.unwrap());

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
    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let mb = 1 << 20;
    let memory_capacity = 1000 * mb;
    let memory_used = memory_capacity - 10 * mb;

    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 160)))
            )
            (memory 0)
        )"#;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(memory_capacity as i64)
        .build();

    let wasm = wabt::wat2wasm(wat).unwrap();

    let canister1 = test.create_canister(initial_cycles);
    let canister2 = test.create_canister(initial_cycles);

    test.install_canister_with_allocation(canister1, wasm.clone(), None, Some(memory_used))
        .unwrap();

    let execution_cost_before = test.canister_execution_cost(canister2);
    let err = test
        .install_canister_with_allocation(canister2, wasm.clone(), None, Some(11 * mb))
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
    assert_eq!(err.description(), "Canister with memory allocation 11MiB cannot be installed because the Subnet's remaining memory capacity is 10MiB");
    // The memory allocation is validated first before charging the fee.
    assert_eq!(
        test.canister_state(canister2).system_state.balance(),
        initial_cycles - (test.canister_execution_cost(canister2) - execution_cost_before),
    );

    // Try installing without any memory allocation.
    let err = test
        .install_canister_with_allocation(canister2, wasm, None, None)
        .unwrap_err();
    let execution_cost_after = test.canister_execution_cost(canister2);
    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
    assert_eq!(err.description(), "Canister with memory allocation 10MiB cannot be installed because the Subnet's remaining memory capacity is 10MiB");

    assert_eq!(
        test.canister_state(canister2).system_state.balance(),
        initial_cycles - (execution_cost_after - execution_cost_before)
    );
}

#[test]
fn can_update_memory_allocation_during_upgrade() {
    with_setup(|canister_manager, mut state, _| {
        let sender = canister_test_id(13).get();
        let sender_subnet_id = subnet_test_id(1);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: SubnetAvailableMemory::new(
                MEMORY_CAPACITY.get() as i64,
                MEMORY_CAPACITY.get() as i64,
            ),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let initial_memory_allocation =
            MemoryAllocation::try_from(NumBytes::from(1 << 30)).unwrap();
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .memory_allocation(initial_memory_allocation)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .memory_allocation(),
            initial_memory_allocation
        );

        let final_memory_allocation = MemoryAllocation::try_from(NumBytes::from(2 << 30)).unwrap();
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .memory_allocation(final_memory_allocation)
                .mode(CanisterInstallMode::Upgrade)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        assert_eq!(
            state
                .canister_state(&canister_id)
                .unwrap()
                .memory_allocation(),
            final_memory_allocation,
        );
    });
}

#[test]
fn install_code_preserves_messages() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
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
                (
                    SignedIngressBuilder::new()
                        .canister_id(canister_test_id(canister_id))
                        .nonce(i)
                        .build(),
                    None,
                )
                    .into(),
            );
        }
        state.put_canister_state(canister_state_builder.build());

        // Install the canister with new wasm.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_test_id(0))
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Check the ingress messages are still in the queue.
        let canister = state
            .canister_state(&canister_test_id(0))
            .expect("Failed to find the canister");
        assert_eq!(
            canister.system_state.queues().ingress_queue_size() as u64,
            num_messages
        );
    });
}

#[test]
fn can_create_canister() {
    with_setup(|canister_manager, mut state, _| {
        let canister = canister_test_id(50).get();
        let sender_subnet_id = subnet_test_id(1);
        let expected_generated_id1 = CanisterId::from(0);
        let expected_generated_id2 = CanisterId::from(1);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        assert_eq!(
            canister_manager
                .create_canister(
                    canister,
                    sender_subnet_id,
                    *INITIAL_CYCLES,
                    CanisterSettings::default(),
                    MAX_NUMBER_OF_CANISTERS,
                    &mut state,
                    SMALL_APP_SUBNET_MAX_SIZE,
                    &mut round_limits,
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
                    *INITIAL_CYCLES,
                    CanisterSettings::default(),
                    MAX_NUMBER_OF_CANISTERS,
                    &mut state,
                    SMALL_APP_SUBNET_MAX_SIZE,
                    &mut round_limits,
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };

        assert_eq!(
            canister_manager.create_canister(
                canister,
                sender_subnet_id,
                Cycles::new(100),
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            ),
            (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: Cycles::new(100),
                    required: CANISTER_CREATION_FEE
                }),
                Cycles::new(100),
            ),
        );
        assert_eq!(state.canister_states.len(), 0);
    });
}

#[test]
fn can_create_canister_with_extra_cycles() {
    with_setup(|canister_manager, mut state, _| {
        let canister = canister_test_id(30).get();
        let sender_subnet_id = subnet_test_id(1);
        let expected_generated_id1 = CanisterId::from(0);
        let cycles: u64 = 1_000_000_000_200;
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        assert_eq!(
            canister_manager
                .create_canister(
                    canister,
                    sender_subnet_id,
                    Cycles::from(cycles),
                    CanisterSettings::default(),
                    MAX_NUMBER_OF_CANISTERS,
                    &mut state,
                    SMALL_APP_SUBNET_MAX_SIZE,
                    &mut round_limits,
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Install a wasm module. Should succeed.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        let instructions_left = as_num_instructions(round_limits.instructions);
        // Install again. Should fail.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        state.put_canister_state(res.2.unwrap());
        assert_eq!(
            (res.0, res.1),
            (
                instructions_left,
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        // Create a canister with canister_test_id 1 as controller.
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        for mode in CanisterInstallMode::iter() {
            // Try to install_code with canister_test_id 2. Should fail.
            let res = install_code(
                &canister_manager,
                InstallCodeContextBuilder::default()
                    .sender(canister_test_id(2).get())
                    .canister_id(canister_id)
                    .wasm_module(
                        ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                    )
                    .mode(*mode)
                    .build(),
                &mut state,
                &mut round_limits,
            );
            state.put_canister_state(res.2.unwrap());
            assert_eq!(
                (res.0, res.1),
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };

        let mem_alloc = MemoryAllocation::Reserved(NumBytes::new(1024 * 1024 * 1024));
        let compute_alloc = ComputeAllocation::try_from(50).unwrap();
        let settings = CanisterSettings {
            compute_allocation: Some(compute_alloc),
            memory_allocation: Some(mem_alloc),
            ..Default::default()
        };
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                *INITIAL_CYCLES,
                settings,
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let canister = state.canister_state(&canister_id).unwrap();
        assert_eq!(canister.memory_allocation(), mem_alloc);
        assert_eq!(canister.scheduler_state.compute_allocation, compute_alloc);
    });
}

#[test]
fn create_canister_updates_consumed_cycles_metric_correctly() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_manager
            .create_canister(
                canister_test_id(1).get(),
                subnet_test_id(1),
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let creation_fee = cycles_account_manager.canister_creation_fee(SMALL_APP_SUBNET_MAX_SIZE);
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
            canister.system_state.balance(),
            *INITIAL_CYCLES - creation_fee
        )
    });
}

#[test]
fn provisional_create_canister_has_no_creation_fee() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_manager
            .create_canister_with_cycles(
                canister_test_id(1).get(),
                Some(INITIAL_CYCLES.get()),
                CanisterSettings::default(),
                None,
                &mut state,
                &ProvisionalWhitelist::All,
                MAX_NUMBER_OF_CANISTERS,
                &mut round_limits,
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
        assert_eq!(canister.system_state.balance(), *INITIAL_CYCLES)
    });
}

#[test]
fn reinstall_on_empty_canister_succeeds() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(42).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_test_id(1),
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Reinstalling an empty canister should succeed.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .mode(CanisterInstallMode::Reinstall)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

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

const EMPTY_WAT: &str = r#"(module (memory $memory 1 1000))"#;

#[test]
fn reinstall_calls_canister_start_and_canister_init() {
    let mut test = ExecutionTestBuilder::new().build();

    // install wasm module with no exported functions
    let id = test
        .canister_from_cycles_and_wat(*INITIAL_CYCLES, EMPTY_WAT)
        .unwrap();

    let wasm = wabt::wat2wasm(COUNTER_WAT).unwrap();
    test.reinstall_canister(id, wasm).unwrap();
    // If canister_start and canister_init were called, then the counter
    // should be initialized to 42.
    let reply = test.ingress(id, "read", vec![]);
    assert_eq!(reply, Ok(WasmResult::Reply(vec![42, 0, 0, 0])));
}

#[test]
fn install_calls_canister_start_and_canister_init() {
    let mut test = ExecutionTestBuilder::new().build();

    let id = test
        .canister_from_cycles_and_wat(*INITIAL_CYCLES, COUNTER_WAT)
        .unwrap();

    // If canister_start and canister_init were called, then the counter
    // should be initialized to 42.
    let reply = test.ingress(id, "read", vec![]);
    assert_eq!(reply, Ok(WasmResult::Reply(vec![42, 0, 0, 0])));
}

#[test]
fn install_puts_canister_back_after_invalid_wasm() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        // Use an invalid wasm code (import memory from an invalid module).
        let wasm =
            wabt::wat2wasm(r#"(module (import "foo" "memory" (memory (;0;) 529)))"#).unwrap();
        let wasm_len = wasm.len();

        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Installation should be rejected.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(wasm)
                .build(),
            &mut state,
            &mut round_limits,
        );
        state.put_canister_state(res.2.unwrap());
        assert_eq!(
            (res.0, res.1),
            (
                MAX_NUM_INSTRUCTIONS
                    - Config::default().cost_to_compile_wasm_instruction * wasm_len as u64,
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Write something into the canister's stable memory.
        let mut canister = state.take_canister_state(&canister_id).unwrap();
        assert_eq!(
            canister
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .size,
            NumWasmPages::new(0)
        );
        canister
            .execution_state
            .as_mut()
            .unwrap()
            .stable_memory
            .size = NumWasmPages::new(1);
        let mut buf = page_map::Buffer::new(PageMap::default());
        buf.write(&[1; 10], 0);
        canister
            .execution_state
            .as_mut()
            .unwrap()
            .stable_memory
            .page_map
            .update(&buf.dirty_pages().collect::<Vec<_>>());

        state.put_canister_state(canister);

        // Reinstall the canister.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .mode(CanisterInstallMode::Reinstall)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Stable memory should now be empty.
        let canister = state.take_canister_state(&canister_id).unwrap();
        assert_eq!(
            canister
                .execution_state
                .as_ref()
                .unwrap()
                .stable_memory
                .size,
            NumWasmPages::new(0)
        );
    });
}

#[test]
fn stop_a_running_canister() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1);
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender.get(),
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
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
            cycles: Cycles::zero(),
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
                cycles_to_return: Cycles::zero()
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

        let cycles = 20u128;
        let stop_context = StopCanisterContext::Canister {
            sender: controller,
            reply_callback: CallbackId::from(0),
            cycles: Cycles::from(cycles),
        };
        assert_eq!(
            canister_manager.stop_canister(canister_id, stop_context, &mut state),
            StopCanisterResult::AlreadyStopped {
                cycles_to_return: Cycles::from(cycles)
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let msg_id = message_test_id(0);
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
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
                cycles_to_return: Cycles::zero(),
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
                cycles_to_return: Cycles::zero(),
                error: CanisterManagerError::CanisterNotFound(canister_id),
            }
        );
    });
}

#[test]
fn start_a_canister_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Start the canister by a sender who isn't the controller.
        let other_sender = user_test_id(1).get();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_eq!(
            canister_manager.start_canister(other_sender, canister),
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(42).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
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
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister_manager.start_canister(sender, canister).unwrap();

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
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister_manager.start_canister(sender, canister).unwrap();

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

        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_eq!(
            canister_manager.start_canister(sender, canister),
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

        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_eq!(
            canister_manager.start_canister(sender, canister),
            Ok(vec![stop_context])
        );
    });
}

#[test]
fn get_canister_status_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Get the status of the canister by a sender who isn't the controller.
        let other_sender = user_test_id(1).get();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_eq!(
            canister_manager.get_canister_status(other_sender, canister, SMALL_APP_SUBNET_MAX_SIZE),
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let canister = state.canister_state_mut(&canister_id).unwrap();
        let status = canister_manager
            .get_canister_status(sender, canister, SMALL_APP_SUBNET_MAX_SIZE)
            .unwrap()
            .status();
        assert_eq!(status, CanisterStatusType::Running);
    });
}

#[test]
fn get_canister_status_of_self() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let canister = state.canister_state_mut(&canister_id).unwrap();
        let status = canister_manager
            .get_canister_status(canister_id.get(), canister, SMALL_APP_SUBNET_MAX_SIZE)
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

        let canister = state.canister_state_mut(&canister_id).unwrap();
        let status = canister_manager
            .get_canister_status(sender, canister, SMALL_APP_SUBNET_MAX_SIZE)
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

        let canister = state.canister_state_mut(&canister_id).unwrap();
        let status = canister_manager
            .get_canister_status(sender, canister, SMALL_APP_SUBNET_MAX_SIZE)
            .unwrap()
            .status();
        assert_eq!(status, CanisterStatusType::Stopping);
    });
}

#[test]
fn set_controller_with_incorrect_controller() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
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
                &mut state,
                &mut round_limits,
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
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let canister_id = canister_test_id(0);
        let canister = get_running_canister(canister_id);
        state.put_canister_state(canister);

        let controller = user_test_id(1).get();
        let new_controller = user_test_id(2).get();

        // Set the controller from the correct controller. Should succeed.
        assert!(canister_manager
            .set_controller(
                controller,
                canister_id,
                new_controller,
                &mut state,
                &mut round_limits
            )
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
    });
}

#[test]
fn install_canister_with_query_allocation() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        let query_allocation = QueryAllocation::try_from(50).unwrap();
        assert!(install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .query_allocation(query_allocation)
                .build(),
            &mut state,
            &mut round_limits,
        )
        .1
        .is_ok());
    });
}

#[test]
fn deposit_cycles_succeeds_with_enough_cycles() {
    with_setup(|canister_manager, _, _| {
        let canister_id = canister_test_id(0);
        let sender = canister_test_id(1).get();
        let mut canister = get_running_canister_with_args(canister_id, sender, *INITIAL_CYCLES);

        let cycles_balance_before = canister.system_state.balance();
        let cycles = Cycles::new(100);

        canister_manager
            .cycles_account_manager
            .add_cycles(canister.system_state.balance_mut(), cycles);

        // Assert that state has changed
        assert_eq!(
            canister.system_state.balance(),
            cycles_balance_before + cycles,
        );
    });
}

#[test]
fn create_canister_with_cycles_sender_in_whitelist() {
    let subnet_id = subnet_test_id(1);
    let subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(subnet_type)
        .build();

    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .with_cycles_account_manager(cycles_account_manager)
        .build();

    let mut state = initial_state(subnet_id, false);
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions((*EXECUTION_PARAMETERS).instruction_limits.message()),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let sender = canister_test_id(1).get();
    let canister_id = canister_manager
        .create_canister_with_cycles(
            sender,
            Some(123),
            CanisterSettings::default(),
            None,
            &mut state,
            &ProvisionalWhitelist::Set(btreeset! { canister_test_id(1).get() }),
            MAX_NUMBER_OF_CANISTERS,
            &mut round_limits,
        )
        .unwrap();

    let canister = state.take_canister_state(&canister_id).unwrap();

    // Verify cycles are set as expected.
    assert_eq!(canister.system_state.balance(), Cycles::new(123));
}

fn create_canister_with_specified_id(
    specified_id: PrincipalId,
) -> (Result<CanisterId, CanisterManagerError>, ReplicatedState) {
    let subnet_id = subnet_test_id(1);
    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .build();

    let mut state = initial_state(subnet_id, true);
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions((*EXECUTION_PARAMETERS).instruction_limits.message()),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };

    let creator = canister_test_id(1).get();

    let creation_result = canister_manager.create_canister_with_cycles(
        creator,
        Some(123),
        CanisterSettings::default(),
        Some(specified_id),
        &mut state,
        &ProvisionalWhitelist::Set(btreeset! { canister_test_id(1).get() }),
        MAX_NUMBER_OF_CANISTERS,
        &mut round_limits,
    );

    (creation_result, state)
}

#[test]
fn create_canister_with_valid_specified_id_creator_in_whitelist() {
    let specified_id = CanisterId::from(u64::MAX / 4).get();

    let (creation_result, mut state) = create_canister_with_specified_id(specified_id);

    let canister_id = creation_result.unwrap();

    let canister = state.take_canister_state(&canister_id).unwrap();

    // Verify canister ID is set as expected.
    assert_eq!(canister.canister_id().get(), specified_id);
}

#[test]
fn create_canister_with_invalid_specified_id_creator_in_whitelist() {
    let specified_id = CanisterId::from(u64::MAX / 4 * 3).get();

    let creation_result = create_canister_with_specified_id(specified_id).0;

    assert_matches!(
        creation_result,
        Err(CanisterManagerError::CanisterNotHostedBySubnet { .. })
    );
}

#[test]
fn can_get_canister_balance() {
    with_setup(|canister_manager, mut state, _| {
        let canister_id = canister_test_id(0);
        let sender = canister_test_id(1).get();
        let cycles = Cycles::new(100);
        let canister = get_running_canister_with_args(canister_id, sender, cycles);
        state.put_canister_state(canister);

        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_matches!(
            canister_manager.get_canister_status( sender, canister, SMALL_APP_SUBNET_MAX_SIZE),
            Ok(res) if res.cycles() == cycles.get()
        );
    });
}

#[test]
fn add_cycles_sender_in_whitelist() {
    let subnet_id = subnet_test_id(1);
    let subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(subnet_type)
        .build();

    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .with_cycles_account_manager(cycles_account_manager)
        .build();

    let canister_id = canister_test_id(0);
    let canister = get_running_canister(canister_id);
    let sender = canister_test_id(1).get();

    let mut state = initial_state(subnet_id, false);
    let initial_cycles = canister.system_state.balance();
    state.put_canister_state(canister);

    let canister = state.canister_state_mut(&canister_id).unwrap();
    canister_manager
        .add_cycles(
            sender,
            Some(123),
            canister,
            &ProvisionalWhitelist::Set(btreeset! { canister_test_id(1).get() }),
        )
        .unwrap();

    // Verify cycles are set as expected.
    let canister = state.take_canister_state(&canister_id).unwrap();
    assert_eq!(
        canister.system_state.balance(),
        initial_cycles + Cycles::new(123),
    );
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
        let canister = state.canister_state_mut(&canister_id).unwrap();
        assert_eq!(
            canister_manager.add_cycles(
                sender,
                Some(123),
                canister,
                &ProvisionalWhitelist::Set(BTreeSet::new()),
            ),
            Err(CanisterManagerError::SenderNotInWhitelist(sender))
        );
    });
}

#[test]
fn installing_a_canister_with_not_enough_memory_allocation_fails() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Give just 10 bytes of memory allocation which should result in an error.
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(10)).unwrap();
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .memory_allocation(memory_allocation)
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert_eq!(
            res.0,
            MAX_NUM_INSTRUCTIONS
                - wasm_compilation_cost(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM
                )
        );
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
        state.put_canister_state(res.2.unwrap());

        // Install the canister.
        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Attempt to re-install with low memory allocation should fail.
        let instructions_before_reinstall = as_num_instructions(round_limits.instructions);
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(50)).unwrap();
        let res = install_code(
            &canister_manager,
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
            &mut round_limits,
        );
        assert_eq!(res.0, instructions_before_reinstall);
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    });
}

#[test]
fn upgrading_canister_with_not_enough_memory_allocation_fails() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Give just 10 bytes which should be small enough.
        let memory_allocation = MemoryAllocation::try_from(NumBytes::from(10)).unwrap();
        assert_matches!(
            install_code(
                &canister_manager,
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
                &mut round_limits,
            )
            .1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    });
}

#[test]
fn upgrading_canister_fails_if_memory_capacity_exceeded() {
    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let mb = 1 << 20;
    let memory_capacity = 1000 * mb;
    let memory_used = memory_capacity - 10 * mb;

    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (func (export "canister_pre_upgrade")
                (drop (call $stable64_grow (i64.const 80)))
            )
            (func (export "canister_post_upgrade")
                (drop (call $stable64_grow (i64.const 80)))
            )
            (memory 0)
        )"#;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(memory_capacity as i64)
        .build();

    let wasm = wabt::wat2wasm(wat).unwrap();

    let canister1 = test.create_canister(initial_cycles);
    let canister2 = test.create_canister(initial_cycles);

    test.install_canister_with_allocation(canister1, wasm.clone(), None, Some(memory_used))
        .unwrap();

    test.install_canister_with_allocation(canister2, wasm.clone(), None, None)
        .unwrap();

    let cycles_before = test.canister_state(canister2).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(canister2);
    let err = test
        .upgrade_canister_with_allocation(canister2, wasm.clone(), None, Some(11 * mb))
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
    assert_eq!(err.description(), "Canister with memory allocation 11MiB cannot be installed because the Subnet's remaining memory capacity is 9MiB");

    assert_eq!(
        test.canister_state(canister2).system_state.balance(),
        cycles_before - (test.canister_execution_cost(canister2) - execution_cost_before),
    );

    // Try upgrading without any memory allocation.
    let err = test
        .upgrade_canister_with_allocation(canister2, wasm, None, None)
        .unwrap_err();
    let execution_cost_after = test.canister_execution_cost(canister2);
    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
    assert_eq!(err.description(), "Canister with memory allocation 10MiB cannot be installed because the Subnet's remaining memory capacity is 9MiB");

    assert_eq!(
        test.canister_state(canister2).system_state.balance(),
        cycles_before - (execution_cost_after - execution_cost_before)
    );
}

#[test]
fn installing_a_canister_with_not_enough_cycles_fails() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);
        let canister_id = canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                // Give the new canister a relatively small number of cycles so it doesn't have
                // enough to be installed.
                CANISTER_CREATION_FEE + Cycles::new(100),
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(
                    ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec(),
                )
                .build(),
            &mut state,
            &mut round_limits,
        );
        assert_eq!(res.0, MAX_NUM_INSTRUCTIONS);
        assert_matches!(
            res.1,
            Err(CanisterManagerError::InstallCodeNotEnoughCycles(_))
        );
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
            mock_time(),
        )[0],
        Response::Ingress(IngressResponse {
            message_id: message_test_id(456),
            status: IngressStatus::Known {
                receiver: canister_test_id(789).get(),
                user_id: user_test_id(123),
                time: mock_time(),
                state: IngressState::Failed(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    "Canister has been uninstalled.",
                )),
            }
        })
    );
}

#[test]
fn failed_upgrade_hooks_consume_instructions() {
    fn run(
        initial_wasm: Vec<u8>,
        upgrade_wasm: Vec<u8>,
        fails_before_compiling_upgrade_wasm: bool,
    ) {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(subnet_type)
            .build();

        let canister_manager = CanisterManagerBuilder::default()
            .with_subnet_id(subnet_id)
            .with_cycles_account_manager(cycles_account_manager)
            .build();

        let mut state = initial_state(subnet_id, false);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(100).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(initial_wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // reset instruction limit to investigate costs of just the following install
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let compilation_cost = wasm_compilation_cost(&upgrade_wasm);
        let (instructions_left, result, _) = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(upgrade_wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Upgrade,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        let expected = NumInstructions::from(1)
            + if fails_before_compiling_upgrade_wasm {
                NumInstructions::new(0)
            } else {
                compilation_cost
            };
        assert_eq!(
            MAX_NUM_INSTRUCTIONS - instructions_left,
            expected,
            "initial instructions {} left {} diff {} expected {}",
            MAX_NUM_INSTRUCTIONS,
            instructions_left,
            MAX_NUM_INSTRUCTIONS - instructions_left,
            expected
        );
        assert_matches!(result, Err(CanisterManagerError::Hypervisor(_, _)));
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
    run(initial_wasm, upgrade_wasm, true);

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
    run(initial_wasm, upgrade_wasm, false);

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
    run(initial_wasm, upgrade_wasm, false);
}

#[test]
fn failed_install_hooks_consume_instructions() {
    fn run(wasm: Vec<u8>) {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let cycles_account_manager = CyclesAccountManagerBuilder::new()
            .with_subnet_type(subnet_type)
            .build();

        let canister_manager = CanisterManagerBuilder::default()
            .with_subnet_id(subnet_id)
            .with_cycles_account_manager(cycles_account_manager)
            .build();

        let mut state = initial_state(subnet_id, false);
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(100).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let compilation_cost = wasm_compilation_cost(&wasm);
        let (instructions_left, result, _) = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert_matches!(result, Err(CanisterManagerError::Hypervisor(_, _)));
        assert_eq!(
            MAX_NUM_INSTRUCTIONS - instructions_left,
            NumInstructions::from(1) + compilation_cost,
            "initial instructions {} left {} diff {} expected {}",
            MAX_NUM_INSTRUCTIONS,
            instructions_left,
            MAX_NUM_INSTRUCTIONS - instructions_left,
            NumInstructions::from(1) + compilation_cost,
        );
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
fn install_code_respects_instruction_limit() {
    let subnet_id = subnet_test_id(1);
    let subnet_type = SubnetType::Application;
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(subnet_type)
        .build();

    let canister_manager = CanisterManagerBuilder::default()
        .with_subnet_id(subnet_id)
        .with_cycles_account_manager(cycles_account_manager)
        .build();

    let mut state = initial_state(subnet_id, false);
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions((*EXECUTION_PARAMETERS).instruction_limits.message()),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let sender = canister_test_id(100).get();
    let canister_id = canister_manager
        .create_canister(
            sender,
            subnet_id,
            *INITIAL_CYCLES,
            CanisterSettings::default(),
            MAX_NUMBER_OF_CANISTERS,
            &mut state,
            SMALL_APP_SUBNET_MAX_SIZE,
            &mut round_limits,
        )
        .0
        .unwrap();

    let wasm = r#"
    (module
        (func $start
          (i32.const 0)
          drop
        )
        (func $canister_init
          (i32.const 0)
          drop
        )
        (func $canister_pre_upgrade
          (i32.const 0)
          drop
        )
        (func $canister_post_upgrade
          (i32.const 0)
          drop
        )
        (memory $memory 1)
        (start $start)
        (export "canister_init" (func $canister_init))
        (export "canister_pre_upgrade" (func $canister_pre_upgrade))
        (export "canister_post_upgrade" (func $canister_post_upgrade))
    )"#;
    let compilation_cost = wat_compilation_cost(wasm);
    let wasm = wabt::wat2wasm(wasm).unwrap();

    // Too few instructions result in failed installation.
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(NumInstructions::from(3)),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let (instructions_left, result, canister) = install_code(
        &canister_manager,
        InstallCodeContext {
            sender,
            canister_id,
            wasm_module: CanisterModule::new(wasm.clone()),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            mode: CanisterInstallMode::Install,
            query_allocation: QueryAllocation::default(),
        },
        &mut state,
        &mut round_limits,
    );
    state.put_canister_state(canister.unwrap());
    assert_matches!(
        result,
        Err(CanisterManagerError::Hypervisor(
            _,
            HypervisorError::InstructionLimitExceeded
        ))
    );
    assert_eq!(instructions_left, NumInstructions::from(0));

    // Enough instructions result in successful installation.
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(NumInstructions::from(5) + compilation_cost),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let (instructions_left, result, canister) = install_code(
        &canister_manager,
        InstallCodeContext {
            sender,
            canister_id,
            wasm_module: CanisterModule::new(wasm.clone()),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            mode: CanisterInstallMode::Install,
            query_allocation: QueryAllocation::default(),
        },
        &mut state,
        &mut round_limits,
    );
    assert!(result.is_ok());
    assert_eq!(instructions_left, NumInstructions::from(1));
    state.put_canister_state(canister.unwrap());

    // Too few instructions result in failed upgrade.
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(NumInstructions::from(5)),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let (instructions_left, result, canister) = install_code(
        &canister_manager,
        InstallCodeContext {
            sender,
            canister_id,
            wasm_module: CanisterModule::new(wasm.clone()),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            mode: CanisterInstallMode::Upgrade,
            query_allocation: QueryAllocation::default(),
        },
        &mut state,
        &mut round_limits,
    );
    state.put_canister_state(canister.unwrap());
    assert_matches!(
        result,
        Err(CanisterManagerError::Hypervisor(
            _,
            HypervisorError::InstructionLimitExceeded
        ))
    );
    assert_eq!(instructions_left, NumInstructions::from(0));

    // Enough instructions result in successful upgrade.
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(NumInstructions::from(10) + compilation_cost),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };
    let (instructions_left, result, _) = install_code(
        &canister_manager,
        InstallCodeContext {
            sender,
            canister_id,
            wasm_module: CanisterModule::new(wasm),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            mode: CanisterInstallMode::Upgrade,
            query_allocation: QueryAllocation::default(),
        },
        &mut state,
        &mut round_limits,
    );
    assert!(result.is_ok());
    assert_eq!(instructions_left, NumInstructions::from(4));
}

#[test]
fn install_code_preserves_system_state_and_scheduler_state() {
    let canister_manager = CanisterManagerBuilder::default()
        .with_cycles_account_manager(
            CyclesAccountManagerBuilder::new()
                // Make it free so we don't have to worry about cycles when
                // making assertions.
                .with_update_message_execution_fee(Cycles::zero())
                .with_ten_update_instructions_execution_fee(Cycles::zero())
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
        .with_input(
            RequestBuilder::default()
                .receiver(canister_id)
                .build()
                .into(),
        )
        .build();

    let mut state = ReplicatedStateBuilder::new()
        .with_canister(original_canister.clone())
        .build();
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions((*EXECUTION_PARAMETERS).instruction_limits.message()),
        subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
        compute_allocation_used: state.total_compute_allocation(),
    };

    // 1. INSTALL
    let install_code_context = InstallCodeContextBuilder::default()
        .mode(CanisterInstallMode::Install)
        .sender(controller.into())
        .canister_id(canister_id)
        .build();
    let compilation_cost = wasm_compilation_cost(install_code_context.wasm_module.as_slice());

    let (instructions_left, res, canister) = install_code(
        &canister_manager,
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Install)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        &mut round_limits,
    );
    state.put_canister_state(canister.unwrap());

    // Installation is free, since there is no `(start)` or `canister_init` to run.
    assert_eq!(instructions_left, MAX_NUM_INSTRUCTIONS - compilation_cost);

    // No heap delta.
    assert_eq!(res.unwrap().heap_delta, NumBytes::from(0));

    // Verify the system state is preserved except for global timer and canister version.
    let mut new_state = state
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .clone();
    assert_eq!(new_state.global_timer, CanisterTimer::Inactive);
    assert_eq!(
        new_state.canister_version,
        original_canister.system_state.canister_version + 1
    );
    new_state.global_timer = original_canister.system_state.global_timer;
    new_state.canister_version = original_canister.system_state.canister_version;
    assert_eq!(new_state, original_canister.system_state);

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );

    // 2. REINSTALL

    let instructions_before_reinstall = as_num_instructions(round_limits.instructions);
    let (instructions_left, res, canister) = install_code(
        &canister_manager,
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Reinstall)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        &mut round_limits,
    );
    state.put_canister_state(canister.unwrap());

    // Installation is free, since there is no `(start)` or `canister_init` to run.
    assert_eq!(
        instructions_left,
        instructions_before_reinstall - compilation_cost
    );

    // No heap delta.
    assert_eq!(res.unwrap().heap_delta, NumBytes::from(0));

    // Verify the system state is preserved except for global timer and canister version.
    let mut new_state = state
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .clone();
    assert_eq!(new_state.global_timer, CanisterTimer::Inactive);
    assert_eq!(
        new_state.canister_version,
        original_canister.system_state.canister_version + 2
    );
    new_state.global_timer = original_canister.system_state.global_timer;
    new_state.canister_version = original_canister.system_state.canister_version;
    assert_eq!(new_state, original_canister.system_state);

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );

    // 3. UPGRADE
    let instructions_before_upgrade = as_num_instructions(round_limits.instructions);
    let (instructions_left, res, canister) = install_code(
        &canister_manager,
        InstallCodeContextBuilder::default()
            .mode(CanisterInstallMode::Upgrade)
            .sender(controller.into())
            .canister_id(canister_id)
            .build(),
        &mut state,
        &mut round_limits,
    );
    state.put_canister_state(canister.unwrap());

    // Installation is free, since there is no `canister_pre/post_upgrade`
    assert_eq!(
        instructions_left,
        instructions_before_upgrade - compilation_cost
    );

    // No heap delta.
    assert_eq!(res.unwrap().heap_delta, NumBytes::from(0));

    // Verify the system state is preserved except for global timer and canister version.
    let mut new_state = state
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .clone();
    assert_eq!(new_state.global_timer, CanisterTimer::Inactive);
    assert_eq!(
        new_state.canister_version,
        original_canister.system_state.canister_version + 3
    );
    new_state.global_timer = original_canister.system_state.global_timer;
    new_state.canister_version = original_canister.system_state.canister_version;
    assert_eq!(new_state, original_canister.system_state);

    // Verify the scheduler state is preserved.
    assert_eq!(
        state.canister_state(&canister_id).unwrap().scheduler_state,
        original_canister.scheduler_state
    );
}

#[test]
fn lower_memory_allocation_than_usage_fails() {
    with_setup(|canister_manager, mut state, subnet_id| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let wasm = r#"
        (module
            (memory $memory 1)
        )"#;
        let wasm = wabt::wat2wasm(wasm).unwrap();

        let sender = canister_test_id(100).get();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(2)).unwrap()),
            None,
        );

        let canister = state.canister_state_mut(&canister_id).unwrap();

        assert_matches!(
            canister_manager.update_settings(sender, settings, canister, &mut round_limits,),
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
    })
}

#[test]
fn test_install_when_updating_memory_allocation_via_canister_settings() {
    with_setup(|canister_manager, mut state, subnet_id| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let wasm = ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec();

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
                *INITIAL_CYCLES,
                settings,
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // The memory allocation is too low, install should fail.
        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm.clone()),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        state.put_canister_state(res.2.unwrap());
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );

        // Update memory allocation to a big enough value via canister settings. The
        // install should succeed.
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(MEMORY_CAPACITY.get() / 2)).unwrap()),
            None,
        );

        let canister = state.canister_state_mut(&canister_id).unwrap();

        canister_manager
            .update_settings(sender, settings, canister, &mut round_limits)
            .unwrap();

        install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        )
        .1
        .unwrap();
    })
}

#[test]
fn test_upgrade_when_updating_memory_allocation_via_canister_settings() {
    with_setup(|canister_manager, mut state, subnet_id| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(100).get();
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(
                MemoryAllocation::try_from(NumBytes::from(WASM_PAGE_SIZE_IN_BYTES + 100)).unwrap(),
            ),
            None,
        );
        let wat = r#"
        (module
            (memory $memory 1)
        )"#;
        let wasm = wabt::wat2wasm(wat).unwrap();
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                settings,
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Try to upgrade to a wasm module that has bigger memory requirements. It
        // should fail...
        let wat = r#"
        (module
            (memory $memory 2)
        )"#;
        let wasm = wabt::wat2wasm(wat).unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm.clone()),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Upgrade,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert_matches!(
            res.1,
            Err(CanisterManagerError::NotEnoughMemoryAllocationGiven { .. })
        );
        state.put_canister_state(res.2.unwrap());

        // Update memory allocation to a big enough value via canister settings. The
        // upgrade should succeed.
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(
                MemoryAllocation::try_from(NumBytes::from(WASM_PAGE_SIZE_IN_BYTES * 2 + 100))
                    .unwrap(),
            ),
            None,
        );

        let canister = state.canister_state_mut(&canister_id).unwrap();

        canister_manager
            .update_settings(sender, settings, canister, &mut round_limits)
            .unwrap();

        install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Upgrade,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        )
        .1
        .unwrap();
    })
}

#[test]
fn uninstall_code_can_be_invoked_by_governance_canister() {
    use crate::util::GOVERNANCE_CANISTER_ID;

    let canister_manager = CanisterManagerBuilder::default().build();
    let mut state = ReplicatedStateBuilder::new()
        .with_canister(
            CanisterStateBuilder::new()
                .with_canister_id(canister_test_id(0))
                // Give the canister a random wasm so that it
                // has an execution state.
                .with_wasm(vec![1, 2, 3])
                .build(),
        )
        .build();

    assert!(state
        .canister_state(&canister_test_id(0))
        .unwrap()
        .execution_state
        .is_some());

    canister_manager
        .uninstall_code(
            canister_test_id(0),
            GOVERNANCE_CANISTER_ID.get(),
            &mut state,
        )
        .unwrap();

    // The execution state of the canister should be removed.
    assert_eq!(
        state
            .canister_state(&canister_test_id(0))
            .unwrap()
            .execution_state,
        None
    );
}

#[test]
fn test_install_when_setting_memory_allocation_to_zero() {
    with_setup(|canister_manager, mut state, subnet_id| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let wasm = ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec();

        let sender = canister_test_id(100).get();
        let settings = CanisterSettings::new(None, None, None, None, None);
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                settings,
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        // Set memory allocation to 0.
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(0)).unwrap()),
            None,
        );

        let canister = state.canister_state_mut(&canister_id).unwrap();

        canister_manager
            .update_settings(
                sender,
                settings,
                canister,
                //memory_allocation_used,
                &mut round_limits,
            )
            .unwrap();

        install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        )
        .1
        .unwrap();
    })
}

#[test]
fn test_upgrade_when_setting_memory_allocation_to_zero() {
    with_setup(|canister_manager, mut state, subnet_id| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let wasm = ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM.to_vec();

        let sender = canister_test_id(100).get();
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(MEMORY_CAPACITY.get() / 2)).unwrap()),
            None,
        );
        let canister_id = canister_manager
            .create_canister(
                sender,
                subnet_id,
                *INITIAL_CYCLES,
                settings,
                MAX_NUMBER_OF_CANISTERS,
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();

        let res = install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm.clone()),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Install,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        );
        assert!(res.1.is_ok());
        state.put_canister_state(res.2.unwrap());

        // Set memory allocation to 0.
        let settings = CanisterSettings::new(
            None,
            None,
            None,
            Some(MemoryAllocation::try_from(NumBytes::from(0)).unwrap()),
            None,
        );

        let canister = state.canister_state_mut(&canister_id).unwrap();

        canister_manager
            .update_settings(sender, settings, canister, &mut round_limits)
            .unwrap();

        install_code(
            &canister_manager,
            InstallCodeContext {
                sender,
                canister_id,
                wasm_module: CanisterModule::new(wasm),
                arg: vec![],
                compute_allocation: None,
                memory_allocation: None,
                mode: CanisterInstallMode::Upgrade,
                query_allocation: QueryAllocation::default(),
            },
            &mut state,
            &mut round_limits,
        )
        .1
        .unwrap();
    })
}

#[test]
fn max_number_of_canisters_is_respected_when_creating_canisters() {
    with_setup(|canister_manager, mut state, _| {
        let mut round_limits = RoundLimits {
            instructions: as_round_instructions(
                (*EXECUTION_PARAMETERS).instruction_limits.message(),
            ),
            subnet_available_memory: (*MAX_SUBNET_AVAILABLE_MEMORY),
            compute_allocation_used: state.total_compute_allocation(),
        };
        let sender = canister_test_id(1).get();
        let sender_subnet_id = subnet_test_id(1);

        // Create 3 canisters with `max_number_of_canisters = 3`, should succeed.
        canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                3, /* max_number_of_canisters */
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                3, /* max_number_of_canisters */
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                3, /* max_number_of_canisters */
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        assert_eq!(state.num_canisters(), 3);

        // Creating a fourth canister with 3 already created and
        // `max_number_of_canisters = 3` should fail.
        let (res, _) = canister_manager.create_canister(
            sender,
            sender_subnet_id,
            *INITIAL_CYCLES,
            CanisterSettings::default(),
            3, /* max_number_of_canisters */
            &mut state,
            SMALL_APP_SUBNET_MAX_SIZE,
            &mut round_limits,
        );
        assert_matches!(
            res,
            Err(CanisterManagerError::MaxNumberOfCanistersReached { .. })
        );

        // Creating a fourth canister with 3 already created and
        // `max_number_of_canisters = 10` should succeed.
        canister_manager
            .create_canister(
                sender,
                sender_subnet_id,
                *INITIAL_CYCLES,
                CanisterSettings::default(),
                10, /* max_number_of_canisters */
                &mut state,
                SMALL_APP_SUBNET_MAX_SIZE,
                &mut round_limits,
            )
            .0
            .unwrap();
        assert_eq!(state.num_canisters(), 4);
    })
}

/// This canister exports a query that returns its controller's length.
const CONTROLLER_LENGTH: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
        (import "ic0" "controller_size"
            (func $controller_size (result i32)))
        (func $controller
            (i32.store (i32.const 0) (call $controller_size))
            (call $msg_reply_data_append
                (i32.const 0) ;; the counter from heap[0]
                (i32.const 1)) ;; length (assume the i32 actually fits in one byte)
            (call $msg_reply))
        (func $canister_init)
        (memory $memory 1)
        (export "canister_query controller" (func $controller))
        (export "canister_init" (func $canister_init))
    )"#;

/// With sandboxing, we are caching some information about a canister's state
/// (including the controler) with the sandboxed process. This test verifies
/// that the canister sees the proper change when the controller is updated.
#[test]
fn controller_changes_are_visible() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.canister_from_wat(CONTROLLER_LENGTH).unwrap();
    let result = test.ingress(canister_id, "controller", vec![]);
    let reply = get_reply(result);
    assert_eq!(reply, vec![test.user_id().get().to_vec().len() as u8]);

    // Change to a new controller with a different length.
    let new_controller = PrincipalId::try_from(&[1, 2, 3][..]).unwrap();
    assert!(new_controller != test.user_id().get());
    test.set_controller(canister_id, new_controller).unwrap();

    let result = test.ingress(canister_id, "controller", vec![]);
    let reply = get_reply(result);
    assert_eq!(reply, vec![new_controller.to_vec().len() as u8]);
}

// This test confirms that we can always create as many canisters as possible if
// no explicit limit is set.
#[test]
fn creating_canisters_always_works_if_limit_is_set_to_zero() {
    let own_subnet = subnet_test_id(1);
    let caller = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller)
        .build();
    for _ in 0..1_000 {
        test.inject_call_to_ic00(
            Method::CreateCanister,
            EmptyBlob.encode(),
            test.canister_creation_fee(),
        );
        test.execute_all();
    }
    assert_eq!(test.state().num_canisters() as u64, 1_000);
}

#[test]
fn test_upgrade_preserves_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let data = [1, 2, 3, 5, 8, 13];
    let update = wasm()
        .stable_grow(1)
        .stable_write(42, &data)
        .reply()
        .build();
    let result = test.ingress(canister_id, "update", update);
    let reply = get_reply(result);
    assert_eq!(reply, vec![] as Vec<u8>);
    test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let query = wasm()
        .stable_read(42, data.len() as u32)
        .append_and_reply()
        .build();
    let result = test.ingress(canister_id, "query", query);
    let reply = get_reply(result);
    assert_eq!(reply, data);
}

fn create_canisters(test: &mut ExecutionTest, canisters: usize) {
    for _ in 1..=canisters {
        test.canister_from_binary(MINIMAL_WASM.to_vec()).unwrap();
    }
}

#[test]
pub fn test_can_create_10_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 10);
}

// The following tests are expensive to run, so enable them explicitly:
// perf stat cargo t test_can_create_125_canisters -- --include-ignored --nocapture
// Test results: https://docs.google.com/spreadsheets/d/14tBO0vg508tW_r4t4_btH4iQdia9BMIJeV8IAuWc_sg
#[test]
#[ignore]
pub fn test_can_create_125_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 125);
}

#[test]
#[ignore]
pub fn test_can_create_250_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 250);
}

#[test]
#[ignore]
pub fn test_can_create_500_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 500);
}

#[test]
#[ignore]
pub fn test_can_create_1000_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 1000);
}

#[test]
#[ignore]
pub fn test_can_create_5000_canisters() {
    let mut test = ExecutionTestBuilder::new().build();
    create_canisters(&mut test, 5000);
}

#[test]
#[ignore]
pub fn test_can_create_10000_canisters() {
    let mut test = ExecutionTestBuilder::new()
        .with_max_number_of_canisters(10_000)
        .build();
    create_canisters(&mut test, 10_000);
}

#[test]
fn test_install_code_rate_limiting() {
    let mut test = ExecutionTestBuilder::new()
        .with_rate_limiting_of_instructions()
        .build();
    let canister_id = test.universal_canister().unwrap();
    let binary = UNIVERSAL_CANISTER_WASM.to_vec();
    let err = test
        .upgrade_canister(canister_id, binary.clone())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterInstallCodeRateLimited, err.code());
    let err = test.upgrade_canister(canister_id, binary).unwrap_err();
    assert_eq!(ErrorCode::CanisterInstallCodeRateLimited, err.code());
}

#[test]
fn test_install_code_rate_limiting_disabled() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let binary = UNIVERSAL_CANISTER_WASM.to_vec();
    test.upgrade_canister(canister_id, binary.clone()).unwrap();
    test.upgrade_canister(canister_id, binary).unwrap();
}

#[test]
fn install_code_context_conversion_u128() {
    let install_args = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: PrincipalId::try_from([1, 2, 3].as_ref()).unwrap(),
        wasm_module: vec![],
        arg: vec![],
        compute_allocation: Some(candid::Nat::from(u128::MAX)),
        memory_allocation: Some(candid::Nat::from(u128::MAX)),
        query_allocation: Some(candid::Nat::from(u128::MAX)),
    };

    assert!(InstallCodeContext::try_from((
        PrincipalId::try_from([1, 2, 3].as_ref()).unwrap(),
        install_args,
    ))
    .is_err());
}

#[test]
fn unfreezing_of_frozen_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test
        .universal_canister_with_cycles(Cycles::new(1_000_000_000_000))
        .unwrap();

    // Set the freezing theshold high to freeze the canister.
    let payload = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgs {
            freezing_threshold: Some(candid::Nat::from(1_000_000_000_000_u64)),
            ..Default::default()
        },
    }
    .encode();
    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.subnet_message(Method::UpdateSettings, payload);
    let balance_after = test.canister_state(canister_id).system_state.balance();
    // If the freezing threshold doesn't change, then the canister is not charged.
    assert_eq!(balance_before, balance_after);
    get_reply(result);

    // Sending an ingress message fails due to the cycles balance.
    let err = test
        .ingress(canister_id, "update", wasm().reply().build())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfCycles, err.code());

    // Unfreeze the canister.
    let payload = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgs {
            freezing_threshold: Some(candid::Nat::from(0_u64)),
            ..Default::default()
        },
    }
    .encode();
    let ingress_bytes =
        NumBytes::from((Method::UpdateSettings.to_string().len() + payload.len()) as u64);
    let balance_before = test.canister_state(canister_id).system_state.balance();
    test.subnet_message(Method::UpdateSettings, payload)
        .unwrap();
    let balance_after = test.canister_state(canister_id).system_state.balance();
    assert_eq!(
        balance_before - balance_after,
        test.cycles_account_manager()
            .ingress_induction_cost_from_bytes(ingress_bytes, test.subnet_size())
    );
    // Now the canister works again.
    let result = test.ingress(canister_id, "update", wasm().reply().build());
    get_reply(result);
}

#[test]
fn create_canister_fails_if_memory_capacity_exceeded() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_total_memory(MEMORY_CAPACITY.get() as i64)
        .build();
    let uc = test.universal_canister().unwrap();

    *test.canister_state_mut(uc).system_state.balance_mut() = Cycles::new(1_000_000_000_000_000);

    let settings = CanisterSettingsArgs {
        memory_allocation: Some(candid::Nat::from(MEMORY_CAPACITY.get() / 2)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister);
    let reply = get_reply(result);
    Decode!(reply.as_slice(), CanisterIdRecord).unwrap();

    // There should be not enough memory for CAPACITY/2 because universal
    // canister already consumed some
    let settings = CanisterSettingsArgs {
        memory_allocation: Some(candid::Nat::from(MEMORY_CAPACITY.get() / 2)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister).unwrap();
    match result {
        WasmResult::Reject(msg) => {
            assert!(
                msg.contains("memory allocation"),
                "actual reject message: {}",
                msg
            )
        }
        _ => panic!("Expected WasmResult::Reject"),
    }
}

#[test]
fn create_canister_makes_subnet_oversubscribed() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(100)
        .build();
    let uc = test.universal_canister().unwrap();

    *test.canister_state_mut(uc).system_state.balance_mut() = Cycles::new(1_000_000_000_000_000);

    let settings = CanisterSettingsArgs {
        compute_allocation: Some(candid::Nat::from(50_u32)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister);
    let reply = get_reply(result);
    Decode!(reply.as_slice(), CanisterIdRecord).unwrap();

    let settings = CanisterSettingsArgs {
        compute_allocation: Some(candid::Nat::from(25_u32)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister);
    let reply = get_reply(result);
    Decode!(reply.as_slice(), CanisterIdRecord).unwrap();

    // Create a canister with compute allocation.
    let settings = CanisterSettingsArgs {
        compute_allocation: Some(candid::Nat::from(30_u32)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister).unwrap();
    match result {
        WasmResult::Reject(msg) => {
            assert!(msg.contains("compute allocation"))
        }
        _ => panic!("Expected WasmResult::Reject"),
    }
}

#[test]
fn update_settings_makes_subnet_oversubscribed() {
    // By default the scheduler has 2 cores
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(100)
        .with_subnet_total_memory(100 * 1024 * 1024) // 100 MiB
        .build();
    let c1 = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let c2 = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let c3 = test.create_canister(Cycles::new(1_000_000_000_000_000));

    // Updating the compute allocation.
    let args = UpdateSettingsArgs {
        canister_id: c1.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(50_u32)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();

    let args = UpdateSettingsArgs {
        canister_id: c2.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(25_u32)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();

    // Go over the compute capacity.
    let args = UpdateSettingsArgs {
        canister_id: c3.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(30_u32)),
            ..Default::default()
        },
    };
    let err = test
        .subnet_message(Method::UpdateSettings, args.encode())
        .unwrap_err();
    assert_eq!(ErrorCode::SubnetOversubscribed, err.code());

    // Updating the memory allocation.
    let args = UpdateSettingsArgs {
        canister_id: c1.get(),
        settings: CanisterSettingsArgs {
            memory_allocation: Some(candid::Nat::from(10 * 1024 * 1024)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();

    let args = UpdateSettingsArgs {
        canister_id: c2.get(),
        settings: CanisterSettingsArgs {
            memory_allocation: Some(candid::Nat::from(30 * 1024 * 1024)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();

    // Go over the memory capacity.
    let args = UpdateSettingsArgs {
        canister_id: c3.get(),
        settings: CanisterSettingsArgs {
            memory_allocation: Some(candid::Nat::from(65 * 1024 * 1024)),
            ..Default::default()
        },
    };
    let err = test
        .subnet_message(Method::UpdateSettings, args.encode())
        .unwrap_err();
    assert_eq!(ErrorCode::SubnetOversubscribed, err.code());
}

#[test]
fn create_canister_when_compute_capacity_is_oversubscribed() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(0)
        .build();
    let uc = test.universal_canister().unwrap();

    // Manually set the compute allocation higher to emulate the state after
    // replica upgrade that decreased compute capacity.
    test.canister_state_mut(uc)
        .scheduler_state
        .compute_allocation = ComputeAllocation::try_from(60).unwrap();
    *test.canister_state_mut(uc).system_state.balance_mut() = Cycles::new(2_000_000_000_000_000);

    // Create a canister with default settings.
    let args = CreateCanisterArgs::default();
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args().other_side(args.encode()),
            test.canister_creation_fee().into_parts(),
        )
        .build();

    let result = test.ingress(uc, "update", create_canister);
    let reply = get_reply(result);
    Decode!(reply.as_slice(), CanisterIdRecord).unwrap();

    // Create a canister with zero compute allocation.
    let settings = CanisterSettingsArgs {
        compute_allocation: Some(candid::Nat::from(0_u32)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister);
    let reply = get_reply(result);
    Decode!(reply.as_slice(), CanisterIdRecord).unwrap();

    // Create a canister with compute allocation.
    let settings = CanisterSettingsArgs {
        compute_allocation: Some(candid::Nat::from(10_u32)),
        ..Default::default()
    };
    let args = CreateCanisterArgs {
        settings: Some(settings),
    };
    let create_canister = wasm()
        .call_with_cycles(
            CanisterId::ic_00(),
            Method::CreateCanister,
            call_args()
                .other_side(args.encode())
                .on_reject(wasm().reject_message().reject()),
            test.canister_creation_fee().into_parts(),
        )
        .build();
    let result = test.ingress(uc, "update", create_canister).unwrap();
    assert_eq!(
        result,
        WasmResult::Reject(
            "Canister requested a compute allocation of 10% which \
            cannot be satisfied because the Subnet's remaining \
            compute capacity is 0%"
                .to_string()
        )
    );
}

#[test]
fn install_code_when_compute_capacity_is_oversubscribed() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(0)
        .build();
    let canister_id = test.create_canister(Cycles::new(2_000_000_000_000_000));

    // Manually set the compute allocation higher to emulate the state after
    // replica upgrade that decreased compute capacity.
    test.canister_state_mut(canister_id)
        .scheduler_state
        .compute_allocation = ComputeAllocation::try_from(60).unwrap();

    // Updating the compute allocation to a higher value fails.
    let err = test
        .install_canister_with_allocation(
            canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            Some(61),
            None,
        )
        .unwrap_err();
    assert_eq!(ErrorCode::SubnetOversubscribed, err.code());
    assert_eq!(
        err.description(),
        "Canister requested a compute allocation of 61% \
        which cannot be satisfied because the Subnet's \
        remaining compute capacity is 60%"
    );

    // Updating the compute allocation to the same value succeeds.
    test.install_canister_with_allocation(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        Some(60),
        None,
    )
    .unwrap();
    assert_eq!(
        ComputeAllocation::try_from(60).unwrap(),
        test.canister_state(canister_id)
            .scheduler_state
            .compute_allocation
    );

    test.uninstall_code(canister_id).unwrap();

    // Updating the compute allocation to a lower value succeeds.
    test.install_canister_with_allocation(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        Some(59),
        None,
    )
    .unwrap();
    assert_eq!(
        ComputeAllocation::try_from(59).unwrap(),
        test.canister_state(canister_id)
            .scheduler_state
            .compute_allocation
    );
}

#[test]
fn update_settings_when_compute_capacity_is_oversubscribed() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(0)
        .build();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));

    // Manually set the compute allocation higher to emulate the state after
    // replica upgrade that decreased compute capacity.
    test.canister_state_mut(canister_id)
        .scheduler_state
        .compute_allocation = ComputeAllocation::try_from(60).unwrap();

    // Updating the compute allocation to a higher value fails.
    let args = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(61_u32)),
            ..Default::default()
        },
    };
    let err = test
        .subnet_message(Method::UpdateSettings, args.encode())
        .unwrap_err();
    assert_eq!(ErrorCode::SubnetOversubscribed, err.code());
    assert_eq!(
        err.description(),
        "Canister requested a compute allocation of 61% \
        which cannot be satisfied because the Subnet's \
        remaining compute capacity is 60%"
    );

    // Updating the compute allocation to the same value succeeds.
    let args = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(60_u32)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();
    assert_eq!(
        ComputeAllocation::try_from(60).unwrap(),
        test.canister_state(canister_id)
            .scheduler_state
            .compute_allocation
    );

    // Updating the compute allocation to a lower value succeeds.
    let args = UpdateSettingsArgs {
        canister_id: canister_id.get(),
        settings: CanisterSettingsArgs {
            compute_allocation: Some(candid::Nat::from(59_u32)),
            ..Default::default()
        },
    };
    test.subnet_message(Method::UpdateSettings, args.encode())
        .unwrap();
    assert_eq!(
        ComputeAllocation::try_from(59).unwrap(),
        test.canister_state(canister_id)
            .scheduler_state
            .compute_allocation
    );
}

#[test]
fn cycles_correct_if_upgrade_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (i32.const 1))
            )
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(6 + 14) + wasm_compilation_cost(&wasm),
            test.subnet_size()
        )
    );

    let cycles_before = test.canister_state(id).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(id);
    test.upgrade_canister(id, wasm.clone()).unwrap();
    let execution_cost = test.canister_execution_cost(id) - execution_cost_before;
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        cycles_before - execution_cost,
    );
    assert_eq!(
        execution_cost,
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(18 + 24) + wasm_compilation_cost(&wasm),
            test.subnet_size()
        )
    );
}

#[test]
fn cycles_correct_if_upgrade_fails_at_validation() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(50)
        .build();

    let wat = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager()
            .execution_cost(wasm_compilation_cost(&wasm), test.subnet_size())
    );

    let cycles_before = test.canister_state(id).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(id);
    test.upgrade_canister_with_allocation(id, wasm, Some(100), None)
        .unwrap_err();
    let execution_cost = test.canister_execution_cost(id) - execution_cost_before;
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        cycles_before - execution_cost,
    );
    assert_eq!(
        execution_cost,
        test.cycles_account_manager()
            .execution_cost(NumInstructions::from(0), test.subnet_size())
    );
}

#[test]
fn cycles_correct_if_upgrade_fails_at_start() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat1 = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 1)))
            )
            (memory 0)
        )"#;
    let wat2 = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (unreachable)
            )
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm1 = wabt::wat2wasm(wat1).unwrap();
    let wasm2 = wabt::wat2wasm(wat2).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm1).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );

    let cycles_before = test.canister_state(id).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(id);
    test.upgrade_canister(id, wasm2.clone()).unwrap_err();
    let execution_cost = test.canister_execution_cost(id) - execution_cost_before;
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        cycles_before - execution_cost,
    );
    assert_eq!(
        execution_cost,
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(1 + 9) + wasm_compilation_cost(&wasm2),
            test.subnet_size()
        )
    );
}

#[test]
fn cycles_correct_if_upgrade_fails_at_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (unreachable)
            )
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager()
            .execution_cost(wasm_compilation_cost(&wasm), test.subnet_size())
    );

    let cycles_before = test.canister_state(id).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(id);
    test.upgrade_canister(id, wasm).unwrap_err();
    let execution_cost = test.canister_execution_cost(id) - execution_cost_before;
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        cycles_before - execution_cost,
    );
    assert_eq!(
        execution_cost,
        test.cycles_account_manager()
            .execution_cost(NumInstructions::from(10), test.subnet_size())
    );
}

#[test]
fn cycles_correct_if_upgrade_fails_at_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat1 = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (memory 0)
        )"#;
    let wat2 = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_post_upgrade")
                (unreachable)
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm1 = wabt::wat2wasm(wat1).unwrap();
    let wasm2 = wabt::wat2wasm(wat2).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm1).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );

    let cycles_before = test.canister_state(id).system_state.balance();
    let execution_cost_before = test.canister_execution_cost(id);
    test.upgrade_canister(id, wasm2.clone()).unwrap_err();
    let execution_cost = test.canister_execution_cost(id) - execution_cost_before;
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        cycles_before - execution_cost,
    );
    assert_eq!(
        execution_cost,
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(6 + 3 + 1) + wasm_compilation_cost(&wasm2),
            test.subnet_size()
        )
    );
}

#[test]
fn cycles_correct_if_install_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (i32.const 1))
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(6 + 14) + wasm_compilation_cost(&wasm),
            test.subnet_size()
        )
    );
}

#[test]
fn cycles_correct_if_install_fails_at_validation() {
    let mut test = ExecutionTestBuilder::new()
        .with_allocatable_compute_capacity_in_percent(50)
        .build();

    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister_with_allocation(id, wasm, Some(100), None)
        .unwrap_err();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager()
            .execution_cost(NumInstructions::from(0), test.subnet_size())
    );
}

#[test]
fn cycles_correct_if_install_fails_at_start() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (unreachable)
            )
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap_err();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(10) + wasm_compilation_cost(&wasm),
            test.subnet_size()
        )
    );
}

#[test]
fn cycles_correct_if_install_fails_at_init() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 1)))
            )
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
                (drop (memory.grow (i32.const 1)))
                (unreachable)
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test.create_canister(initial_cycles);

    test.install_canister(id, wasm.clone()).unwrap_err();
    assert_eq!(
        test.canister_state(id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(id),
    );
    assert_eq!(
        test.canister_execution_cost(id),
        test.cycles_account_manager().execution_cost(
            NumInstructions::from(1 + 9) + wasm_compilation_cost(&wasm),
            test.subnet_size()
        )
    );
}

#[test]
fn install_code_can_increase_and_use_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test
        .create_canister_with_allocation(initial_cycles, None, Some(1_000))
        .unwrap();

    test.install_canister_with_allocation(id, wasm, None, Some(1_000_000))
        .unwrap();

    assert_eq!(
        test.canister_state(id).system_state.memory_allocation,
        MemoryAllocation::Reserved(NumBytes::from(1_000_000))
    );
    assert_eq!(
        test.canister_state(id)
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_memory
            .size,
        NumWasmPages::from(10)
    )
}

#[test]
fn install_code_cannot_switch_from_reserved_to_best_effort_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().build();

    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 0)
        )"#;
    let wasm = wabt::wat2wasm(wat).unwrap();

    let initial_cycles = Cycles::new(1_000_000_000_000_000);
    let id = test
        .create_canister_with_allocation(initial_cycles, None, Some(1_000_000))
        .unwrap();

    test.install_canister_with_allocation(id, wasm, None, None)
        .unwrap();

    assert_eq!(
        test.canister_state(id).system_state.memory_allocation,
        MemoryAllocation::Reserved(NumBytes::from(1_000_000))
    );
    assert_eq!(
        test.canister_state(id)
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_memory
            .size,
        NumWasmPages::from(10)
    )
}
