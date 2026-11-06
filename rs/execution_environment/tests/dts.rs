//! # Traceability
//! Spec: openspec/capabilities/execution-dts/spec.md
//!
//! REQ-DTS-002: Instruction Limits
//!   SCENARIO-DTS-003: Message instruction limit
//!   SCENARIO-DTS-004: Slice instruction limit
//!   SCENARIO-DTS-005: Slicing enabled check
//!   SCENARIO-DTS-006: Install code slice limits
//!
//! REQ-DTS-003: Paused Execution State
//!   SCENARIO-DTS-007: Paused message execution state
//!   SCENARIO-DTS-008: Paused install_code execution state
//!
//! REQ-DTS-004: Resuming Paused Executions
//!   SCENARIO-DTS-010: Resume paused message execution
//!   SCENARIO-DTS-011: Resume paused install_code
//!   SCENARIO-DTS-012: Resume with updated round context
//!
//! REQ-DTS-006: Multi-Stage DTS Operations
//!   SCENARIO-DTS-015: Upgrade with DTS across stages
//!   SCENARIO-DTS-016: Install with DTS across stages
//!   SCENARIO-DTS-017: Response callback with DTS

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::{
    embedders::Config as EmbeddersConfig,
    execution_environment::Config as HypervisorConfig,
    subnet_config::{SchedulerConfig, SubnetConfig},
};
use ic_cycles_account_manager::IngressInductionCost;
use ic_error_types::UserError;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgsBuilder, EmptyBlob, IC_00,
    InstallCodeArgs, Method, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::{NextExecution, execution_state::NextScheduledMethod};
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineConfig};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::MessageId;
use ic_types::{CryptoHashOfState, NumInstructions};
use ic_types_cycles::Cycles;
use ic_universal_canister::{
    CallArgs, CallInterface, UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM, UNIVERSAL_CANISTER_WASM,
    call_args, management, wasm,
};
use std::sync::OnceLock;
use strum::{EnumIter, IntoEnumIterator};

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

const DTS_WAT: &str = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (import "ic0" "time" (func $time (result i64)))
            (import "ic0" "global_timer_set"
                (func $global_timer_set (param i64) (result i64))
            )
            (import "ic0" "canister_version" (func $canister_version (result i64)))
            (func $work
                ;; The bulk of the work is a sequence of `memory.fill`s. Their
                ;; cost (~1 instruction/byte) is page-size independent, unlike the
                ;; one-off deterministic-memory-tracker page-fault charge, which
                ;; depends on the OS page size (16 OS pages per Wasm page on 4 KiB
                ;; hosts such as Linux, 4 on 16 KiB hosts such as arm64-darwin).
                ;; Doing enough fills keeps the number of DTS slices dominated by
                ;; this page-size-independent work, so the tests observe the same
                ;; DTS behavior on both platforms. All fills target Wasm page 0,
                ;; so only that single page is dirtied. The last fill writes `78`
                ;; over `heap[0..)`, which `canister_query read` relies on.
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 23) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 56) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 67) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 23) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 56) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 67) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 50000))
                (memory.fill (i32.const 0) (i32.const 78) (i32.const 50000))
            )
            (start $work)

            (func (export "canister_pre_upgrade")
                (call $work)
            )

            (func (export "canister_post_upgrade")
                (call $work)
            )

            (func (export "canister_init")
                (call $work)
                (drop (call $global_timer_set
                    (i64.add (call $time) (i64.const 1))
                ))
                (drop (call $canister_version))
            )

            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 20)) ;; length
                (call $msg_reply))

            (func (export "canister_update update")
                (call $work)
                (call $msg_reply_data_append (i32.const 0) (i32.const 0))
                (call $msg_reply)
            )

            (func (export "canister_heartbeat")
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 10))
            )

            (func (export "canister_global_timer")
                (memory.fill (i32.const 10) (i32.const 13) (i32.const 5))
            )

            (memory 1)
        )"#;

fn wat2wasm(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).unwrap()
}

fn dts_subnet_config(
    message_instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
) -> SubnetConfig {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    SubnetConfig {
        scheduler_config: SchedulerConfig {
            max_instructions_per_install_code: message_instruction_limit,
            max_instructions_per_install_code_slice: slice_instruction_limit,
            // We should execute just one slice per round.
            max_instructions_per_round: slice_instruction_limit + slice_instruction_limit / 2,
            max_instructions_per_message: message_instruction_limit,
            max_instructions_per_query_message: slice_instruction_limit,
            max_instructions_per_slice: slice_instruction_limit,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            ..subnet_config.scheduler_config
        },
        ..subnet_config
    }
}

fn dts_state_machine_config(subnet_config: SubnetConfig) -> StateMachineConfig {
    StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            embedders_config: EmbeddersConfig {
                create_execution_state_base_cost: 0.into(),
                cost_to_compile_wasm_instruction: 0.into(),
                ..EmbeddersConfig::default()
            },
            ..Default::default()
        },
    )
}

fn dts_env(
    message_instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
) -> StateMachine {
    ic_state_machine_tests::StateMachineBuilder::new()
        .with_config(Some(dts_state_machine_config(dts_subnet_config(
            message_instruction_limit,
            slice_instruction_limit,
        ))))
        .with_subnet_type(SubnetType::Application)
        .build()
}

fn dts_install_code_env(
    message_instruction_limit: NumInstructions,
    slice_instruction_limit: NumInstructions,
) -> (StateMachine, SubnetConfig) {
    let default_app_subnet_config = SubnetConfig::new(SubnetType::Application);
    let subnet_config = SubnetConfig {
        scheduler_config: SchedulerConfig {
            max_instructions_per_install_code: message_instruction_limit,
            max_instructions_per_install_code_slice: slice_instruction_limit,
            max_instructions_per_round: message_instruction_limit + message_instruction_limit,
            max_instructions_per_message: message_instruction_limit,
            max_instructions_per_query_message: slice_instruction_limit,
            max_instructions_per_slice: message_instruction_limit,
            instruction_overhead_per_execution: NumInstructions::from(0),
            instruction_overhead_per_canister: NumInstructions::from(0),
            install_code_rate_limit: message_instruction_limit,
            ..default_app_subnet_config.scheduler_config
        },
        ..default_app_subnet_config
    };
    let hypervisor_config = HypervisorConfig::default();
    let state_machine = ic_state_machine_tests::StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config.clone(),
            hypervisor_config,
        )))
        .with_subnet_type(SubnetType::Application)
        .build();
    (state_machine, subnet_config)
}

/// Extracts the ingress state from the ingress status.
fn ingress_state(ingress_status: IngressStatus) -> Option<IngressState> {
    match ingress_status {
        IngressStatus::Known { state, .. } => Some(state),
        IngressStatus::Unknown => None,
    }
}

/// Extracts the ingress time from the ingress status.
fn ingress_time(ingress_status: IngressStatus) -> Option<SystemTime> {
    match ingress_status {
        IngressStatus::Known { time, .. } => {
            let time =
                SystemTime::UNIX_EPOCH + Duration::from_nanos(time.as_nanos_since_unix_epoch());
            Some(time)
        }
        IngressStatus::Unknown => None,
    }
}

// The following constant was chosen so that the universal canister can be successfully deployed
// using at most `MAX_INSTRUCTIONS`.
const MAX_INSTRUCTIONS: u64 = 10_000_000_000;

// The following constant was chosen as an arbitrary fraction of `MAX_INSTRUCTIONS`
// high enough that exceeding `MAX_INSTRUCTIONS` does not take too many slices.
const MAX_SLICE_INSTRUCTIONS: u64 = 100_000_000;

// The following constant was chosen arbitrarily between `MAX_SLICE_INSTRUCTIONS` and `MAX_INSTRUCTIONS`
// so that executing that many instructions results in multiple slices
// and stays within the limit of `MAX_INSTRUCTIONS`.
const TEST_INSTALL_CODE_INSTRUCTIONS: u64 = 10 * MAX_SLICE_INSTRUCTIONS;

// Creates an empty canister with high cycles balance, a compute allocation of 1%, and no freezing threshold.
fn create_canister(env: &StateMachine) -> CanisterId {
    env.create_canister_with_cycles(
        None,
        INITIAL_CYCLES_BALANCE,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .with_freezing_threshold(0)
                .build(),
        ),
    )
}

// Installs the universal canister (without heartbeat to avoid unexpected cycles consumption) executing at least the given number of instructions.
fn install_code(
    env: &StateMachine,
    canister_id: CanisterId,
    mode: CanisterInstallMode,
    instructions: u64,
) -> Result<WasmResult, UserError> {
    env.execute_ingress_as(
        PrincipalId::new_anonymous(),
        IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            mode,
            canister_id,
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            wasm().instruction_counter_is_at_least(instructions).build(),
        )
        .encode(),
    )
}

// Executes an update call on the universal canister executing at least the given number of instructions.
fn update_call(
    env: &StateMachine,
    canister_id: CanisterId,
    instructions: u64,
) -> Result<MessageId, UserError> {
    env.send_ingress_safe(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        wasm().instruction_counter_is_at_least(instructions).build(),
    )
}

// The number of cycles used for instruction limit exceeded when installing the universal canister.
static MAX_INSTALL_CODE_COST: OnceLock<Cycles> = OnceLock::new();

fn max_install_code_cost() -> Cycles {
    *MAX_INSTALL_CODE_COST.get_or_init(|| {
        let (env, _) = dts_install_code_env(
            NumInstructions::from(MAX_INSTRUCTIONS),
            NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
        );

        let canister_id = create_canister(&env);

        let initial_balance = env.cycle_balance(canister_id);
        let err = install_code(
            &env,
            canister_id,
            CanisterInstallMode::Install,
            MAX_INSTRUCTIONS,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);
        let balance = env.cycle_balance(canister_id);
        Cycles::new(initial_balance - balance)
    })
}

// The number of cycles used for instruction limit exceeded when reinstalling the universal canister.
static MAX_REINSTALL_CODE_COST: OnceLock<Cycles> = OnceLock::new();

fn max_reinstall_code_cost() -> Cycles {
    *MAX_REINSTALL_CODE_COST.get_or_init(|| {
        let (env, _) = dts_install_code_env(
            NumInstructions::from(MAX_INSTRUCTIONS),
            NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
        );

        let canister_id = create_canister(&env);
        install_code(
            &env,
            canister_id,
            CanisterInstallMode::Install,
            TEST_INSTALL_CODE_INSTRUCTIONS,
        )
        .unwrap();

        let initial_balance = env.cycle_balance(canister_id);
        let err = install_code(
            &env,
            canister_id,
            CanisterInstallMode::Reinstall,
            MAX_INSTRUCTIONS,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);
        let balance = env.cycle_balance(canister_id);
        Cycles::new(initial_balance - balance)
    })
}

// The number of cycles used for installing the universal canister using multiple slices.
static INSTALL_CODE_COST: OnceLock<Cycles> = OnceLock::new();

fn install_code_cost() -> Cycles {
    *INSTALL_CODE_COST.get_or_init(|| {
        let (env, _) = dts_install_code_env(
            NumInstructions::from(MAX_INSTRUCTIONS),
            NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
        );

        let canister_id = create_canister(&env);

        let initial_balance = env.cycle_balance(canister_id);
        install_code(
            &env,
            canister_id,
            CanisterInstallMode::Install,
            TEST_INSTALL_CODE_INSTRUCTIONS,
        )
        .unwrap();
        let balance = env.cycle_balance(canister_id);
        Cycles::new(initial_balance - balance)
    })
}

// The number of cycles used for instruction limit exceeded when executing an update call on the universal canister.
static MAX_UPDATE_CALL_COST: OnceLock<Cycles> = OnceLock::new();

fn max_update_call_cost() -> Cycles {
    *MAX_UPDATE_CALL_COST.get_or_init(|| {
        let (env, _) = dts_install_code_env(
            NumInstructions::from(MAX_INSTRUCTIONS),
            NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
        );

        let canister_id = create_canister(&env);
        install_code(
            &env,
            canister_id,
            CanisterInstallMode::Install,
            TEST_INSTALL_CODE_INSTRUCTIONS,
        )
        .unwrap();

        let initial_balance = env.cycle_balance(canister_id);
        let msg_id = update_call(&env, canister_id, MAX_INSTRUCTIONS).unwrap();
        // We are awaiting the ingress message for up to 100 rounds (arbitrary value high enough for the message to complete).
        let err = env.await_ingress(msg_id, 100).unwrap_err();
        assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);
        let balance = env.cycle_balance(canister_id);
        Cycles::new(initial_balance - balance)
    })
}

// The following test executes the following scenario:
// - successfully install the universal canister using multiple slices;
// - start reinstalling the universal canister (exceeding the instruction limit eventually);
// - submit an ingress message to the universal canister (exceeding the instruction limit eventually)
//   while it is being reinstalled.
// All messages complete eventually since the canister has enough cycles for all of them.
#[test]
fn dts_install_code_with_concurrent_ingress_sufficient_cycles() {
    // The initial balance is sufficient to run `install_code` twice
    // (a successful install code and then one exceeding the instruction limit)
    // and to execute an ingress message concurrently.
    let initial_balance = install_code_cost() + max_reinstall_code_cost() + max_update_call_cost();

    let (env, _) = dts_install_code_env(
        NumInstructions::from(MAX_INSTRUCTIONS),
        NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
    );

    let canister_id = env.create_canister_with_cycles(
        None,
        initial_balance,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .with_freezing_threshold(0)
                .with_log_memory_limit(0) // Disable canister logging.
                .build(),
        ),
    );

    install_code(
        &env,
        canister_id,
        CanisterInstallMode::Install,
        TEST_INSTALL_CODE_INSTRUCTIONS,
    )
    .unwrap();

    let install_code_ingress_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            CanisterInstallMode::Reinstall,
            canister_id,
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            wasm()
                .instruction_counter_is_at_least(MAX_INSTRUCTIONS)
                .build(),
        )
        .encode(),
    );

    // Start execution of `install_code`.
    env.tick();

    // Send a normal ingress message while the canister is being reinstalled.
    let update_call_id = update_call(&env, canister_id, MAX_INSTRUCTIONS).unwrap();

    // We are awaiting the ingress message for up to 100 rounds (arbitrary value high enough for the message to complete).
    let err = env.await_ingress(install_code_ingress_id, 100).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);

    // We are awaiting the ingress message for up to 100 rounds (arbitrary value high enough for the message to complete).
    let err = env.await_ingress(update_call_id, 100).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);

    // No cycles are left at the end.
    assert_eq!(env.cycle_balance(canister_id), 0);
}

#[test]
fn dts_install_code_with_concurrent_ingress_insufficient_cycles() {
    dts_install_code_with_concurrent_ingress_insufficient_cycles_and_freezing_threshold(0);
}

#[test]
fn dts_install_code_with_concurrent_ingress_insufficient_cycles_and_nonzero_freezing_threshold() {
    dts_install_code_with_concurrent_ingress_insufficient_cycles_and_freezing_threshold(1);
}

// The following test executes the following scenario:
// - start installing the universal canister (exceeding the instruction limit eventually);
// - submit an ingress message to the universal canister (exceeding the instruction limit eventually)
//   while it is being installed: this fails because the canister has no cycles left at this point.
// Multiple values of the freezing threshold affecting the cycles balance are tested.
fn dts_install_code_with_concurrent_ingress_insufficient_cycles_and_freezing_threshold(
    freezing_threshold: u64,
) {
    let (env, config) = dts_install_code_env(
        NumInstructions::from(MAX_INSTRUCTIONS),
        NumInstructions::from(MAX_SLICE_INSTRUCTIONS),
    );

    let compute_allocation_cycles = config
        .cycles_account_manager_config
        .compute_percent_allocated_per_second_fee
        * freezing_threshold;

    // A freshly created canister has non-zero memory (canister history), so the
    // base_per_second_fee also contributes to the freeze threshold.
    let base_per_second_fee_cycles =
        config.cycles_account_manager_config.base_per_second_fee * freezing_threshold;

    // The initial balance is sufficient to only pay the reservation for installing code
    // and the freeze threshold (compute allocation + base fee).
    let initial_balance =
        max_install_code_cost() + compute_allocation_cycles + base_per_second_fee_cycles;

    let canister_id = env.create_canister_with_cycles(
        None,
        initial_balance,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .with_freezing_threshold(freezing_threshold)
                .with_log_memory_limit(0) // Disable canister logging.
                .build(),
        ),
    );

    let install_code_ingress_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister_id,
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            wasm()
                .instruction_counter_is_at_least(MAX_INSTRUCTIONS)
                .build(),
        )
        .encode(),
    );

    // Start execution of `install_code`.
    env.tick();

    // Send a normal ingress message while the canister is being installed:
    // this fails because the canister has no more liquid cycles left at this point,
    // i.e., consuming any cycles would make the canister frozen.
    assert_eq!(
        env.cycle_balance(canister_id),
        (compute_allocation_cycles + base_per_second_fee_cycles).get()
    );
    let sender = PrincipalId::new_anonymous();
    let method = "update";
    let payload = wasm()
        .instruction_counter_is_at_least(MAX_INSTRUCTIONS)
        .build();
    let err = env
        .send_ingress_safe(sender, canister_id, method, payload.clone())
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    let ingress_induction_cost =
        match env.ingress_message_cost(sender, canister_id, method, payload) {
            IngressInductionCost::Fee { payer: _, cost } => cost,
            cost => panic!("Unexpected ingress induction cost: {cost:?}"),
        };
    assert_eq!(
        err.description(),
        format!(
            "Canister {canister_id} is out of cycles: \
             please top up the canister with at least {ingress_induction_cost} additional cycles",
        )
    );

    // We are awaiting the ingress message for up to 100 rounds (arbitrary value high enough for the message to complete).
    let err = env.await_ingress(install_code_ingress_id, 100).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterInstructionLimitExceeded);

    // The cycles to cover the freeze threshold are only needed to keep the canister unfrozen
    // and are not actually used.
    let unused_cycles = compute_allocation_cycles + base_per_second_fee_cycles;
    assert_eq!(env.cycle_balance(canister_id), unused_cycles.get());
}

#[test]
fn dts_pending_upgrade_with_heartbeat() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let controller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id, controller.get()])
            .build(),
    );

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let upgrade = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        env.send_ingress(user_id, controller, "update", payload)
    };

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Processing)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 30).unwrap();

    env.advance_time(Duration::from_secs(1));

    env.tick();

    let read = env.send_ingress(user_id, canister, "read", vec![]);
    let result = env.await_ingress(read, 10).unwrap();

    let mut expected = vec![12; 10]; // heartbeat
    expected.extend([78; 5].iter()); // global timer is disabled after upgrade
    expected.extend([78; 5].iter()); // work()
    assert_eq!(result, WasmResult::Reply(expected));
}

/// In this test the controller canister sends `n` install code messages to `n`
/// different canisters. Execution of each message requires multiple slices.
/// The test also sends `n` ingress messages to query the canister status of
/// each canister.
///
/// The expectations:
/// - the install code messages run one by one.
/// - the canister status messages are completed immediately except for one
///   for the canister on which the code install is running.
#[test]
fn dts_scheduling_of_install_code() {
    let (env, _) = dts_install_code_env(
        NumInstructions::from(5_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let controller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id, controller.get()])
            .build(),
    );

    let n = 10;
    let mut canister = vec![];

    for i in 0..n {
        let id = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, settings.clone());
        eprintln!("canister[{i}] = {id}");
        canister.push(id);
    }

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let mut ingress = vec![];
    for c in canister.iter() {
        let args = InstallCodeArgs::new(CanisterInstallMode::Install, *c, binary.clone(), vec![]);
        let install = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller, "update", install);
        ingress.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress for other install code messages.
        env.tick();
    }

    // This ingress message is not blocked by the first install code message.
    let status_last = env.send_ingress(
        user_id,
        IC_00,
        Method::CanisterStatus,
        Encode!(&CanisterIdRecord::from(canister[n - 1])).unwrap(),
    );

    let mut status = vec![];

    // All other canister status messages are completed except for the canister
    // on which the code install is running.
    for c in canister.iter().take(n - 1) {
        let id = env.send_ingress(
            user_id,
            IC_00,
            Method::CanisterStatus,
            Encode!(&CanisterIdRecord::from(*c)).unwrap(),
        );
        status.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress for other install code messages.
        env.tick();
    }

    match ingress_state(env.ingress_status(&status_last)).unwrap() {
        IngressState::Completed(_) => {}
        ingress_state => {
            unreachable!("Expected message to complete, got {:?}", ingress_state)
        }
    }

    // The canister status ingress message for the canister on which
    // the code is installing is blocked.
    assert_eq!(
        ingress_state(env.ingress_status(&status[0])),
        Some(IngressState::Received)
    );

    // Canister status ingress messages for all other canisters are executed.
    for s in status.iter().take(n - 1).skip(1) {
        assert_matches!(
            ingress_state(env.ingress_status(s)),
            Some(IngressState::Completed(..))
        );
    }

    // All install code messages are pending.
    for i in ingress.iter() {
        assert_eq!(
            ingress_state(env.ingress_status(i)),
            Some(IngressState::Processing)
        );
    }

    env.set_checkpoints_enabled(false);

    // Now install code messages start making progress.
    for k in 0..n {
        env.await_ingress(ingress[k].clone(), 30).unwrap();
        // All subsequent install code messages are still blocked.
        for i in ingress.iter().skip(k + 1) {
            assert_eq!(
                ingress_state(env.ingress_status(i)),
                Some(IngressState::Processing)
            );
        }
    }

    // By this time all canister status messages should be processed.
    for s in status.iter() {
        match ingress_state(env.ingress_status(s)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }
}

/// This test creates `n` controller canisters and `n` ordinary canisters.
/// The first half of the controllers install code on the first half of the
/// canisters. The second half of the controllers query the canister status
/// of the second half of the canisters.
/// The expectation is that canister status messages are not blocked the
/// long-running install code messages.
#[test]
fn dts_pending_install_code_does_not_block_subnet_messages_of_other_canisters() {
    let (env, _) = dts_install_code_env(
        NumInstructions::from(5_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        controller.push(id);
    }

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(controller.iter().map(|x| x.get()).collect())
            .build(),
    );

    let mut canister = vec![];

    for _ in 0..n {
        let id = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, settings.clone());
        canister.push(id);
    }

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let mut install = vec![];
    for i in 0..n / 2 {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            canister[i],
            binary.clone(),
            vec![],
        );
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        install.push(id);
    }

    let mut status = vec![];
    for i in n / 2..n {
        let arg = Encode!(&CanisterIdRecord::from(canister[i])).unwrap();
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::CanisterStatus,
                call_args()
                    .other_side(arg)
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        status.push(id);
    }

    for _ in 0..5 {
        // With checkpoints enabled, the first install code will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    // All install code messages are pending.
    for i in install.iter() {
        assert_eq!(
            ingress_state(env.ingress_status(i)),
            Some(IngressState::Processing)
        );
    }

    // All canister status messages should be processed because they are not
    // blocked by install code messages.
    for s in status.iter() {
        match ingress_state(env.ingress_status(s)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    env.set_checkpoints_enabled(false);

    // Now install code messages start making progress.
    for k in 0..n / 2 {
        env.await_ingress(install[k].clone(), 30).unwrap();
        // All subsequent install code messages are still blocked.
        for i in install.iter().skip(k + 1) {
            assert_eq!(
                ingress_state(env.ingress_status(i)),
                Some(IngressState::Processing)
            );
        }
    }
}

/// This test starts a long-running execution of an update message and sends a
/// canister status and an upgrade subnet messages for the same canisters.
/// The expectation is that the subnet messages are blocked by the
/// long-running update message.
#[test]
fn dts_pending_execution_blocks_subnet_messages_to_the_same_canister() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id])
            .build(),
    );

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let update = env.send_ingress(user_id, canister, "update", vec![]);

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    let status = {
        let arg = Encode!(&CanisterIdRecord::from(canister)).unwrap();
        env.send_ingress(user_id, IC_00, Method::CanisterStatus, arg)
    };

    let upgrade = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    // The `update` canister call should be aborted.
    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );
    // The `ic0.install_code` should be blocked by the aborted execution.
    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Received)
    );
    // The `ic0.canister_status` is allowed for aborted canisters.
    env.await_ingress(status, 30).unwrap();

    env.set_checkpoints_enabled(false);

    env.await_ingress(update, 30).unwrap();
    env.await_ingress(upgrade, 30).unwrap();
}

#[test]
fn dts_aborted_execution_does_not_block_subnet_messages() {
    fn test<F: Fn(CanisterId) -> (Method, CallArgs)>(runs_on_aborted_canister: bool, f: F) {
        let slice_instruction_limit = 1_000_000;
        let env = dts_env(
            NumInstructions::from(slice_instruction_limit * 10),
            NumInstructions::from(slice_instruction_limit),
        );

        let user_id = PrincipalId::new_anonymous();
        let other_canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        let aborted_canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id, other_canister_id.get()])
                        .build(),
                ),
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();

        let (method, args) = f(aborted_canister_id);

        env.set_checkpoints_enabled(true);
        // With checkpoints enabled, the update call will be aborted.
        let long_execution_id = env.send_ingress(
            user_id,
            aborted_canister_id,
            "update",
            wasm()
                .instruction_counter_is_at_least(slice_instruction_limit)
                .reply_data(&[42])
                .build(),
        );

        let subnet_message = wasm()
            .call_with_cycles(IC_00, method, args, 100_000_000_000_u128)
            .build();

        let subnet_message_id =
            env.send_ingress(user_id, other_canister_id, "update", subnet_message);

        // Need 2 rounds for the response to the subnet message to be inducted.
        for _ in 0..2 {
            env.tick();
        }

        // Make sure the aborted execution is still processing.
        assert_eq!(
            ingress_state(env.ingress_status(&long_execution_id)),
            Some(IngressState::Processing)
        );

        if runs_on_aborted_canister {
            // Make sure the execution of the method completed, despite the effective canister is aborted.
            assert!(matches!(
                ingress_state(env.ingress_status(&subnet_message_id)),
                Some(IngressState::Completed(WasmResult::Reply(_)))
            ));
        } else {
            // Make sure the execution of the method is still pending, because the effective canister is aborted.
            assert_eq!(
                ingress_state(env.ingress_status(&subnet_message_id)),
                Some(IngressState::Processing)
            );
        }

        env.set_checkpoints_enabled(false);
        for _ in 0..5 {
            env.tick();
        }

        // Make sure the aborted message is completed.
        assert_eq!(
            ingress_state(env.ingress_status(&long_execution_id)),
            Some(IngressState::Completed(WasmResult::Reply(vec![42])))
        );
    }
    fn test_supported<F: Fn(CanisterId) -> (Method, CallArgs)>(f: F) {
        test(true, f);
    }
    fn test_unsupported<F: Fn(CanisterId) -> (Method, CallArgs)>(f: F) {
        test(false, f);
    }

    test_supported(|aborted_canister_id| {
        let args = CanisterIdRecord::from(aborted_canister_id).encode();
        (Method::CanisterStatus, call_args().other_side(args))
    });

    test_unsupported(|aborted_canister_id| {
        let args = CanisterIdRecord::from(aborted_canister_id).encode();
        (Method::StartCanister, call_args().other_side(args))
    });
}

#[test]
fn dts_paused_execution_blocks_deposit_cycles() {
    let slice_instruction_limit = 1_000_000;
    let env = dts_env(
        NumInstructions::from(slice_instruction_limit * 10),
        NumInstructions::from(slice_instruction_limit),
    );

    let user_id = PrincipalId::new_anonymous();
    let long_canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let other_canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let long_execution_id = env.send_ingress(
        user_id,
        long_canister_id,
        "update",
        wasm()
            .instruction_counter_is_at_least(slice_instruction_limit * 5)
            .reply_data(&[42])
            .build(),
    );

    let args = Encode!(&CanisterIdRecord::from(long_canister_id)).unwrap();
    let deposit_cycles = wasm()
        .call_with_cycles(
            IC_00,
            Method::DepositCycles,
            call_args()
                .other_side(args)
                .on_reject(wasm().reject_message().reject())
                .on_reply(wasm().reply_data(&[43])),
            1_u128,
        )
        .build();

    let deposit_message_id = env.send_ingress(user_id, other_canister_id, "update", deposit_cycles);

    assert_eq!(
        ingress_state(env.ingress_status(&long_execution_id)),
        Some(IngressState::Processing)
    );

    // Make sure the `ic0.deposit_cycles` is not completed,
    // as the effective canister is paused.
    assert_eq!(
        ingress_state(env.ingress_status(&deposit_message_id)),
        Some(IngressState::Processing)
    );

    for _ in 0..5 {
        env.tick();
    }

    // Make sure the paused message is completed.
    assert_eq!(
        ingress_state(env.ingress_status(&long_execution_id)),
        Some(IngressState::Completed(WasmResult::Reply(vec![42])))
    );
    // Make sure the `ic0.deposit_cycles` is completed.
    assert_eq!(
        ingress_state(env.ingress_status(&deposit_message_id)),
        Some(IngressState::Completed(WasmResult::Reply(vec![43])))
    );
}

/// This test starts execution of a long-running install code message
/// and sends an update message to the same canister.
/// The expectation is that the update message is blocked.
#[test]
fn dts_pending_install_code_blocks_update_messages_to_the_same_canister() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id])
            .build(),
    );

    let canister = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, settings);

    let payload = InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister,
        binary.clone(),
        vec![],
    );
    env.execute_ingress_as(user_id, IC_00, Method::InstallCode, payload.encode())
        .unwrap();

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let install = {
        let payload =
            InstallCodeArgs::new(CanisterInstallMode::Reinstall, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, payload.encode())
    };

    let update = env.send_ingress(user_id, canister, "update", vec![]);

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Received)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(install, 30).unwrap();
    env.await_ingress(update, 30).unwrap();
}

/// This test runs multiple long-running update and install code messages.
/// It also runs a short message every round.
/// The expectation that all messages eventually complete.
#[test]
fn dts_long_running_install_and_update() {
    let slice_instruction_limit = 15_000_000;
    let env = dts_env(
        NumInstructions::from(100_000_000),
        NumInstructions::from(slice_instruction_limit),
    );

    let user_id = PrincipalId::new_anonymous();

    let n = 5;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        controller.push(id);
    }

    let mut canister = vec![];

    for controller_id in controller.iter() {
        let settings = Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![controller_id.get()])
                .build(),
        );

        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                settings.clone(),
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let mut install = vec![];
    for i in 0..n {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            canister[i],
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
        );
        let payload = wasm()
            .call_simple(
                IC_00,
                Method::InstallCode,
                call_args()
                    .other_side(args.encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let id = env.send_ingress(user_id, controller[i], "update", payload);
        install.push(id);
    }

    let mut long_update = vec![];
    let mut short_update = vec![];

    for i in 0..3 * n {
        let work = wasm()
            .instruction_counter_is_at_least(slice_instruction_limit)
            .message_payload()
            .append_and_reply()
            .build();
        let id = env.send_ingress(user_id, canister[i % n], "update", work);
        long_update.push(id);

        let id = env.send_ingress(
            user_id,
            short,
            "update",
            wasm().push_int(0).reply_int().build(),
        );
        short_update.push(id);

        if i % (2 * n) == 0 {
            env.set_checkpoints_enabled(true);
            env.tick();
            env.set_checkpoints_enabled(false);
        } else {
            env.tick();
        }
    }

    for msg_id in short_update.iter() {
        match ingress_state(env.ingress_status(msg_id)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    for msg_id in long_update.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }

    for msg_id in install.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }
}

/// This test runs long-running update and install code messages. Each update
/// message performs a call with a long-running response callback.
/// It also runs a short message every round.
/// The expectation that all messages eventually complete.
#[test]
fn dts_long_running_calls() {
    let env = dts_env(
        NumInstructions::from(100_000_000),
        NumInstructions::from(1_000_000),
    );

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut canister = vec![];

    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let mut long_update = vec![];
    let mut short_update = vec![];

    for i in 0..30 {
        let work = wasm()
            .instruction_counter_is_at_least(1_000_000)
            .message_payload()
            .append_and_reply()
            .build();
        let payload = wasm()
            .inter_update(
                canister[(i + 1) % n],
                call_args().other_side(work.clone()).on_reply(work),
            )
            .build();
        let id = env.send_ingress(user_id, canister[i % n], "update", payload);
        long_update.push(id);

        let id = env.send_ingress(
            user_id,
            short,
            "update",
            wasm().push_int(0).reply_int().build(),
        );
        short_update.push(id);

        if i % 20 == 0 {
            env.set_checkpoints_enabled(true);
            env.tick();
            env.set_checkpoints_enabled(false);
        } else {
            env.tick();
        }
    }

    for msg_id in short_update.iter() {
        match ingress_state(env.ingress_status(msg_id)).unwrap() {
            IngressState::Completed(_) => {}
            ingress_state => {
                unreachable!("Expected message to complete, got {:?}", ingress_state)
            }
        }
    }

    for msg_id in long_update.into_iter() {
        env.await_ingress(msg_id, 100).unwrap();
    }
}

#[test]
fn dts_unrelated_subnet_messages_make_progress() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id])
            .build(),
    );

    let canister = env
        .install_canister_with_cycles(
            binary.clone(),
            vec![],
            settings.clone(),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let unrelated_canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Enable the checkpoints so that the first install code message is always
    // aborted and doesn't make progress.
    env.set_checkpoints_enabled(true);

    let upgrade = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    for _ in 0..5 {
        // With checkpoints enabled, the update message will be repeatedly
        // aborted, so there will be no progress.
        env.tick();
    }

    let status = {
        let arg = Encode!(&CanisterIdRecord::from(unrelated_canister)).unwrap();
        env.send_ingress(user_id, IC_00, Method::CanisterStatus, arg)
    };

    env.await_ingress(status, 30).unwrap();

    assert_eq!(
        ingress_state(env.ingress_status(&upgrade)),
        Some(IngressState::Processing)
    );

    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_update_is_correct() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(170_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let update = env.send_ingress(user_id, canister, "update", vec![]);
    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    // The ingress time is pinned to the batch time of the round in which the
    // message first started executing. Depending on the OS page size that may be
    // the round triggered by `send_ingress` or the subsequent `tick`, so capture
    // the pinned time from the ingress status rather than assuming it equals the
    // current time. The rest of the test verifies that this pinned time does not
    // change while the DTS execution is in progress.
    let original_time = ingress_time(env.ingress_status(&update)).unwrap();

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&update)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&update)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(update, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_install_is_correct() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(170_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let original_time = env.time();

    let install = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Reinstall, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&install)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&install)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(install, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_upgrade_is_correct() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let original_time = env.time();

    let install = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&install)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&install)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&install)) == Some(IngressState::Processing) {
        assert_eq!(
            ingress_time(env.ingress_status(&install)),
            Some(original_time)
        );
        env.tick();
    }

    env.await_ingress(install, 30).unwrap();
}

#[test]
fn dts_ingress_status_of_update_with_call_is_correct() {
    // start with a large slice limit so installations just work.
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_checkpoints_enabled(true)
        .build();

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let user_id = PrincipalId::new_anonymous();

    let a_id = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let b_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // reduce slice limit to provoke test conditions
    let env = env.restart_node_with_config(dts_state_machine_config(dts_subnet_config(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000),
    )));

    let b = wasm()
        .stable64_grow(1) // cost: 1 wasm page = 16 os pages -> 5k * 16 = 80k instructions
        .stable64_fill(0, 0, 24_000) // 24_000 cost: 6 stable pages dirtied (6*5k) + 6 heap pages (6*5k) (because vec is allocated there) + 24k for the bytes = 84k instructions
        .stable64_fill(0, 0, 24_000) // 84k * 3 = 252k -> this message needs at least two slices.
        .stable64_fill(0, 0, 24_000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 24_000)
        .stable64_fill(0, 0, 24_000)
        .stable64_fill(0, 0, 24_000)
        .inter_update(b_id, call_args().other_side(b))
        .build();

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let original_time = env.time();
    let update = env.send_ingress(user_id, a_id, "update", a);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.advance_time(Duration::from_secs(60));

    env.tick();

    env.advance_time(Duration::from_secs(60));

    // Enable the checkpoints to abort the update message execution.
    env.set_checkpoints_enabled(true);

    env.tick();

    assert_eq!(
        ingress_state(env.ingress_status(&update)),
        Some(IngressState::Processing)
    );

    assert_eq!(
        ingress_time(env.ingress_status(&update)),
        Some(original_time)
    );

    env.set_checkpoints_enabled(false);

    let mut call_time = None;

    // The ingress time must not change during DTS execution.
    while ingress_state(env.ingress_status(&update)) == Some(IngressState::Processing) {
        if ingress_time(env.ingress_status(&update)) != Some(original_time) {
            // The ingress time in the `Processing` state may change only once
            // when the call is made.
            if let Some(call_time) = call_time {
                assert_eq!(ingress_time(env.ingress_status(&update)), Some(call_time));
            }
            call_time = ingress_time(env.ingress_status(&update));
        }
        env.tick();
    }

    call_time.unwrap();

    env.await_ingress(update, 100).unwrap();
}

/// Causes a canister to run out of cycles with a paused / aborted upgrade and
/// returns the result of the upgrade.
fn impl_dts_canister_with_upgrade_is_uninstalled_due_to_resource_charges(
    aborted: bool,
) -> Result<WasmResult, UserError> {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(170000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_compute_allocation(1)
            .build(),
    );

    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();
    // Checkpointing will abort the upgrade after each round.
    env.set_checkpoints_enabled(aborted);

    let upgrade = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };
    env.tick();

    // Advance the time enough to get the canister uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));
    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    env.await_ingress(upgrade, 60)
}

#[test]
fn dts_canister_with_aborted_upgrade_is_uninstalled_due_to_resource_charges() {
    let result = impl_dts_canister_with_upgrade_is_uninstalled_due_to_resource_charges(true);

    // Canister with aborted upgrade is uninstalled. Upgrade fails.
    assert_matches!(
        result,
        Err(err) if err.code() == ErrorCode::CanisterWasmModuleNotFound
    );
}

#[test]
fn dts_canister_with_paused_upgrade_is_not_uninstalled_due_to_resource_charges() {
    let result = impl_dts_canister_with_upgrade_is_uninstalled_due_to_resource_charges(false);

    // Canister is only uninstalled after paused upgrade completes successfully.
    assert_eq!(result, Ok(WasmResult::Reply(EmptyBlob.encode())));
}

fn impl_dts_canister_with_update_is_uninstalled_due_to_resource_charges(
    aborted: bool,
) -> Result<WasmResult, UserError> {
    // The first write to a Wasm page in `$work` is charged the full
    // deterministic-memory-tracker page-fault overhead, which is OS-page-size
    // dependent (2 x 16 OS pages x 5_000 = 160_000 on 4 KiB hosts such as Linux,
    // 2 x 4 OS pages x 5_000 = 40_000 on 16 KiB hosts such as arm64-darwin). The
    // slice limit must exceed that (un-splittable) charge on either platform so
    // execution can make progress, while staying well below the total `$work`
    // cost so execution still spans multiple rounds and can be aborted. `$work`
    // does enough page-size-independent `memory.fill` work (~1 instruction/byte)
    // that it spans multiple rounds on both platforms.
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(200_000),
    );
    let binary = wat2wasm(DTS_WAT);
    let user_id = PrincipalId::new_anonymous();

    let settings = Some(
        CanisterSettingsArgsBuilder::new()
            .with_compute_allocation(1)
            .build(),
    );
    let canister = env
        .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Checkpointing will abort the update after each round.
    env.set_checkpoints_enabled(aborted);

    let update = env.send_ingress(user_id, canister, "update", vec![]);
    env.tick();

    // Advance the time so that the canister gets uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));
    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    env.await_ingress(update, 100)
}

#[test]
fn dts_canister_with_aborted_update_is_uninstalled_due_to_resource_charges() {
    let result = impl_dts_canister_with_update_is_uninstalled_due_to_resource_charges(true);

    // Canister with aborted update is uninstalled. Update fails.
    assert_matches!(
        result,
        Err(err) if err.code() == ErrorCode::CanisterWasmModuleNotFound
    );
}

#[test]
fn dts_canister_with_paused_update_is_not_uninstalled_due_to_resource_charges() {
    let result = impl_dts_canister_with_update_is_uninstalled_due_to_resource_charges(false);

    // Canister is only uninstalled after paused update completes successfully.
    assert_matches!(result, Ok(WasmResult::Reply(_)));
}

#[test]
fn dts_serialized_and_runtime_states_are_equal() {
    fn run(restart_node: bool) -> CryptoHashOfState {
        let subnet_config = dts_subnet_config(
            NumInstructions::from(1_000_000_000),
            NumInstructions::from(250_000),
        );
        let num_canisters = subnet_config.scheduler_config.scheduler_cores * 2;
        let state_machine_config = dts_state_machine_config(subnet_config);
        let env = StateMachine::new_with_config(state_machine_config.clone());

        let mut canister_ids = vec![];
        for _ in 0..num_canisters {
            let canister_id = env
                .install_canister_with_cycles(
                    UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                    vec![],
                    None,
                    INITIAL_CYCLES_BALANCE,
                )
                .unwrap();
            canister_ids.push(canister_id);
        }

        env.set_checkpoints_enabled(true);
        for canister_id in canister_ids.iter() {
            let work = wasm()
                .instruction_counter_is_at_least(10_000)
                .reply()
                .build();
            env.send_ingress(PrincipalId::new_anonymous(), *canister_id, "update", work);
        }
        let env = if restart_node {
            env.restart_node_with_config(state_machine_config)
        } else {
            env
        };
        env.tick();
        env.await_state_hash()
    }

    let hash_without_restart = run(false);
    let hash_with_restart = run(true);
    assert_eq!(hash_without_restart, hash_with_restart);
}

fn get_global_counter(env: &StateMachine, canister_id: CanisterId) -> u64 {
    let query = wasm().get_global_counter().reply_int64().build();
    match env.query(canister_id, "query", query).unwrap() {
        WasmResult::Reply(r) => {
            let bytes: [u8; 8] = r.try_into().unwrap();
            u64::from_le_bytes(bytes)
        }
        WasmResult::Reject(_) => {
            unreachable!("unexpected reject result");
        }
    }
}

fn get_canister_version(env: &StateMachine, canister_id: CanisterId) -> u64 {
    let query = wasm().canister_version().reply_int64().build();
    match env.query(canister_id, "query", query).unwrap() {
        WasmResult::Reply(r) => {
            let bytes: [u8; 8] = r.try_into().unwrap();
            u64::from_le_bytes(bytes)
        }
        WasmResult::Reject(_) => {
            unreachable!("unexpected reject result");
        }
    }
}

#[test]
fn dts_heartbeat_works() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .build();

    let set_heartbeat = wasm()
        .set_heartbeat(heartbeat)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat)
        .unwrap();

    // 3) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(3, base_canister_version);

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    for i in 1..10 {
        env.tick();
        // Each heartbeat takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
        assert_eq!(
            base_canister_version + i / 3,
            get_canister_version(&env, canister_id)
        );
    }
}

#[test]
fn dts_heartbeat_resume_after_abort() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .build();

    let set_heartbeat = wasm()
        .set_heartbeat(heartbeat)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    // 3) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(3, base_canister_version);

    env.set_checkpoints_enabled(true);

    for _ in 0..3 {
        env.tick();
        assert_eq!(0, get_global_counter(&env, canister_id));
        assert_eq!(
            base_canister_version,
            get_canister_version(&env, canister_id)
        );
    }

    env.set_checkpoints_enabled(false);

    for i in 1..10 {
        env.tick();
        // Each heartbeat takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
        assert_eq!(
            base_canister_version + i / 3,
            get_canister_version(&env, canister_id)
        );
    }
}

#[test]
fn dts_heartbeat_with_trap() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .trap()
        .build();

    let set_heartbeat = wasm()
        .set_heartbeat(heartbeat)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    // 3) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(3, base_canister_version);

    for _ in 1..10 {
        env.tick();
        assert_eq!(0, get_global_counter(&env, canister_id));
        assert_eq!(
            base_canister_version,
            get_canister_version(&env, canister_id)
        );
    }
}

#[test]
fn dts_heartbeat_does_not_prevent_canister_from_stopping() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let heartbeat = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .build();

    let set_heartbeat = wasm()
        .set_heartbeat(heartbeat)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    for i in 1..10 {
        env.tick();
        // Each heartbeat takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
    }

    env.stop_canister(canister_id).unwrap();

    assert_eq!(
        ErrorCode::CanisterStopped,
        env.query(canister_id, "query", vec![]).unwrap_err().code()
    );
}

#[test]
fn dts_heartbeat_does_not_prevent_upgrade() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let heartbeat = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .build();

    let set_heartbeat = wasm()
        .set_heartbeat(heartbeat)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    for i in 1..10 {
        env.tick();
        // Each heartbeat takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
    }

    let empty_wasm = wat2wasm("(module)");

    let result = env.upgrade_canister(canister_id, empty_wasm, vec![]);

    assert_eq!(Ok(()), result);
}

#[test]
fn dts_global_timer_one_shot_works() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) install code.
    assert_eq!(1, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .build();

    let set_global_timer = wasm()
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    // 2) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(2, base_canister_version);

    for i in 1..10 {
        env.tick();
        if i < 3 {
            // The timer takes three rounds to execute.
            assert_eq!(0, get_global_counter(&env, canister_id));
            assert_eq!(
                base_canister_version,
                get_canister_version(&env, canister_id)
            );
        } else {
            // The timer is one shot.
            assert_eq!(1, get_global_counter(&env, canister_id));
            // Plus one timer update.
            assert_eq!(
                base_canister_version + 1,
                get_canister_version(&env, canister_id)
            );
        }
    }
}

#[test]
fn dts_heartbeat_does_not_starve_when_global_timer_is_long() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let heartbeat = wasm().instruction_counter_is_at_least(1_100_000).build();

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .build();

    let set_heartbeat_and_global_timer = wasm()
        .set_heartbeat(heartbeat)
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat_and_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    // 3) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(3, base_canister_version);

    // Check that GlobalTimer is the next scheduled method, since
    // we expect it to be executed next.
    assert_eq!(
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .get_next_scheduled_method(),
        NextScheduledMethod::GlobalTimer
    );

    for repetition in 0..10 {
        // Each repetition executes one timer.
        for timer_round in 1..4 {
            env.tick();
            // Each timer takes three rounds to execute.
            assert_eq!(
                repetition + timer_round / 3,
                get_global_counter(&env, canister_id)
            );
            assert_eq!(
                base_canister_version + 2 * repetition + timer_round / 3,
                get_canister_version(&env, canister_id)
            );
        }

        // Each repetition executes one heartbeat.
        for heartbeat_round in 1..4 {
            env.tick();
            // get_global_counter is const hence we are executing heartbeat.
            assert_eq!(repetition + 1, get_global_counter(&env, canister_id));
            // Each heartbeat takes three rounds to execute.
            assert_eq!(
                base_canister_version + 2 * repetition + 1 + heartbeat_round / 3,
                get_canister_version(&env, canister_id)
            );
        }
    }
}

#[test]
fn dts_global_timer_resume_after_abort() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .build();

    let set_global_timer = wasm()
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    env.set_checkpoints_enabled(true);

    for _ in 0..3 {
        env.tick();
        assert_eq!(0, get_global_counter(&env, canister_id));
    }

    env.set_checkpoints_enabled(false);

    for i in 1..10 {
        env.tick();
        // Each timer takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
    }
}

#[test]
fn dts_global_timer_does_not_prevent_canister_from_stopping() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .build();

    let set_global_timer = wasm()
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    for i in 1..10 {
        env.tick();
        // Each timer takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
    }

    env.stop_canister(canister_id).unwrap();

    assert_eq!(
        ErrorCode::CanisterStopped,
        env.query(canister_id, "query", vec![]).unwrap_err().code()
    );
}

#[test]
fn dts_global_timer_with_trap() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) install code.
    assert_eq!(1, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .trap()
        .build();

    let set_heartbeat_and_global_timer = wasm()
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat_and_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));

    // 2) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(2, base_canister_version);

    for _ in 1..10 {
        env.tick();
        assert_eq!(0, get_global_counter(&env, canister_id));
        assert_eq!(
            base_canister_version,
            get_canister_version(&env, canister_id)
        );
    }
}

#[test]
fn dts_global_timer_does_not_prevent_upgrade() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(500_000),
    );

    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(1_100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .build();

    let set_global_timer = wasm()
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0_u64.to_le_bytes().to_vec()));
    for i in 1..10 {
        env.tick();
        // Each timer takes three rounds to execute.
        assert_eq!(i / 3, get_global_counter(&env, canister_id));
    }

    let empty_wasm = wat2wasm("(module)");

    let result = env.upgrade_canister(canister_id, empty_wasm, vec![]);

    assert_eq!(Ok(()), result);
}

#[test]
fn dts_abort_paused_execution_on_state_switch() {
    // Installing the universal canister copies its data segment into memory in a
    // single (un-splittable) bulk memory operation that now costs ~240K
    // instructions: the first write to each touched Wasm page is charged the full
    // deterministic-memory-tracker page overhead (2 * OS pages * 5_000). The slice
    // limit must therefore exceed that op, hence 300K (round = slice + slice / 2 =
    // 450K).
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(300_000),
    );

    let user_id = PrincipalId::new_anonymous();
    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Snapshot the clean state that doesn't have any paused executions.
    let clean_state = env.get_latest_state();

    // Start and pause a long-running execution.
    let update = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .reply_data(&[42])
        .build();
    env.send_ingress(user_id, canister_id, "update", update.clone());
    env.tick();
    assert_eq!(
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .next_execution(),
        NextExecution::ContinueLong,
    );

    // Emulate switching of the state due to state sync.
    env.replace_canister_state(clean_state, canister_id);

    assert_eq!(
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .next_execution(),
        NextExecution::None,
    );

    // Execute a new message on the new state.
    let result = env.execute_ingress(canister_id, "update", update).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![42]));
}

#[test]
fn dts_abort_after_dropping_memory_on_state_switch() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(250_000_000),
    );

    let user_id = PrincipalId::new_anonymous();

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update update")
                ;; We need to generate at least MIN_PAGES_TO_FREE dirty pages
                ;; to force freeing pages (see page_allocator/mmap.rs).
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (call $msg_reply)
            )
            (func (export "canister_update long_update")
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (memory.fill (i32.const 0) (i32.const 42) (i32.const 65536000))
                (call $msg_reply)
            )
            (memory 1000)
        )"#;

    let binary = wat2wasm(wat);

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Snapshot the clean state that doesn't have any paused executions.
    let clean_state = env.get_latest_state();

    // Generate dirty pages.
    env.execute_ingress(canister_id, "update", vec![]).unwrap();

    // Start and pause a long-running execution.
    env.send_ingress(user_id, canister_id, "long_update", vec![]);
    env.tick();
    assert_eq!(
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .next_execution(),
        NextExecution::ContinueLong,
    );

    env.replace_canister_state(clean_state, canister_id);

    // Drop all old state to free dirty pages.
    env.remove_old_states();

    // This is unfortunate, but freeing of dirty pages is deferred and happens
    // on a background thread. There is no way to wait for this event except for
    // sleeping.
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .next_execution(),
        NextExecution::None,
    );

    // This will abort the paused execution. The expectation is that aborting
    // doesn't try to access a dropped page.
    let result = env.execute_ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

const WRITE_MORE_THAN_1G_WAT: &str = r#"
(module
    (import "ic0" "msg_reply" (func $msg_reply))
    (func (export "canister_update write")
        (local $i i32)
        (local.set $i (i32.const 1073745920)) ;; 1GiB + 4096
        (loop $loop
            (i32.store (local.get $i) (i32.const 1))
            (br_if $loop (local.tee $i (i32.sub (local.get $i) (i32.const 4096))))
        )
        (call $msg_reply)
    )
    (memory 16385) ;; 1GiB + 65536
)"#;

#[test]
fn yield_for_dirty_pages_copy_works() {
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(WRITE_MORE_THAN_1G_WAT).unwrap();
    let canister_id = env
        .install_canister_with_cycles(wasm, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let mut payload = ic_state_machine_tests::PayloadBuilder::new().with_nonce(0);
    // Send two ingress messages to the same canister.
    for _ in 0..2 {
        payload = payload.ingress(PrincipalId::new_anonymous(), canister_id, "write", vec![]);
    }
    let message_ids = payload.ingress_ids();
    env.execute_payload(payload);

    // Neither of messages should be completed after the first round.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Processing)
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );

    env.tick();
    env.tick();

    // Only the first message must be completed after three rounds.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Completed(_))
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );
}

#[test]
fn yield_for_dirty_pages_copy_works_for_many_canisters() {
    let scheduler_cores = 4;
    let num_canisters = scheduler_cores;
    let num_messages = 2;
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(WRITE_MORE_THAN_1G_WAT).unwrap();
    let mut canister_ids = vec![];
    let mut payload = ic_state_machine_tests::PayloadBuilder::new().with_nonce(0);
    for _ in 0..num_canisters {
        let canister_id = env
            .install_canister_with_cycles(wasm.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
            .unwrap();
        canister_ids.push(canister_id);

        for _ in 0..num_messages {
            payload = payload.ingress(PrincipalId::new_anonymous(), canister_id, "write", vec![]);
        }
    }
    let message_ids = payload.ingress_ids();
    env.execute_payload(payload);

    let num_completed = || {
        message_ids
            .iter()
            .filter_map(|id| match ingress_state(env.ingress_status(id)) {
                Some(IngressState::Completed(_)) => Some(()),
                Some(IngressState::Received) | Some(IngressState::Processing) => None,
                _ => panic!("Unexpected ingress state"),
            })
            .count()
    };

    // Neither of messages should be completed after the first round.
    assert_eq!(num_completed(), 0);

    env.tick();
    env.tick();

    // Only the first message per scheduler core must be completed after two rounds.
    assert_eq!(num_completed(), scheduler_cores);
}

#[test]
fn heavy_install_code_prevents_another_install_code_to_start_in_the_same_round() {
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let canister_id = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);

    let mut payload = ic_state_machine_tests::PayloadBuilder::new().with_nonce(0);
    // Send two install code messages to the same canister.
    for _ in 0..2 {
        let canister_init = wasm()
            // The instruction limit for subnet messages is 7 billion / 16 = ~438M
            .instruction_counter_is_at_least(2_438_000_000)
            .build();
        payload = payload.ingress(
            PrincipalId::new_anonymous(),
            CanisterId::ic_00(),
            Method::InstallCode,
            InstallCodeArgs::new(
                CanisterInstallMode::Reinstall,
                canister_id,
                UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
                canister_init,
            )
            .encode(),
        );
    }
    let message_ids = payload.ingress_ids();
    env.execute_payload(payload);

    // Neither of messages should be completed after the first round.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Processing)
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );

    env.tick();

    // Only the first message must be completed after two rounds.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Completed(_))
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );
}

#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
const WRITE_MORE_THAN_1G_ON_INIT_WAT: &str = r#"
(module
    (func (export "canister_init")
        (local $i i32)
        (local.set $i (i32.const 1073745920)) ;; 1GiB + 4096
        (loop $loop
            (i32.store (local.get $i) (i32.const 1))
            (br_if $loop (local.tee $i (i32.sub (local.get $i) (i32.const 4096))))
        )
    )
    (memory 16385) ;; 1GiB + 65536
)"#;

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn yield_for_dirty_pages_copy_works_for_install_code() {
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(WRITE_MORE_THAN_1G_ON_INIT_WAT).unwrap();
    let canister_id = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);

    let mut payload = ic_state_machine_tests::PayloadBuilder::new().with_nonce(0);
    // Send two install code messages to the same canister.
    for _ in 0..2 {
        payload = payload.ingress(
            PrincipalId::new_anonymous(),
            CanisterId::ic_00(),
            Method::InstallCode,
            InstallCodeArgs::new(
                CanisterInstallMode::Reinstall,
                canister_id,
                wasm.clone(),
                vec![],
            )
            .encode(),
        );
    }
    let message_ids = payload.ingress_ids();
    env.execute_payload(payload);

    // Neither of messages should be completed after the first round.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Processing)
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );

    env.tick();
    env.tick();

    // Only the first message must be completed after three rounds.
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[0])),
        Some(IngressState::Completed(_))
    );
    assert_matches!(
        ingress_state(env.ingress_status(&message_ids[1])),
        Some(IngressState::Received)
    );
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn yield_for_dirty_pages_copy_works_for_install_code_and_many_canisters() {
    let scheduler_cores = 4;
    let num_canisters = scheduler_cores;
    let num_messages = 2;
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(WRITE_MORE_THAN_1G_ON_INIT_WAT).unwrap();
    let mut canister_ids = vec![];
    let mut payload = ic_state_machine_tests::PayloadBuilder::new().with_nonce(0);
    for _ in 0..num_canisters {
        let canister_id = env.create_canister_with_cycles(None, INITIAL_CYCLES_BALANCE, None);
        canister_ids.push(canister_id);

        for _ in 0..num_messages {
            payload = payload.ingress(
                PrincipalId::new_anonymous(),
                CanisterId::ic_00(),
                Method::InstallCode,
                InstallCodeArgs::new(
                    CanisterInstallMode::Reinstall,
                    canister_id,
                    wasm.clone(),
                    vec![],
                )
                .encode(),
            );
        }
    }
    let message_ids = payload.ingress_ids();
    env.execute_payload(payload);

    let num_completed = || {
        message_ids
            .iter()
            .filter_map(|id| match ingress_state(env.ingress_status(id)) {
                Some(IngressState::Completed(_)) => Some(()),
                Some(IngressState::Received) | Some(IngressState::Processing) => None,
                _ => panic!("Unexpected ingress state"),
            })
            .count()
    };

    // Neither of messages should be completed after the first round.
    assert_eq!(num_completed(), 0);

    env.tick();
    env.tick();

    // Only the first message must be completed after three rounds.
    assert_eq!(num_completed(), 1);

    env.tick();

    // Only the first message must be completed after four rounds.
    assert_eq!(num_completed(), 1);

    env.tick();
    env.tick();

    // Two heavy install code messages must be completed in five rounds.
    assert_eq!(num_completed(), 2);
}

#[test]
fn dts_stop_and_delete_canister_with_concurrent_long_execution() {
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let user_id = PrincipalId::new_anonymous();
    let binary = UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec();

    // Canister `a` is a controller of canisters `b` and `c`.
    let a = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();
    let controlled_by_a = Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![user_id, a.get()])
            .build(),
    );
    // Canister `b`'s `canister_init` burns 100B instructions, i.e. it takes ~50
    // install code slices to install and leaves `b` install code rate limited for
    // ~50 rounds afterwards.
    let b = env
        .install_canister_with_cycles(
            binary.clone(),
            wasm()
                .instruction_counter_is_at_least(100_000_000_000)
                .build(),
            controlled_by_a.clone(),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let c = env
        .install_canister_with_cycles(binary, vec![], controlled_by_a, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Start a long execution on canister `c`: at 2B instructions per slice, 38B
    // instructions take ~19 rounds to execute.
    let long_execution = env.send_ingress(
        user_id,
        c,
        "update",
        wasm()
            .instruction_counter_is_at_least(38_000_000_000)
            .reply_data(&[42])
            .build(),
    );
    env.tick();
    assert_eq!(
        env.get_latest_state()
            .canister_state(&c)
            .unwrap()
            .next_execution(),
        NextExecution::ContinueLong,
    );

    // Canister `a` stops canister `b`.
    let stop = env.send_ingress(
        user_id,
        a,
        "update",
        wasm()
            .call_simple(
                IC_00,
                Method::StopCanister,
                call_args().other_side(CanisterIdRecord::from(b).encode()),
            )
            .build(),
    );
    env.await_ingress(stop, 100).unwrap();

    // The long execution on canister `c` is still running.
    assert_eq!(
        ingress_state(env.ingress_status(&long_execution)),
        Some(IngressState::Processing)
    );
    assert_eq!(
        env.get_latest_state()
            .canister_state(&c)
            .unwrap()
            .next_execution(),
        NextExecution::ContinueLong,
    );

    // Canister `a` requests the status of canister `c` (which has a long execution)
    // and deletes canister `b`. Only the reply to the last call (`delete_canister`)
    // is passed on to the ingress message's caller.
    let status_and_delete = env.send_ingress(
        user_id,
        a,
        "update",
        wasm()
            .call_simple(
                IC_00,
                Method::CanisterStatus,
                call_args()
                    .other_side(CanisterIdRecord::from(c).encode())
                    .on_reply(wasm().noop())
                    .on_reject(wasm().noop()),
            )
            .call_simple(
                IC_00,
                Method::DeleteCanister,
                call_args().other_side(CanisterIdRecord::from(b).encode()),
            )
            .build(),
    );
    env.await_ingress(status_and_delete, 100).unwrap();

    // Canister `b` is gone and the long execution on canister `c` eventually completes.
    assert!(env.get_latest_state().canister_state(&b).is_none());
    assert_eq!(
        env.await_ingress(long_execution, 100).unwrap(),
        WasmResult::Reply(vec![42])
    );
}

// Blob that releases canister `B`'s looping update call: the loop only replies
// once `B`'s global data is set to this blob. Nothing in this test sets it, so
// the reply is held back until `B`'s call context is closed by `uninstall_code`.
const LOOP_TRIGGER_BLOB: &[u8] = b"dts-uninstall-code-loop-trigger";
// The reply that canister `B`'s looping update call would produce if it were
// ever released (it never is in this test).
const LOOP_REPLY_BLOB: &[u8] = b"dts-uninstall-code-loop-reply";
// The reply that canister `A` produces once its last call (`uninstall_code` on
// `B`) replies.
const UNINSTALL_CODE_REPLY_BLOB: &[u8] = b"dts-uninstall-code-completed";
// The number of instructions executed by canister `C`'s update call. It is above
// the default `max_instructions_per_slice` (`2B`) so the call runs in DTS across
// multiple rounds, and below the default `max_instructions_per_message` (`40B`)
// so it eventually completes.
const LONG_EXECUTION_INSTRUCTIONS: u64 = 38_000_000_000;

// The following test executes the following scenario:
// - three universal canisters `A`, `B`, and `C` are deployed, with `A` being the
//   sole controller of `B` and `C`;
// - `C` starts a long-running update call which runs in DTS (i.e., it is paused
//   and resumed over multiple rounds);
// - `B`'s `update` method is invoked via an ingress message running a loop that
//   keeps calling `canister_status` on `B`, i.e., `B` holds the reply to that
//   ingress message back indefinitely;
// - `A` fires two concurrent calls: `canister_status` on the canister `C` running
//   in DTS, and `uninstall_code` on the looping canister `B`;
// - `A` replies to its ingress message from the callbacks of its last call
//   (`uninstall_code` on `B`), which is what the test waits for.
#[test]
fn dts_uninstall_code_of_looping_canister_with_concurrent_canister_status() {
    // The default application subnet configuration allows `40B` instructions per
    // message and `2B` instructions per slice, i.e., DTS is in effect for the
    // long-running update call of canister `C` below.
    let env = ic_state_machine_tests::StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let user_id = PrincipalId::new_anonymous();

    // Deploy three universal canisters (without heartbeat so that they do not
    // execute anything in the background).
    let deploy = || {
        env.install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap()
    };
    let canister_a = deploy();
    let canister_b = deploy();
    let canister_c = deploy();

    // Make `B` and `C` controlled by `A` so that `A` may call `canister_status`
    // on `C` and `uninstall_code` on `B`. Note that this makes `B` lose the
    // permission to call `canister_status` on itself, but the loop in `B` also
    // iterates on rejected calls, so it keeps looping either way.
    for canister_id in [canister_b, canister_c] {
        env.update_settings(
            &canister_id,
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![canister_a.get()])
                .build(),
        )
        .unwrap();
    }

    // Start a long-running update call on `C`, which runs in DTS.
    let long_execution_id = env.send_ingress(
        user_id,
        canister_c,
        "update",
        wasm()
            .instruction_counter_is_at_least(LONG_EXECUTION_INSTRUCTIONS)
            .reply_data(&[42])
            .build(),
    );

    // Invoke `B`'s `update` method running the loop via an ingress message: `B`
    // keeps calling `canister_status` on itself and only replies once its global
    // data is set to `LOOP_TRIGGER_BLOB`, which never happens in this test.
    let loop_id = env.send_ingress(
        user_id,
        canister_b,
        "update",
        wasm()
            .loop_until_global_data_set(LOOP_TRIGGER_BLOB, LOOP_REPLY_BLOB)
            .build(),
    );

    // Execute a couple of rounds so that `C`'s execution is paused (i.e., `C`
    // runs in DTS) and `B` is looping.
    for _ in 0..2 {
        env.tick();
    }
    assert_eq!(
        ingress_state(env.ingress_status(&long_execution_id)),
        Some(IngressState::Processing)
    );
    assert_eq!(
        ingress_state(env.ingress_status(&loop_id)),
        Some(IngressState::Processing)
    );

    let payload = wasm()
        // 1. Call `canister_status` on `C`, which is running in DTS.
        .call(
            management::canister_status(canister_c)
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
        )
        // 2. Call `uninstall_code` on the looping canister `B`. This is the last
        //    call by `A` and thus `A` replies to its ingress message from its
        //    callbacks.
        .call(
            management::uninstall_code(canister_b)
                .on_reply(wasm().reply_data(UNINSTALL_CODE_REPLY_BLOB))
                .on_reject(wasm().reject_message().reply_data_append().reply()),
        )
        .build();
    let msg_id = env.send_ingress(user_id, canister_a, "update", payload);

    // Wait until the last call by `A` completes. The number of rounds is an
    // arbitrary value high enough for the calls to complete.
    assert_eq!(
        env.await_ingress(msg_id, 100).unwrap(),
        WasmResult::Reply(UNINSTALL_CODE_REPLY_BLOB.to_vec())
    );
    // Canister `B` has indeed been uninstalled and thus the ingress message
    // whose reply `B` was holding back has been rejected.
    assert!(env.module_hash(canister_b).is_none());
    assert_matches!(
        ingress_state(env.ingress_status(&loop_id)),
        Some(IngressState::Failed(_))
    );
}

#[derive(Clone, Copy, Debug, PartialEq, EnumIter)]
enum StorageReservationMessage {
    /// An update call growing memory.
    Update,
    /// A heartbeat growing memory.
    Heartbeat,
    /// A global timer growing memory.
    GlobalTimer,
    /// `canister_init` growing memory.
    Install,
    /// `canister_init` growing memory after a long-running `(start)`.
    InstallAfterStart,
    /// `canister_pre_upgrade` growing memory.
    PreUpgrade,
    /// `canister_post_upgrade` growing memory.
    PostUpgrade,
    /// `canister_post_upgrade` growing memory after a long-running
    /// `canister_pre_upgrade`.
    PostUpgradeAfterPreUpgrade,
    /// `canister_post_upgrade` growing memory after a long-running `(start)`.
    PostUpgradeAfterStart,
    /// A response callback of an inter-canister call growing memory.
    Response,
    /// A cleanup callback (after the response callback traps) of an
    /// inter-canister call growing memory.
    Cleanup,
}

impl StorageReservationMessage {
    /// Returns true if a long-running stage of `install_code` (that does not
    /// grow memory) precedes the stage growing memory.
    fn has_long_running_previous_stage(self) -> bool {
        matches!(
            self,
            Self::InstallAfterStart
                | Self::PostUpgradeAfterPreUpgrade
                | Self::PostUpgradeAfterStart
        )
    }

    fn is_task(self) -> bool {
        matches!(self, Self::Heartbeat | Self::GlobalTimer)
    }

    fn is_callback(self) -> bool {
        matches!(self, Self::Response | Self::Cleanup)
    }

    fn is_install_code(self) -> bool {
        !matches!(
            self,
            Self::Update | Self::Heartbeat | Self::GlobalTimer | Self::Response | Self::Cleanup
        )
    }

    fn is_upgrade(self) -> bool {
        self.is_install_code() && !matches!(self, Self::Install | Self::InstallAfterStart)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum StorageReservationSlice {
    First,
    Second,
}

/// The outcome of a long-running message growing memory.
struct StorageReservationOutcome {
    /// The result of the message (for a system task: of the update call
    /// arming the system task).
    result: Result<WasmResult, UserError>,
    /// The reserved balance of the canister before the message started.
    reserved_balance_before: Cycles,
    /// The reserved balance of the canister after the message completed.
    reserved_balance: Cycles,
    /// The stable memory usage of the canister after the message completed.
    stable_memory_usage: u64,
    /// The instructions executed by the canister while the message executed.
    instructions_executed: u64,
}

const GIB: u64 = 1 << 30;
/// The instructions executed by the Wasm execution growing memory (it burns
/// instructions until its instruction counter reaches this value). This spans
/// multiple slices so that the execution is still paused after other canisters
/// change the subnet memory usage.
const STORAGE_RESERVATION_TOTAL_INSTRUCTIONS: u64 = 650_000_000;

/// The change in the subnet memory usage due to other canisters on the subnet
/// (not the canister executing the message growing memory).
#[derive(Clone, Copy)]
enum SubnetMemoryChange {
    GrowWhilePaused,
    GrowBeforeExecution,
    ShrinkWhilePaused,
}

/// Executes a long-running message (an update call, a system task,
/// `install_code`, or a response or cleanup callback) that grows stable memory
/// by 185 GiB in the given slice of the Wasm execution growing memory. The
/// canister has the given cycles balance and reserved cycles limit.
///
/// Other canisters grow the subnet memory usage either before the message or
/// while it is paused. For `ShrinkWhilePaused`, they grow before the message
/// and release their memory allocations while it is paused.
fn run_long_running_message_growing_memory(
    message: StorageReservationMessage,
    slice: StorageReservationSlice,
    subnet_memory_change: SubnetMemoryChange,
    canister_balance: Cycles,
    reserved_cycles_limit: u128,
) -> StorageReservationOutcome {
    const SLICE_INSTRUCTIONS: u64 = 100_000_000;
    const TOTAL_INSTRUCTIONS: u64 = STORAGE_RESERVATION_TOTAL_INSTRUCTIONS;
    // The instructions executed by a long-running stage of `install_code`
    // preceding the stage growing memory: the stage must still be paused
    // after other canisters grow the subnet memory usage.
    const PREVIOUS_STAGE_INSTRUCTIONS: u64 = TOTAL_INSTRUCTIONS;
    const STABLE_MEMORY_GROWTH_PAGES: u64 = 3_031_040; // 185 GiB.
    const INITIAL_BALANCE: Cycles = Cycles::new(100_000_000_000_000_000);

    let grow_after_instructions = match slice {
        StorageReservationSlice::First => 0,
        StorageReservationSlice::Second => SLICE_INSTRUCTIONS + SLICE_INSTRUCTIONS / 2,
    };
    let burn = |instructions: u64| format!("(call $burn (i64.const {instructions}))");
    let grow = format!(
        "(if (i64.eq (call $stable64_grow (i64.const {STABLE_MEMORY_GROWTH_PAGES}))
                     (i64.const -1))
             (then (unreachable)))"
    );
    let grow_body = if message.has_long_running_previous_stage() {
        // The stage growing memory starts right after the long-running
        // previous stage completes (in the same round) and grows memory
        // immediately, i.e., in its first slice.
        assert!(slice == StorageReservationSlice::First);
        grow
    } else {
        format!(
            "{} {grow} {}",
            burn(grow_after_instructions),
            burn(TOTAL_INSTRUCTIONS)
        )
    };
    let long_running_start = format!(
        "(func $start {}) (start $start)",
        burn(PREVIOUS_STAGE_INSTRUCTIONS)
    );
    let module = |funcs: &str| {
        wat2wasm(&format!(
            r#"(module
                (import "ic0" "performance_counter"
                    (func $performance_counter (param i32) (result i64)))
                (import "ic0" "stable64_grow"
                    (func $stable64_grow (param i64) (result i64)))
                (import "ic0" "global_timer_set"
                    (func $global_timer_set (param i64) (result i64)))
                (import "ic0" "msg_reply" (func $msg_reply))
                (func $burn (param $instructions i64)
                    (loop $burn
                        (br_if $burn
                            (i64.lt_u
                                (call $performance_counter (i32.const 0))
                                (local.get $instructions)))))
                {funcs}
                (memory 1))"#
        ))
    };
    // The module installed before the message (if any) and the module
    // installed by the message (for `install_code`).
    let (old_module, new_module) = match message {
        StorageReservationMessage::Update => (
            Some(module(&format!(
                r#"(func (export "canister_update update") {grow_body} (call $msg_reply))"#
            ))),
            None,
        ),
        // The heartbeat grows memory once after an update call arms it (by
        // setting a flag in the Wasm memory).
        StorageReservationMessage::Heartbeat => (
            Some(module(&format!(
                r#"(func (export "canister_update update")
                       (i32.store (i32.const 0) (i32.const 1))
                       (call $msg_reply))
                   (func (export "canister_heartbeat")
                       (if (i32.eq (i32.load (i32.const 0)) (i32.const 1))
                           (then
                               (i32.store (i32.const 0) (i32.const 2))
                               {grow_body})))"#
            ))),
            None,
        ),
        // An update call sets the global timer to a time in the past so that
        // the global timer runs in the next round.
        StorageReservationMessage::GlobalTimer => (
            Some(module(&format!(
                r#"(func (export "canister_update update")
                       (drop (call $global_timer_set (i64.const 1)))
                       (call $msg_reply))
                   (func (export "canister_global_timer") {grow_body})"#
            ))),
            None,
        ),
        StorageReservationMessage::Install => (
            None,
            Some(module(&format!(
                r#"(func (export "canister_init") {grow_body})"#
            ))),
        ),
        StorageReservationMessage::InstallAfterStart => (
            None,
            Some(module(&format!(
                r#"{long_running_start} (func (export "canister_init") {grow_body})"#
            ))),
        ),
        StorageReservationMessage::PreUpgrade => (
            Some(module(&format!(
                r#"(func (export "canister_pre_upgrade") {grow_body})"#
            ))),
            Some(module("")),
        ),
        StorageReservationMessage::PostUpgrade => (
            Some(module("")),
            Some(module(&format!(
                r#"(func (export "canister_post_upgrade") {grow_body})"#
            ))),
        ),
        StorageReservationMessage::PostUpgradeAfterPreUpgrade => (
            Some(module(&format!(
                r#"(func (export "canister_pre_upgrade") {})"#,
                burn(PREVIOUS_STAGE_INSTRUCTIONS)
            ))),
            Some(module(&format!(
                r#"(func (export "canister_post_upgrade") {grow_body})"#
            ))),
        ),
        StorageReservationMessage::PostUpgradeAfterStart => (
            Some(module("")),
            Some(module(&format!(
                r#"{long_running_start} (func (export "canister_post_upgrade") {grow_body})"#
            ))),
        ),
        // The response (or cleanup) callback is executed by the universal
        // canister.
        StorageReservationMessage::Response | StorageReservationMessage::Cleanup => {
            (Some(UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec()), None)
        }
    };

    let env = if message.is_install_code() {
        dts_install_code_env(
            NumInstructions::from(1_000_000_000),
            NumInstructions::from(SLICE_INSTRUCTIONS),
        )
        .0
    } else {
        dts_env(
            NumInstructions::from(1_000_000_000),
            NumInstructions::from(SLICE_INSTRUCTIONS),
        )
    };
    let settings = |reserved_cycles_limit: u128| {
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_freezing_threshold(0)
                .with_reserved_cycles_limit(reserved_cycles_limit)
                .build(),
        )
    };
    let canister_id =
        env.create_canister_with_cycles(None, canister_balance, settings(reserved_cycles_limit));
    let filler_1 = env.create_canister_with_cycles(None, INITIAL_BALANCE, settings(u128::MAX));
    let filler_2 = env.create_canister_with_cycles(None, INITIAL_BALANCE, settings(u128::MAX));
    if let Some(old_module) = old_module {
        // The universal canister grows its Wasm memory when it first executes
        // a (no-op) program. Do so in `canister_init` so that the update call
        // making the inter-canister call does not reserve cycles depending on
        // when it is executed.
        let init_arg = if message.is_callback() {
            wasm().noop().build()
        } else {
            vec![]
        };
        env.install_wasm_in_mode(
            canister_id,
            CanisterInstallMode::Install,
            old_module,
            init_arg,
        )
        .unwrap();
    }
    let callee = message.is_callback().then(|| {
        env.install_canister_with_cycles(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            vec![],
            settings(u128::MAX),
            INITIAL_BALANCE,
        )
        .unwrap()
    });
    let mut growing_callback = wasm();
    if slice == StorageReservationSlice::Second {
        growing_callback =
            growing_callback.instruction_counter_is_at_least(grow_after_instructions);
    }
    let growing_callback = growing_callback
        .stable64_grow(STABLE_MEMORY_GROWTH_PAGES)
        .instruction_counter_is_at_least(TOTAL_INSTRUCTIONS);
    let callback_args = match message {
        StorageReservationMessage::Cleanup => call_args()
            .other_side(wasm().reply_data(&[]))
            .on_reply(wasm().trap())
            .on_cleanup(growing_callback),
        _ => call_args()
            .other_side(wasm().reply_data(&[]))
            .on_reply(growing_callback.reply_data(&[])),
    };

    let start_message = || match message {
        StorageReservationMessage::Update
        | StorageReservationMessage::Heartbeat
        | StorageReservationMessage::GlobalTimer => {
            env.send_ingress(PrincipalId::new_anonymous(), canister_id, "update", vec![])
        }
        StorageReservationMessage::Install
        | StorageReservationMessage::InstallAfterStart
        | StorageReservationMessage::PreUpgrade
        | StorageReservationMessage::PostUpgrade
        | StorageReservationMessage::PostUpgradeAfterPreUpgrade
        | StorageReservationMessage::PostUpgradeAfterStart => {
            let mode = if message.is_upgrade() {
                CanisterInstallMode::Upgrade
            } else {
                CanisterInstallMode::Install
            };
            env.send_ingress(
                PrincipalId::new_anonymous(),
                IC_00,
                Method::InstallCode,
                InstallCodeArgs::new(mode, canister_id, new_module.clone().unwrap(), vec![])
                    .encode(),
            )
        }
        StorageReservationMessage::Response | StorageReservationMessage::Cleanup => env
            .send_ingress(
                PrincipalId::new_anonymous(),
                canister_id,
                "update",
                wasm()
                    .inter_update(callee.unwrap(), callback_args.clone())
                    .build(),
            ),
    };
    let is_paused = || {
        env.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .has_paused_execution_or_install_code()
    };
    // Executes rounds until the message is paused (starting a system task or
    // executing a response callback requires multiple rounds).
    let tick_until_paused = || {
        for _ in 0..5 {
            if is_paused() {
                break;
            }
            env.tick();
        }
        assert!(is_paused());
    };
    let set_subnet_memory_allocation = |filler: CanisterId, bytes: u64| {
        env.update_settings(
            &filler,
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(bytes)
                .build(),
        )
        .unwrap();
    };
    let reserved_balance_and_instructions_executed = || {
        let state = env.get_latest_state();
        let system_state = &state.canister_state(&canister_id).unwrap().system_state;
        (
            system_state.reserved_balance(),
            system_state
                .canister_metrics()
                .instructions_executed()
                .get(),
        )
    };

    let (reserved_balance_before, instructions_executed_before) =
        reserved_balance_and_instructions_executed();
    let message_id = match subnet_memory_change {
        SubnetMemoryChange::GrowWhilePaused => {
            let message_id = start_message();
            env.tick();
            tick_until_paused();
            set_subnet_memory_allocation(filler_1, 500 * GIB);
            set_subnet_memory_allocation(filler_2, 240 * GIB);
            assert!(is_paused());
            message_id
        }
        SubnetMemoryChange::GrowBeforeExecution => {
            set_subnet_memory_allocation(filler_1, 500 * GIB);
            set_subnet_memory_allocation(filler_2, 240 * GIB);
            start_message()
        }
        SubnetMemoryChange::ShrinkWhilePaused => {
            set_subnet_memory_allocation(filler_1, 500 * GIB);
            set_subnet_memory_allocation(filler_2, 240 * GIB);
            let message_id = start_message();
            env.tick();
            tick_until_paused();
            set_subnet_memory_allocation(filler_1, 0);
            set_subnet_memory_allocation(filler_2, 0);
            assert!(is_paused());
            message_id
        }
    };

    let result = env.await_ingress(message_id, 20);
    if message.is_task() {
        // The update call arming the system task completes before the system
        // task, which is started (if it is not yet paused) and completed now.
        tick_until_paused();
        for _ in 0..20 {
            if !is_paused() {
                break;
            }
            env.tick();
        }
        assert!(!is_paused());
    }

    let (reserved_balance, instructions_executed) = reserved_balance_and_instructions_executed();
    let stable_memory_usage = env
        .get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .stable_memory_usage()
        .get();
    StorageReservationOutcome {
        result,
        reserved_balance_before,
        reserved_balance,
        stable_memory_usage,
        instructions_executed: instructions_executed - instructions_executed_before,
    }
}

/// Executes a long-running message growing memory in the given slice and
/// returns the reserved balance of the canister after the message completes
/// (see `run_long_running_message_growing_memory`).
fn storage_reservation_of_long_running_message(
    message: StorageReservationMessage,
    slice: StorageReservationSlice,
    start_before_subnet_memory_grows: bool,
) -> Cycles {
    let outcome = run_long_running_message_growing_memory(
        message,
        slice,
        if start_before_subnet_memory_grows {
            SubnetMemoryChange::GrowWhilePaused
        } else {
            SubnetMemoryChange::GrowBeforeExecution
        },
        Cycles::new(100_000_000_000_000_000),
        u128::MAX,
    );
    match message {
        // The response callback traps (after which the cleanup callback runs).
        StorageReservationMessage::Cleanup => {
            let err = outcome.result.unwrap_err();
            assert_eq!(err.code(), ErrorCode::CanisterCalledTrap, "{err}");
        }
        _ => {
            outcome.result.unwrap();
        }
    }
    assert_eq!(outcome.stable_memory_usage, 185 * GIB);
    outcome.reserved_balance
}

/// Checks that every long-running message growing memory reserves storage
/// cycles at the subnet memory saturation at the time it completes, i.e., the
/// same amount as if it had started after other canisters had grown the subnet
/// memory usage.
#[test]
fn dts_paused_message_growing_memory_reserves_cycles_at_current_saturation() {
    for message in StorageReservationMessage::iter() {
        let slices = if message.has_long_running_previous_stage() {
            vec![StorageReservationSlice::First]
        } else {
            vec![
                StorageReservationSlice::First,
                StorageReservationSlice::Second,
            ]
        };
        for slice in slices {
            let paused_reserved = storage_reservation_of_long_running_message(message, slice, true);
            let fresh_reserved = storage_reservation_of_long_running_message(message, slice, false);
            // Sanity check: the subnet memory saturation is substantial.
            assert!(
                fresh_reserved >= Cycles::new(1_000_000_000_000_000),
                "{message:?} growing memory in the {slice:?} slice: {fresh_reserved}"
            );
            assert_eq!(
                paused_reserved, fresh_reserved,
                "{message:?} growing memory in the {slice:?} slice"
            );
        }
    }
}

/// The reason why a paused message cannot reserve storage cycles at the subnet
/// memory saturation at the time it completes.
#[derive(Clone, Copy, Debug)]
enum LateStorageReservationFailure {
    InsufficientCycles,
    ReservedCyclesLimitExceeded,
}

/// Checks that every long-running message growing memory in its first slice
/// fails if the canister cannot reserve storage cycles at the subnet memory
/// saturation at the time the message completes (due to its cycles balance or
/// reserved cycles limit, which suffice for the storage reservation at the
/// start of the message) and that its changes are discarded.
#[test]
fn dts_paused_message_growing_memory_fails_to_reserve_cycles_at_current_saturation() {
    for message in StorageReservationMessage::iter() {
        // The Wasm execution of a message growing memory only after a long-running
        // previous stage already starts at the current subnet memory saturation,
        // so there is no late storage reservation that could fail.
        if message.has_long_running_previous_stage() {
            continue;
        }
        for failure in [
            LateStorageReservationFailure::InsufficientCycles,
            LateStorageReservationFailure::ReservedCyclesLimitExceeded,
        ] {
            let case = format!("{message:?} failing due to {failure:?}");
            let (canister_balance, reserved_cycles_limit, error_code, error_message) = match failure
            {
                LateStorageReservationFailure::InsufficientCycles => (
                    Cycles::new(10_000_000_000_000),
                    u128::MAX,
                    ErrorCode::InsufficientCyclesInMemoryGrow,
                    "due to insufficient cycles",
                ),
                LateStorageReservationFailure::ReservedCyclesLimitExceeded => (
                    Cycles::new(100_000_000_000_000_000),
                    10_000_000_000_000,
                    ErrorCode::ReservedCyclesLimitExceededInMemoryGrow,
                    "due to its reserved cycles limit",
                ),
            };
            let outcome = run_long_running_message_growing_memory(
                message,
                StorageReservationSlice::First,
                SubnetMemoryChange::GrowWhilePaused,
                canister_balance,
                reserved_cycles_limit,
            );
            if message.is_task() {
                // The failure of a system task is not reported. Hence, we check
                // that the system task has executed (all its instructions).
                outcome.result.unwrap();
                assert!(
                    outcome.instructions_executed >= STORAGE_RESERVATION_TOTAL_INSTRUCTIONS,
                    "{case}: {}",
                    outcome.instructions_executed
                );
            } else {
                let err = outcome.result.unwrap_err();
                // A failing cleanup callback reports the error code of the
                // (trapping) response callback.
                let expected_code = if message == StorageReservationMessage::Cleanup {
                    ErrorCode::CanisterCalledTrap
                } else {
                    error_code
                };
                assert_eq!(err.code(), expected_code, "{case}: {err}");
                assert!(err.description().contains(error_message), "{case}: {err}");
            }
            // The changes of the message are discarded.
            assert_eq!(outcome.stable_memory_usage, 0, "{case}");
            assert_eq!(
                outcome.reserved_balance, outcome.reserved_balance_before,
                "{case}"
            );
        }
    }
}

/// Reservations already made by the sandbox are retained when subnet memory
/// saturation falls before the execution commits.
#[test]
fn dts_paused_message_growing_memory_does_not_refund_cycles_when_saturation_falls() {
    for message in [
        StorageReservationMessage::Update,
        StorageReservationMessage::Response,
        StorageReservationMessage::Cleanup,
    ] {
        let reserved_at_high_saturation = storage_reservation_of_long_running_message(
            message,
            StorageReservationSlice::First,
            false,
        );
        assert!(reserved_at_high_saturation >= Cycles::new(1_000_000_000_000_000));
        let outcome = run_long_running_message_growing_memory(
            message,
            StorageReservationSlice::First,
            SubnetMemoryChange::ShrinkWhilePaused,
            Cycles::new(100_000_000_000_000_000),
            reserved_at_high_saturation.get(),
        );
        if message == StorageReservationMessage::Cleanup {
            let err = outcome.result.unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::CanisterCalledTrap,
                "{message:?}: {err}"
            );
        } else {
            outcome.result.unwrap();
        }
        assert_eq!(outcome.stable_memory_usage, 185 * GIB, "{message:?}");
        assert_eq!(
            outcome.reserved_balance, reserved_at_high_saturation,
            "{message:?}"
        );
    }
}
