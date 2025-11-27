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
    CanisterIdRecord, CanisterInfoRequest, CanisterInstallMode, CanisterInstallModeV2,
    CanisterMetadataRequest, CanisterSettingsArgsBuilder, CanisterSnapshotDataKind,
    CanisterSnapshotDataOffset, ClearChunkStoreArgs, DeleteCanisterSnapshotArgs, EmptyBlob,
    GlobalTimer, IC_00, InstallChunkedCodeArgs, InstallCodeArgs, ListCanisterSnapshotArgs,
    LoadCanisterSnapshotArgs, Method, OnLowWasmMemoryHookStatus, Payload,
    ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs, StoredChunksArgs,
    TakeCanisterSnapshotArgs, UninstallCodeArgs, UpdateSettingsArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::{NextExecution, execution_state::NextScheduledMethod};
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineConfig};
use ic_types::ingress::{IngressState, IngressStatus, WasmResult};
use ic_types::messages::MessageId;
use ic_types::{CryptoHashOfState, Cycles, NumInstructions};
use ic_universal_canister::{
    CallArgs, UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM, UNIVERSAL_CANISTER_WASM, call_args, wasm,
};
use more_asserts::assert_ge;
use std::sync::OnceLock;
use strum::IntoEnumIterator;

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
                (memory.fill (i32.const 0) (i32.const 12) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 23) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 34) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 45) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 56) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 67) (i32.const 10000))
                (memory.fill (i32.const 0) (i32.const 78) (i32.const 10000))
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
            max_instructions_per_message_without_dts: slice_instruction_limit,
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
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
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
            max_instructions_per_message_without_dts: slice_instruction_limit,
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

    // The initial balance is sufficient to only pay the reservation for installing code
    // and the compute allocation during the freezing threshold.
    let initial_balance = max_install_code_cost() + compute_allocation_cycles;

    let canister_id = env.create_canister_with_cycles(
        None,
        initial_balance,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .with_freezing_threshold(freezing_threshold)
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
        compute_allocation_cycles.get()
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

    // The cycles to cover the compute allocation during the freezing threshold are only needed to keep the canister unfrozen
    // and are not actually used.
    let unused_cycles = compute_allocation_cycles;
    assert_eq!(env.cycle_balance(canister_id), unused_cycles.get());
}

#[test]
fn dts_pending_upgrade_with_heartbeat() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(30_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let controller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let controller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(10_000),
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
    fn test<F: Fn(CanisterId) -> (Method, CallArgs)>(
        subnet_complete: bool,
        aborted_complete: bool,
        f: F,
    ) {
        let slice_instruction_limit = 10_000_000;
        let env = dts_env(
            NumInstructions::from(slice_instruction_limit * 10),
            NumInstructions::from(slice_instruction_limit),
        );

        let user_id = PrincipalId::new_anonymous();
        let other_canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        let aborted_canister_id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id, other_canister_id.get()])
                        .build(),
                ),
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();

        env.set_checkpoints_enabled(true);
        let long_execution_id = env.send_ingress(
            user_id,
            aborted_canister_id,
            "update",
            wasm()
                .instruction_counter_is_at_least(slice_instruction_limit)
                .reply_data(&[42])
                .build(),
        );

        for _ in 0..5 {
            // With checkpoints enabled, the update message will be repeatedly
            // aborted, so there will be no progress.
            env.tick();
        }

        let (method, args) = f(aborted_canister_id);
        if method == Method::DeleteCanisterSnapshot
            || method == Method::ReadCanisterSnapshotMetadata
            || method == Method::ReadCanisterSnapshotData
        {
            env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(aborted_canister_id, None))
                .unwrap();
        }

        if method == Method::UploadCanisterSnapshotData {
            env.upload_canister_snapshot_metadata(&UploadCanisterSnapshotMetadataArgs {
                canister_id: aborted_canister_id.into(),
                replace_snapshot: None,
                wasm_module_size: 1024,
                globals: vec![],
                wasm_memory_size: 1 << 16,
                stable_memory_size: 1 << 16,
                certified_data: vec![],
                global_timer: None,
                on_low_wasm_memory_hook_status: None,
            })
            .unwrap();
        }

        let args = args
            .on_reject(wasm().reject_message().reject())
            .on_reply(wasm().reply_data(&[43]));

        let subnet_message = wasm()
            .call_with_cycles(IC_00, method, args, 100_000_000_000_u128)
            .build();

        let subnet_message_id =
            env.send_ingress(user_id, other_canister_id, "update", subnet_message);

        for _ in 0..5 {
            env.tick();
        }

        // Make sure the aborted execution is still processing.
        if aborted_complete {
            assert_eq!(
                ingress_state(env.ingress_status(&long_execution_id)),
                Some(IngressState::Processing)
            );
        } else {
            assert_matches!(
                ingress_state(env.ingress_status(&long_execution_id)),
                Some(IngressState::Failed(_))
            );
        }

        // Make sure the method is completed, despite the effective canister is aborted.
        if subnet_complete {
            assert_eq!(
                ingress_state(env.ingress_status(&subnet_message_id)),
                Some(IngressState::Completed(WasmResult::Reply(vec![43])))
            );
        }

        env.set_checkpoints_enabled(false);
        for _ in 0..5 {
            env.tick();
        }

        // Make sure the aborted message is completed.
        if aborted_complete {
            assert_eq!(
                ingress_state(env.ingress_status(&long_execution_id)),
                Some(IngressState::Completed(WasmResult::Reply(vec![42])))
            );
        }
    }
    fn test_supported<F: Fn(CanisterId) -> (Method, CallArgs)>(f: F) {
        test(true, true, f);
    }
    fn test_unsupported<F: Fn(CanisterId) -> (Method, CallArgs)>(f: F) {
        test(false, true, f);
    }
    fn test_supported_uninstall<F: Fn(CanisterId) -> (Method, CallArgs)>(f: F) {
        test(true, false, f);
    }

    for method in Method::iter() {
        match method {
            // Supported methods accepting just one argument.
            Method::CanisterStatus | Method::DepositCycles | Method::StartCanister => {
                test_supported(|aborted_canister_id| {
                    let args = CanisterIdRecord::from(aborted_canister_id).encode();
                    (method, call_args().other_side(args))
                })
            }
            Method::CanisterInfo => test_supported(|aborted_canister_id| {
                let args = CanisterInfoRequest::new(aborted_canister_id, None).encode();
                (method, call_args().other_side(args))
            }),
            Method::CanisterMetadata => test_supported(|aborted_canister_id| {
                let args =
                    // The "git_commit_id" is one of the metadata sections in the universal canister
                    // wasm (for any canister wasm built in the monorepo).
                    CanisterMetadataRequest::new(aborted_canister_id, "git_commit_id".to_string())
                        .encode();
                (method, call_args().other_side(args))
            }),
            // No effective canister id.
            Method::CreateCanister
            | Method::HttpRequest
            | Method::ECDSAPublicKey
            | Method::RawRand
            | Method::SetupInitialDKG
            | Method::SignWithECDSA
            | Method::ReshareChainKey
            | Method::SchnorrPublicKey
            | Method::SignWithSchnorr
            | Method::VetKdPublicKey
            | Method::VetKdDeriveKey
            | Method::BitcoinGetBalance
            | Method::BitcoinGetUtxos
            | Method::BitcoinGetBlockHeaders
            | Method::BitcoinSendTransaction
            | Method::BitcoinGetCurrentFeePercentiles
            | Method::BitcoinSendTransactionInternal
            | Method::BitcoinGetSuccessors
            | Method::NodeMetricsHistory
            | Method::SubnetInfo
            | Method::ProvisionalCreateCanisterWithCycles
            | Method::ProvisionalTopUpCanister
            | Method::RenameCanister => {}
            // Unsupported methods accepting just one argument.
            // Deleting an aborted canister requires to stop it first.
            // Stopping an aborted canister does not generate a reply.
            Method::DeleteCanister | Method::StopCanister => {
                test_unsupported(|aborted_canister_id| {
                    let args = CanisterIdRecord::from(aborted_canister_id).encode();
                    (method, call_args().other_side(args))
                })
            }
            // Installing code is not supported on aborted canister.
            Method::InstallCode => test_unsupported(|aborted_canister_id| {
                let args = InstallCodeArgs {
                    canister_id: aborted_canister_id.get(),
                    mode: CanisterInstallMode::Install,
                    wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
                    arg: vec![],
                    sender_canister_version: None,
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            // Installing code is not supported on aborted canister.
            Method::InstallChunkedCode => test_unsupported(|aborted_canister_id| {
                let args = InstallChunkedCodeArgs {
                    mode: CanisterInstallModeV2::Install,
                    target_canister: aborted_canister_id.get(),
                    store_canister: None,
                    chunk_hashes_list: vec![],
                    wasm_module_hash: vec![],
                    arg: vec![],
                    sender_canister_version: None,
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::UninstallCode => test_supported_uninstall(|aborted_canister_id| {
                let args = UninstallCodeArgs::new(aborted_canister_id, None).encode();
                (method, call_args().other_side(args))
            }),
            Method::UpdateSettings => test_supported(|aborted_canister_id| {
                let settings = CanisterSettingsArgsBuilder::new().build();
                let args = UpdateSettingsArgs::new(aborted_canister_id, settings).encode();
                (method, call_args().other_side(args))
            }),
            // TODO(EXC-2112): fix this test.
            // API is accessible both in replicated (only for canisters) and non-replicated (only for non-canisters) mode.
            Method::FetchCanisterLogs => {}
            Method::UploadChunk => test_supported(|aborted_canister_id| {
                let args = UploadChunkArgs {
                    canister_id: aborted_canister_id.get(),
                    chunk: vec![],
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::StoredChunks => test_supported(|aborted_canister_id| {
                let args = StoredChunksArgs {
                    canister_id: aborted_canister_id.get(),
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::ClearChunkStore => test_supported(|aborted_canister_id| {
                let args = ClearChunkStoreArgs {
                    canister_id: aborted_canister_id.get(),
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::TakeCanisterSnapshot => test_supported(|aborted_canister_id| {
                let args = TakeCanisterSnapshotArgs {
                    canister_id: aborted_canister_id.get(),
                    replace_snapshot: None,
                }
                .encode();
                (method, call_args().other_side(args))
            }),
            // Loading a snapshot is similar to the install code.
            Method::LoadCanisterSnapshot => test_unsupported(|aborted_canister_id| {
                let args = LoadCanisterSnapshotArgs::new(
                    aborted_canister_id,
                    (aborted_canister_id, 0).into(),
                    None,
                )
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::ListCanisterSnapshots => test_supported(|aborted_canister_id| {
                let args = ListCanisterSnapshotArgs::new(aborted_canister_id).encode();
                (method, call_args().other_side(args))
            }),
            Method::DeleteCanisterSnapshot => test_supported(|aborted_canister_id| {
                let args = DeleteCanisterSnapshotArgs::new(
                    aborted_canister_id,
                    (aborted_canister_id, 0).into(),
                )
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::ReadCanisterSnapshotMetadata => test_supported(|aborted_canister_id| {
                let args = ReadCanisterSnapshotMetadataArgs::new(
                    aborted_canister_id,
                    (aborted_canister_id, 0).into(),
                )
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::ReadCanisterSnapshotData => test_supported(|aborted_canister_id| {
                let args = ReadCanisterSnapshotDataArgs::new(
                    aborted_canister_id,
                    (aborted_canister_id, 0).into(),
                    CanisterSnapshotDataKind::WasmModule { size: 0, offset: 0 },
                )
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::UploadCanisterSnapshotMetadata => test_supported(|aborted_canister_id| {
                let args = UploadCanisterSnapshotMetadataArgs::new(
                    aborted_canister_id,
                    None,
                    1024,
                    vec![],
                    1 << 16,
                    1 << 16,
                    vec![],
                    Some(GlobalTimer::Inactive),
                    Some(OnLowWasmMemoryHookStatus::ConditionNotSatisfied),
                )
                .encode();
                (method, call_args().other_side(args))
            }),
            Method::UploadCanisterSnapshotData => test_supported(|aborted_canister_id| {
                let args = UploadCanisterSnapshotDataArgs::new(
                    aborted_canister_id,
                    (aborted_canister_id, 0).into(),
                    CanisterSnapshotDataOffset::WasmModule { offset: 0 },
                    vec![42; 42],
                )
                .encode();
                (method, call_args().other_side(args))
            }),
        }
    }
}

#[test]
fn dts_paused_execution_blocks_deposit_cycles() {
    let slice_instruction_limit = 10_000_000;
    let env = dts_env(
        NumInstructions::from(slice_instruction_limit * 10),
        NumInstructions::from(slice_instruction_limit),
    );

    let user_id = PrincipalId::new_anonymous();
    let long_canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();
    let other_canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(10_000),
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

    let n = 10;

    let mut controller = vec![];
    for _ in 0..n {
        let id = env
            .install_canister_with_cycles(
                UNIVERSAL_CANISTER_WASM.to_vec(),
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
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                settings.clone(),
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
            UNIVERSAL_CANISTER_WASM.to_vec(),
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

    for i in 0..30 {
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
                UNIVERSAL_CANISTER_WASM.to_vec(),
                vec![],
                None,
                INITIAL_CYCLES_BALANCE,
            )
            .unwrap();
        canister.push(id);
    }

    let short = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(10_000),
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
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let canister = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let original_time = env.time();
    let update = env.send_ingress(user_id, canister, "update", vec![]);

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
        NumInstructions::from(10_000),
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
fn dts_ingress_status_of_upgrade_is_correct() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
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
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let user_id = PrincipalId::new_anonymous();

    let a_id = env
        .install_canister_with_cycles(binary.clone(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let b_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let b = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
        .message_payload()
        .append_and_reply()
        .build();

    let a = wasm()
        .stable64_grow(1)
        .stable64_fill(0, 0, 10_000)
        .stable64_fill(0, 0, 10_000)
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

#[test]
fn dts_canister_uninstalled_due_to_resource_charges_with_aborted_updrade() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
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

    // Make sure that the upgrade message gets aborted after each round.
    env.set_checkpoints_enabled(true);

    let upgrade = {
        let args = InstallCodeArgs::new(CanisterInstallMode::Upgrade, canister, binary, vec![]);
        env.send_ingress(user_id, IC_00, Method::InstallCode, args.encode())
    };

    env.tick();

    // Advance the time so that the canister gets uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));

    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    let result = env.await_ingress(upgrade, 30).unwrap();

    // The canister is uninstalled after the execution completes because an
    // aborted install_code is always restarted and becomes a paused execution
    // by the time we charge canister for resource allocation.
    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));
}

#[test]
fn dts_canister_uninstalled_due_resource_charges_with_aborted_update() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(10_000),
    );

    let binary = wat2wasm(DTS_WAT);

    let user_id = PrincipalId::new_anonymous();

    let n = 10;

    let mut canisters = vec![];
    for _ in 0..n {
        let settings = Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .build(),
        );

        let id = env
            .install_canister_with_cycles(binary.clone(), vec![], settings, INITIAL_CYCLES_BALANCE)
            .unwrap();
        canisters.push(id);
    }

    // Make sure that the update messages get aborted after each round.
    env.set_checkpoints_enabled(true);

    let mut updates = vec![];
    for canister in canisters.iter() {
        let update = env.send_ingress(user_id, *canister, "update", vec![]);
        updates.push(update);
    }

    // Ensure that each update message starts executing.
    for _ in 0..n {
        env.tick();
    }

    // Advance the time so that the canister gets uninstalled due to the
    // resource usage.
    env.advance_time(Duration::from_secs(10_000_000));

    env.tick();

    // Enable normal message execution.
    env.set_checkpoints_enabled(false);

    let mut errors = 0;

    // Canisters that were chosen for execution before charging for resources
    // become paused and don't get uninstalled until their execution completes.
    // All other canister are uninstalled before resuming their aborted
    // executions.
    for i in 0..n {
        match env.await_ingress(updates[i].clone(), 100) {
            Ok(result) => {
                assert_eq!(result, WasmResult::Reply(vec![]));
            }
            Err(err) => {
                err.assert_contains(
                    ErrorCode::CanisterWasmModuleNotFound,
                    &format!(
                        "Error from Canister {}: Attempted to execute a message, \
                        but the canister contains no Wasm module.",
                        canisters[i]
                    ),
                );
                errors += 1;
            }
        }
    }
    assert_ge!(errors, 1);
}

#[test]
fn dts_serialized_and_runtime_states_are_equal() {
    fn run(restart_node: bool) -> CryptoHashOfState {
        let subnet_config = dts_subnet_config(
            NumInstructions::from(1_000_000_000),
            NumInstructions::from(10_000),
        );
        let num_canisters = subnet_config.scheduler_config.scheduler_cores * 2;
        let state_machine_config = dts_state_machine_config(subnet_config);
        let env = StateMachine::new_with_config(state_machine_config.clone());

        let mut canister_ids = vec![];
        for _ in 0..num_canisters {
            let canister_id = env
                .install_canister_with_cycles(
                    UNIVERSAL_CANISTER_WASM.to_vec(),
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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(100_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(100_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let heartbeat = wasm()
        .instruction_counter_is_at_least(100_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let heartbeat = wasm()
        .instruction_counter_is_at_least(100_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let heartbeat = wasm()
        .instruction_counter_is_at_least(100_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let disable_heartbeats = wasm().trap().build();

    let timer = wasm()
        .instruction_counter_is_at_least(100_000)
        .inc_global_counter()
        .build();

    let set_heartbeat_and_global_timer = wasm()
        .set_heartbeat(disable_heartbeats)
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat_and_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

    // 3) the update.
    let base_canister_version = get_canister_version(&env, canister_id);
    assert_eq!(3, base_canister_version);

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
        NumInstructions::from(75_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let heartbeat = wasm().instruction_counter_is_at_least(150_000).build();

    let timer = wasm()
        .instruction_counter_is_at_least(150_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(60_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(150_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(60_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(150_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
        NumInstructions::from(50_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // 1) canister create and 2) install code.
    assert_eq!(2, get_canister_version(&env, canister_id));

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let disable_heartbeats = wasm().trap().build();

    let timer = wasm()
        .instruction_counter_is_at_least(100_000)
        .inc_global_counter()
        .api_global_timer_set(now_nanos)
        .trap()
        .build();

    let set_heartbeat_and_global_timer = wasm()
        .set_heartbeat(disable_heartbeats)
        .set_global_timer_method(timer)
        .api_global_timer_set(now_nanos)
        .get_global_counter()
        .reply_int64()
        .build();

    let result = env
        .execute_ingress(canister_id, "update", set_heartbeat_and_global_timer)
        .unwrap();

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
fn dts_global_timer_does_not_prevent_upgrade() {
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(60_000),
    );

    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

    let canister_id = env
        .install_canister_with_cycles(binary, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    let now_nanos = env.time().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;

    let timer = wasm()
        .instruction_counter_is_at_least(150_000)
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

    assert_eq!(result, WasmResult::Reply(0u64.to_le_bytes().to_vec()));

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
    let env = dts_env(
        NumInstructions::from(1_000_000_000),
        NumInstructions::from(50_000),
    );

    let user_id = PrincipalId::new_anonymous();
    let binary = UNIVERSAL_CANISTER_WASM.to_vec();

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
        NumInstructions::from(100_000_000),
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
                UNIVERSAL_CANISTER_WASM.to_vec(),
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

    // Only the first message must be completed after two rounds.
    assert_eq!(num_completed(), 1);

    env.tick();

    // Only the first message must be completed after three rounds.
    assert_eq!(num_completed(), 1);

    env.tick();

    // Two heavy install code messages must be completed in four rounds.
    assert_eq!(num_completed(), 2);
}
