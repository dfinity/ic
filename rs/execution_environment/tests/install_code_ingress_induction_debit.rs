//! Tests around the postponed ingress induction charge, i.e. a canister's
//! `ingress_induction_cycles_debit`.
//!
//! Inducting an ingress message into a canister that has a paused DTS execution
//! must not modify its cycles balance (the paused execution is accounted for
//! relative to that balance), so `CyclesAccountManager::charge_ingress_induction_cost()`
//! postpones the charge into the canister's `ingress_induction_cycles_debit`
//! instead. The debit is charged to the balance by the execution that was paused.

use ic_config::{
    execution_environment::Config as ExecutionConfig,
    subnet_config::{SchedulerConfig, SubnetConfig},
};
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterSettingsArgs, CanisterSettingsArgsBuilder, InstallCodeArgs,
    Method, Payload as _,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::messages::MessageId;
use ic_types::{CanisterId, NumInstructions, PrincipalId};
use ic_types_cycles::{Cycles, CyclesUseCase};
use ic_types_test_utils::ids::user_test_id;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use more_asserts::{assert_gt, assert_lt};

/// The subnet type of the `StateMachine` below: an application subnet, so that
/// the production cycles cost settings of an application subnet apply.
const SUBNET_TYPE: SubnetType = SubnetType::Application;

/// The instruction limit of a single `install_code` slice, lowered from the
/// production default so that the `canister_init` below is sliced across rounds
/// without having to execute billions of instructions per slice.
const INSTALL_CODE_SLICE_INSTRUCTION_LIMIT: u64 = 1_000_000;

/// The instruction limit of a whole `install_code`, lowered from the production
/// default of 300B instructions. An application subnet charges one cycle per
/// instruction, so this also bounds the prepaid execution cycles and hence the
/// refund of the unused ones.
///
/// That refund is what lets these tests reproduce the bug they cover: it is
/// credited to the canister's balance right before the debit used to be charged
/// (see `refund_unused_execution_cycles()` in `InstallCodeHelper::finish()`), so
/// at the production limit it dwarfs the debit and silently covers it. The limit
/// therefore has to stay well below `expected_debit()` below, while still
/// covering the ~1.2B instructions charged for instrumenting the universal
/// canister module. The lower bound shows up as a `CanisterInstructionLimitExceeded`
/// failure of the `install_code`, the upper one is checked by
/// `max_install_code_refund()` below.
const INSTALL_CODE_INSTRUCTION_LIMIT: u64 = 3_000 * INSTALL_CODE_SLICE_INSTRUCTION_LIMIT;

/// One trillion, for better cycles readability.
const T: u128 = 1_000_000_000_000;

/// The cycles the canister is created with. Large enough to cover everything
/// the tests below do, so that no top up is needed.
const INITIAL_CYCLES: u128 = 100 * T;

/// The payload size of the ingress messages inducted while `install_code` is
/// paused. Their induction cost is what ends up in the canister's ingress
/// induction debit.
const INGRESS_PAYLOAD_SIZE: usize = 1024 * 1024;
const NUM_INGRESS_MESSAGES: usize = 4;

/// The number of rounds the tests below give the `install_code` to complete.
const MAX_TICKS: usize = 100;

/// The number of seconds in a day, to convert the idle cycles burned per day
/// reported by `canister_status` into a freezing threshold in cycles.
const SECONDS_PER_DAY: u128 = 24 * 60 * 60;

fn user() -> PrincipalId {
    user_test_id(1).get()
}

/// The number of `install_code` slices the `canister_init` below spans. Pausing
/// the `install_code` is what makes the ingress messages inducted in the
/// meantime accumulate a debit instead of being charged right away, so it must
/// still be paused once they have all been inducted, i.e. it has to span more
/// slices than the rounds executed until then: the round that starts it, plus
/// one round per ingress message (`StateMachine::send_ingress_safe` executes a
/// round). Two slices of headroom on top of those.
const INIT_SLICES: u64 = NUM_INGRESS_MESSAGES as u64 + 3;

/// The number of instructions the `canister_init` below executes before burning
/// cycles: `INIT_SLICES` slices worth of instructions, which has to leave room
/// within `INSTALL_CODE_INSTRUCTION_LIMIT` for instrumenting the module and for
/// the burn itself.
const INIT_INSTRUCTIONS: u64 = INIT_SLICES * INSTALL_CODE_SLICE_INSTRUCTION_LIMIT;

/// An upper bound on the execution cycles prepaid for an `install_code`, and
/// hence on the refund of the unused ones: the whole instruction limit plus the
/// per-message base fee, at the application subnet fees. The `StateMachine`
/// below has the reference subnet size, so no subnet size scaling applies.
///
/// The tests below assert that the ingress induction debit they accumulate is
/// worth more than this, as the refund would otherwise cover the debit and hide
/// the bug they cover, see `INSTALL_CODE_INSTRUCTION_LIMIT`.
fn max_install_code_refund() -> Cycles {
    let config = SubnetConfig::new(SUBNET_TYPE).cycles_account_manager_config;
    config.update_message_execution_fee
        + config.ten_update_instructions_execution_fee * (INSTALL_CODE_INSTRUCTION_LIMIT / 10)
}

/// Creates an application subnet `StateMachine` with a single universal
/// canister created with `INITIAL_CYCLES` and the given settings.
fn setup(settings: CanisterSettingsArgs) -> (StateMachine, CanisterId) {
    let subnet_config = SubnetConfig::new(SUBNET_TYPE);
    let subnet_config = SubnetConfig {
        scheduler_config: SchedulerConfig {
            max_instructions_per_install_code: NumInstructions::new(INSTALL_CODE_INSTRUCTION_LIMIT),
            max_instructions_per_install_code_slice: NumInstructions::new(
                INSTALL_CODE_SLICE_INSTRUCTION_LIMIT,
            ),
            ..subnet_config.scheduler_config
        },
        ..subnet_config
    };
    let config = StateMachineConfig::new(subnet_config, ExecutionConfig::default());
    let env = StateMachineBuilder::new()
        // The config carries the execution settings of the subnet, while the
        // subnet type is what ends up in its registry record and in the
        // canister's cycles cost settings; both have to be set, as the builder
        // defaults to `SubnetType::System` and does not derive the subnet type
        // from the config.
        .with_config(Some(config))
        .with_subnet_type(SUBNET_TYPE)
        .build();

    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(settings),
            Cycles::new(INITIAL_CYCLES),
        )
        .unwrap();

    (env, canister_id)
}

/// The body of a system method executed by an `install_code` (`canister_init`,
/// `canister_pre_upgrade` or `canister_post_upgrade`) that runs for
/// `INIT_INSTRUCTIONS` instructions, so that it is sliced across rounds, and
/// then burns `cycles_to_burn` via `ic0.cycles_burn128()`.
///
/// It must not reply: `msg_reply` from a system method is a bug that `fatal!`s.
fn slow_burning(cycles_to_burn: u128) -> Vec<u8> {
    wasm()
        .instruction_counter_is_at_least(INIT_INSTRUCTIONS)
        .cycles_burn128(cycles_to_burn)
        .build()
}

/// Returns the canister's ingress induction debit.
fn ingress_induction_debit(env: &StateMachine, canister_id: CanisterId) -> Cycles {
    env.get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .ingress_induction_cycles_debit()
}

/// Returns the cycles the canister consumed for the given use case.
fn consumed(env: &StateMachine, canister_id: CanisterId, use_case: CyclesUseCase) -> Cycles {
    env.consumed_cycles_by_use_cases(canister_id)
        .get(&use_case)
        .map(|cycles| Cycles::new(cycles.get()))
        .unwrap_or_else(Cycles::zero)
}

/// Returns the canister's freezing threshold in cycles.
fn freezing_threshold_cycles(env: &StateMachine, canister_id: CanisterId) -> Cycles {
    let status = env.canister_status(canister_id).unwrap().unwrap();
    Cycles::new(
        status.idle_cycles_burned_per_day() * status.freezing_threshold() as u128 / SECONDS_PER_DAY,
    )
}

/// Inducts `NUM_INGRESS_MESSAGES` ingress messages into `canister_id`, each in
/// its own round, and returns their total induction cost. That cost accumulates
/// in the canister's ingress induction debit if the canister has a paused
/// execution while the messages are inducted.
fn induct_ingress_messages(env: &StateMachine, canister_id: CanisterId) -> Cycles {
    let payload = vec![0_u8; INGRESS_PAYLOAD_SIZE];
    let mut cost = Cycles::zero();
    for _ in 0..NUM_INGRESS_MESSAGES {
        cost += env
            .ingress_message_cost(user(), canister_id, "update", payload.clone())
            .cost();
        // Note that submitting a message executes a round, which inducts it.
        env.send_ingress_safe(user(), canister_id, "update", payload.clone())
            .expect("failed to submit ingress message");
    }
    cost
}

/// Starts an `install_code` (a reinstall) on `canister_id` whose `canister_init`
/// burns `cycles_to_burn` and pauses after its first slice, and then inducts
/// `NUM_INGRESS_MESSAGES` ingress messages into the canister while it is paused,
/// so that their induction cost accumulates in the canister's ingress induction
/// debit.
///
/// Returns the message ID of the `install_code` and the accumulated debit.
fn install_code_paused_with_ingress_debit(
    env: &StateMachine,
    canister_id: CanisterId,
    cycles_to_burn: u128,
) -> (MessageId, Cycles) {
    let install = env
        .send_ingress_safe(
            PrincipalId::new_anonymous(),
            CanisterId::ic_00(),
            Method::InstallCode,
            InstallCodeArgs::new(
                CanisterInstallMode::Reinstall,
                canister_id,
                UNIVERSAL_CANISTER_WASM.to_vec(),
                slow_burning(cycles_to_burn),
            )
            .encode(),
        )
        .expect("failed to submit install_code");
    // Note that submitting a message executes a round: the round above inducts
    // the `install_code`, starts executing it, and pauses it after its first
    // slice.

    let balance_before = env.cycle_balance(canister_id);
    let expected_debit = induct_ingress_messages(env, canister_id);
    assert_gt!(expected_debit, max_install_code_refund());
    // The whole induction cost of the ingress messages accumulated in the
    // canister's ingress induction debit, leaving its balance untouched.
    assert_eq!(ingress_induction_debit(env, canister_id), expected_debit);
    assert_eq!(balance_before, env.cycle_balance(canister_id));

    (install, expected_debit)
}

/// Regression test: `InstallCodeHelper::handle_wasm_execution()` must charge the
/// ingress induction debit *before* applying the state changes of the Wasm
/// execution, since the latter may burn the canister's whole balance via
/// `ic0.cycles_burn128()`. Charging it afterwards (in
/// `InstallCodeHelper::finish()`, as it used to be) leaves a debit that the
/// burnt balance can no longer cover, so the strict charge trips the
/// `debug_assert_eq!` in `apply_ingress_induction_cycles_debit()` and, in a build
/// without debug assertions, raises the
/// `execution_environment_charging_from_balance` critical error (which
/// `StateMachine::check_critical_errors()` turns into a failure). Reproducing
/// either needs the refund of the unused prepaid execution cycles to be smaller
/// than the debit, hence `INSTALL_CODE_INSTRUCTION_LIMIT`.
///
/// Here the burn no longer fits once the debit has been charged, so the
/// `install_code` fails with `CanisterOutOfCycles` — the same "concurrent cycle
/// change" outcome that update calls and response callbacks produce.
#[test]
fn install_code_burning_the_whole_balance_fails_once_the_ingress_debit_is_charged() {
    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(0)
            .build(),
    );

    let (install, debit) = install_code_paused_with_ingress_debit(&env, canister_id, u128::MAX);
    let induction_before = consumed(&env, canister_id, CyclesUseCase::IngressInduction);
    let burned_before = consumed(&env, canister_id, CyclesUseCase::BurnedCycles);

    // The `install_code` failed because the burn no longer fitted. Note that
    // `check_critical_errors()`, which panics if any critical error was raised,
    // runs after every round executed here.
    let err = env
        .await_ingress(install, MAX_TICKS)
        .expect_err("expected the install_code to fail");
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    // The debit was charged in full, ...
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::IngressInduction),
        induction_before + debit
    );
    // ... and nothing was burnt.
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::BurnedCycles),
        burned_before
    );
}

/// Regression test: burning cycles must not bring the balance below the
/// canister's freezing threshold, not even once the ingress induction debit has
/// been charged. `ic0.cycles_burn128()` caps the burn at the balance above the
/// freezing threshold, but it does so against the balance from before the debit
/// is charged, so the burn has to be checked against the freezing threshold
/// again after charging the debit.
///
/// The canister has a memory allocation, which makes its freezing threshold
/// both sizable and independent of how much memory the installed module ends up
/// using.
#[test]
fn install_code_burning_down_to_the_freezing_threshold_fails_once_the_ingress_debit_is_charged() {
    /// A memory allocation of one GiB, held for 30 days, is worth a few hundred
    /// billion cycles, i.e. much more than the ingress induction debit below.
    const MEMORY_ALLOCATION: u64 = 1024 * 1024 * 1024;
    const FREEZING_THRESHOLD_SECS: u64 = 30 * 24 * 60 * 60;

    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(FREEZING_THRESHOLD_SECS)
            .with_memory_allocation(MEMORY_ALLOCATION)
            .build(),
    );
    let freezing_threshold = freezing_threshold_cycles(&env, canister_id);

    let (install, debit) = install_code_paused_with_ingress_debit(&env, canister_id, u128::MAX);
    // The burn would still be covered by the balance after charging the debit:
    // it is only the freezing threshold that the balance can no longer cover.
    assert_lt!(debit, freezing_threshold);
    let induction_before = consumed(&env, canister_id, CyclesUseCase::IngressInduction);
    let burned_before = consumed(&env, canister_id, CyclesUseCase::BurnedCycles);

    let err = env
        .await_ingress(install, MAX_TICKS)
        .expect_err("expected the install_code to fail");
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    // The debit was charged in full, ...
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::IngressInduction),
        induction_before + debit
    );
    // ... nothing was burnt, ...
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::BurnedCycles),
        burned_before
    );
    // ... and the canister is not frozen.
    assert_gt!(
        Cycles::new(env.cycle_balance(canister_id)),
        freezing_threshold
    );
}

/// The counterpart of the tests above: an `install_code` whose `canister_init`
/// burns an amount that still fits once the ingress induction debit has been
/// charged succeeds, and both the debit and the burn are charged to the balance.
#[test]
fn install_code_burning_some_cycles_charges_both_the_ingress_debit_and_the_burn() {
    const CYCLES_TO_BURN: u128 = 1_000_000;

    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(0)
            .build(),
    );

    let (install, debit) =
        install_code_paused_with_ingress_debit(&env, canister_id, CYCLES_TO_BURN);
    let induction_before = consumed(&env, canister_id, CyclesUseCase::IngressInduction);
    let burned_before = consumed(&env, canister_id, CyclesUseCase::BurnedCycles);

    // The `install_code` succeeded, ...
    env.await_ingress(install, MAX_TICKS)
        .expect("expected the install_code to succeed");
    // ... the debit was charged in full, ...
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::IngressInduction),
        induction_before + debit
    );
    // ... and so was the burn.
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::BurnedCycles),
        burned_before + Cycles::new(CYCLES_TO_BURN)
    );
}

/// An upgrade runs up to three Wasm executions — `canister_pre_upgrade` on the
/// old module, then `(start)` and `canister_post_upgrade` on the new one — each
/// of which charges the ingress induction debit accumulated so far before
/// applying its own state changes, and re-checks the cycles it burns against the
/// balance that is left.
///
/// Here `canister_pre_upgrade` burns a small amount and `canister_post_upgrade`
/// burns the whole balance, with an ingress message inducted in every round of
/// the upgrade so that a debit accumulates while each of them is paused. The
/// burn of the last Wasm execution therefore has to be checked against a balance
/// that an earlier Wasm execution of the same `install_code` has already reduced,
/// on top of the debit charged in the meantime — something a single Wasm
/// execution of an install or a reinstall cannot cover.
///
/// The upgrade fails with `CanisterOutOfCycles` once the burn no longer fits;
/// `finish_err()` then restores the clean canister state, so neither burn is
/// applied, while the whole debit is charged.
#[test]
fn upgrade_burning_the_whole_balance_in_post_upgrade_fails_once_the_ingress_debit_is_charged() {
    const PRE_UPGRADE_BURN: u128 = 1_000_000;

    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(0)
            .build(),
    );

    // Arm the canister's `canister_pre_upgrade`, which the upgrade below runs on
    // the module installed here.
    env.execute_ingress_as(
        user(),
        canister_id,
        "update",
        wasm()
            .set_pre_upgrade(slow_burning(PRE_UPGRADE_BURN))
            .reply()
            .build(),
    )
    .expect("failed to set the pre_upgrade");

    // The upgrade's `canister_post_upgrade` is its install argument, which the
    // universal canister evaluates.
    let upgrade = env
        .send_ingress_safe(
            PrincipalId::new_anonymous(),
            CanisterId::ic_00(),
            Method::InstallCode,
            InstallCodeArgs::new(
                CanisterInstallMode::Upgrade,
                canister_id,
                UNIVERSAL_CANISTER_WASM.to_vec(),
                slow_burning(u128::MAX),
            )
            .encode(),
        )
        .expect("failed to submit the upgrade");

    // The baselines are taken after the round above, which started the upgrade
    // and paused `canister_pre_upgrade` after its first slice. That round also
    // charged the induction cost of the `install_code` message itself to the
    // canister's balance, as the canister had no paused execution when that
    // message was inducted.
    let induction_before = consumed(&env, canister_id, CyclesUseCase::IngressInduction);
    let burned_before = consumed(&env, canister_id, CyclesUseCase::BurnedCycles);
    assert_eq!(ingress_induction_debit(&env, canister_id), Cycles::zero());

    // Induct an ingress message in every round the upgrade still needs, so that
    // a debit accumulates while each of its Wasm executions is paused. Every one
    // of them is inducted before the round executes the next slice, hence while
    // the upgrade is still paused, so its cost is postponed into the debit.
    let payload = vec![0_u8; INGRESS_PAYLOAD_SIZE];
    let mut expected_debit = Cycles::zero();
    let mut rounds = 0;
    let mut status = env.ingress_status(&upgrade);
    while !matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Completed(_) | IngressState::Failed(_),
            ..
        }
    ) {
        assert_lt!(rounds, MAX_TICKS, "the upgrade did not complete");
        rounds += 1;
        expected_debit += env
            .ingress_message_cost(user(), canister_id, "update", payload.clone())
            .cost();
        // Note that submitting a message executes a round, which inducts it.
        env.send_ingress_safe(user(), canister_id, "update", payload.clone())
            .expect("failed to submit ingress message");
        status = env.ingress_status(&upgrade);
    }
    // `canister_pre_upgrade` alone spans `INIT_SLICES` slices, one per round, so
    // messages were inducted while a later Wasm execution of the upgrade was
    // paused as well.
    assert_gt!(rounds, INIT_SLICES as usize);
    assert_gt!(expected_debit, max_install_code_refund());

    // The upgrade failed because the burn of `canister_post_upgrade` no longer
    // fitted. Note that `check_critical_errors()`, which panics if any critical
    // error was raised, runs after every round executed here.
    let err = match status {
        IngressStatus::Known {
            state: IngressState::Failed(err),
            ..
        } => err,
        status => panic!("expected the upgrade to fail, got {status:?}"),
    };
    assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
    // The whole debit was charged, ...
    assert_eq!(ingress_induction_debit(&env, canister_id), Cycles::zero());
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::IngressInduction),
        induction_before + expected_debit
    );
    // ... and neither of the two burns was applied, as `finish_err()` restored
    // the canister state from before the upgrade.
    assert_eq!(
        consumed(&env, canister_id, CyclesUseCase::BurnedCycles),
        burned_before
    );
}
