use assert_matches::assert_matches;
use candid::{Decode, Encode, Principal};
use ic_nervous_system_proto::pb::v1::{
    GetTimersRequest, GetTimersResponse, ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_nns_test_utils::sns_wasm::{build_governance_sns_wasm, build_root_sns_wasm};
use ic_sns_governance::pb::v1::governance::GovernanceCachedMetrics;
use ic_sns_governance::{init::GovernanceCanisterInitPayloadBuilder, pb::v1::Governance};
use ic_sns_root::pb::v1::{Extensions, SnsRootCanister};
use ic_sns_swap::pb::v1::{
    GetStateRequest, GetStateResponse, Init, Lifecycle, NeuronBasketConstructionParameters,
};
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, PrincipalId};
use pretty_assertions::assert_eq;
use std::time::{Duration, SystemTime};

const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
const ONE_WEEK_SECONDS: u64 = 7 * ONE_DAY_SECONDS;

fn swap_init(now: SystemTime) -> Init {
    let now = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let swap_due_timestamp_seconds =
        Some((now + Duration::from_secs(2 * ONE_WEEK_SECONDS)).as_secs());

    Init {
        swap_due_timestamp_seconds,
        nns_governance_canister_id: Principal::anonymous().to_string(),
        sns_governance_canister_id: Principal::anonymous().to_string(),
        sns_ledger_canister_id: Principal::anonymous().to_string(),
        icp_ledger_canister_id: Principal::anonymous().to_string(),
        sns_root_canister_id: Principal::anonymous().to_string(),
        fallback_controller_principal_ids: vec![Principal::anonymous().to_string()],
        transaction_fee_e8s: Some(10_000),
        neuron_minimum_stake_e8s: Some(1_000_000),
        confirmation_text: None,
        restricted_countries: None,
        min_participants: Some(5),
        min_icp_e8s: None,
        max_icp_e8s: None,
        min_direct_participation_icp_e8s: Some(12_300_000_000),
        max_direct_participation_icp_e8s: Some(65_000_000_000),
        min_participant_icp_e8s: Some(6_500_000_000),
        max_participant_icp_e8s: Some(65_000_000_000),
        swap_start_timestamp_seconds: Some(0),
        sns_token_e8s: Some(10_000_000),
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 10_001,
        }),
        nns_proposal_id: Some(10),
        should_auto_finalize: Some(true),
        neurons_fund_participation_constraints: None,
        neurons_fund_participation: Some(false),
    }
}

fn governance_init() -> Governance {
    let mut governance = GovernanceCanisterInitPayloadBuilder::new()
        .with_root_canister_id(PrincipalId::new_anonymous())
        .with_ledger_canister_id(PrincipalId::new_anonymous())
        .with_swap_canister_id(PrincipalId::new_anonymous())
        .with_ledger_canister_id(PrincipalId::new_anonymous())
        .build();

    governance.metrics = Some(GovernanceCachedMetrics {
        timestamp_seconds: u64::MAX, // Ensure that cached metrics are not attempted to be refreshed in tests.
        ..Default::default()
    });

    governance
}

fn root_init() -> SnsRootCanister {
    SnsRootCanister {
        governance_canister_id: Some(PrincipalId::new_anonymous()),
        ledger_canister_id: Some(PrincipalId::new_anonymous()),
        swap_canister_id: Some(PrincipalId::new_anonymous()),
        index_canister_id: Some(PrincipalId::new_anonymous()),
        archive_canister_ids: vec![],
        dapp_canister_ids: vec![],
        extensions: Some(Extensions {
            extension_canister_ids: vec![],
        }),
        testflight: false,
        timers: None,
    }
}

fn get_timers(state_machine: &StateMachine, canister_id: CanisterId) -> Option<Timers> {
    let payload = Encode!(&GetTimersRequest {}).unwrap();
    let response = state_machine
        .execute_ingress(canister_id, "get_timers", payload)
        .unwrap_or_else(|err| {
            panic!("Unable to call get_timers on canister {canister_id:?}: {err}")
        });
    let response = Decode!(&response.bytes(), GetTimersResponse).unwrap();
    response.timers
}

fn try_reset_timers(state_machine: &StateMachine, canister_id: CanisterId) -> Result<(), String> {
    let payload = Encode!(&ResetTimersRequest {}).unwrap();
    let response = state_machine.execute_ingress(canister_id, "reset_timers", payload);
    match response {
        Ok(response) => {
            let response = response.bytes();
            let ResetTimersResponse {} = Decode!(&response, ResetTimersResponse).unwrap();
            Ok(())
        }
        Err(err) => Err(err.to_string()),
    }
}

/// Assumes that `canister_id` is an ID of an already installed canister that implements:
/// - `get_timers`
/// - `reset_timers`
fn run_canister_reset_timers_test(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    reset_timers_cool_down_interval_seconds: u64,
    run_periodic_tasks_interval_seconds: u64,
) {
    let last_spawned_timestamp_seconds = {
        let timers = get_timers(state_machine, canister_id);
        let last_reset_timestamp_seconds = assert_matches!(timers, Some(Timers {
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds),
            last_spawned_timestamp_seconds: None,
            ..
        }) => last_reset_timestamp_seconds);

        // Resetting the timers cannot be done sooner than `reset_timers_cool_down_interval_seconds`
        // after the canister is initialized.
        state_machine.advance_time(Duration::from_secs(reset_timers_cool_down_interval_seconds));
        state_machine.tick();

        let timers = get_timers(state_machine, canister_id);
        let last_spawned_timestamp_seconds = assert_matches!(timers, Some(Timers {
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds_1),
            last_spawned_timestamp_seconds: Some(last_spawned_timestamp_seconds),
            ..
        }) => {
            assert_eq!(last_reset_timestamp_seconds_1, last_reset_timestamp_seconds);
            last_spawned_timestamp_seconds
        });

        assert_eq!(
            last_spawned_timestamp_seconds,
            last_reset_timestamp_seconds + reset_timers_cool_down_interval_seconds
        );
        last_spawned_timestamp_seconds
    };

    // Reset the timers.
    try_reset_timers(state_machine, canister_id).unwrap_or_else(|err| {
        panic!("Unable to call reset_timers on canister {canister_id:?}: {err}")
    });

    // Inspect the sate after resetting the timers.
    {
        let last_spawned_before_reset_timestamp_seconds = last_spawned_timestamp_seconds;

        let timers = get_timers(state_machine, canister_id);
        let last_reset_timestamp_seconds = assert_matches!(timers, Some(Timers {
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds),
            last_spawned_timestamp_seconds: None,
            ..
        }) => last_reset_timestamp_seconds);

        // last_spawned_before_reset_timestamp_seconds is from before the reset, as time did not yet
        // advance since the timers were reset.
        assert_eq!(
            last_reset_timestamp_seconds,
            last_spawned_before_reset_timestamp_seconds
        );

        state_machine.advance_time(Duration::from_secs(run_periodic_tasks_interval_seconds));
        state_machine.tick();

        let timers = get_timers(state_machine, canister_id);
        let last_spawned_timestamp_seconds = assert_matches!(timers, Some(Timers {
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds_1),
            last_spawned_timestamp_seconds: Some(last_spawned_timestamp_seconds),
            ..
        }) => {
            assert_eq!(last_reset_timestamp_seconds_1, last_reset_timestamp_seconds);
            last_spawned_timestamp_seconds
        });

        assert_eq!(
            last_spawned_timestamp_seconds,
            last_spawned_before_reset_timestamp_seconds + run_periodic_tasks_interval_seconds
        );
    }
}

fn run_canister_reset_timers_cannot_be_spammed_test(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    reset_timers_cool_down_interval_seconds: u64,
) {
    // Ensure there was more than `reset_timers_cool_down_interval_seconds` seconds since the timers
    // were initialized.
    state_machine.advance_time(Duration::from_secs(reset_timers_cool_down_interval_seconds));
    state_machine.tick();

    let get_last_spawned_timestamp_seconds = || {
        let timers = get_timers(state_machine, canister_id);
        let last_reset_timestamp_seconds = assert_matches!(timers, Some(Timers {
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds),
            ..
        }) => last_reset_timestamp_seconds);
        last_reset_timestamp_seconds
    };

    try_reset_timers(state_machine, canister_id).unwrap_or_else(|err| {
        panic!("Unable to call reset_timers on canister {canister_id:?}: {err}")
    });

    let last_spawned_timestamp_seconds_1 = get_last_spawned_timestamp_seconds();

    // Attempt to reset the timers again, after a small delay.
    let insufficient_for_resetting_timers_by_seconds = reset_timers_cool_down_interval_seconds
        .checked_sub(100)
        .unwrap();
    state_machine.advance_time(Duration::from_secs(
        insufficient_for_resetting_timers_by_seconds,
    ));
    state_machine.tick();

    {
        let err_text = try_reset_timers(state_machine, canister_id).unwrap_err();
        assert!(err_text.contains(&format!(
            "Reset has already been called within the past {reset_timers_cool_down_interval_seconds} seconds"
        )));
    }

    let last_spawned_timestamp_seconds_2 = get_last_spawned_timestamp_seconds();

    // The last call should not have had an effect.
    assert_eq!(
        last_spawned_timestamp_seconds_1,
        last_spawned_timestamp_seconds_2
    );

    // Attempt to reset the timers again after reset cool down.
    state_machine.advance_time(Duration::from_secs(100));
    state_machine.tick();

    try_reset_timers(state_machine, canister_id).unwrap_or_else(|err| {
        panic!("Unable to call reset_timers on canister {canister_id:?}: {err}")
    });

    let last_spawned_timestamp_seconds_3 = get_last_spawned_timestamp_seconds();

    assert_eq!(
        last_spawned_timestamp_seconds_3,
        last_spawned_timestamp_seconds_2 + reset_timers_cool_down_interval_seconds
    );
}

#[test]
fn test_swap_periodic_tasks_disabled_eventually() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the swap canister.
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&swap_init(state_machine.time())).unwrap();
    let canister_id = state_machine
        .install_canister(wasm.clone(), args, None)
        .unwrap();

    // Helpers.
    let get_relevant_state_components = || {
        let payload = Encode!(&GetStateRequest {}).unwrap();
        let response = state_machine
            .execute_ingress(canister_id, "get_state", payload)
            .expect("Unable to call get_state on the Swap canister");
        let response = Decode!(&response.bytes(), GetStateResponse).unwrap();
        let swap_state = response.swap.unwrap();
        (
            swap_state.timers,
            swap_state.lifecycle(),
            swap_state.already_tried_to_auto_finalize,
        )
    };

    // This first tick brings us to the Open lifecycle state.
    state_machine.advance_time(Duration::from_secs(100));
    state_machine.tick();

    // Inspect the initial state.
    assert_matches!(
        get_relevant_state_components(),
        (
            Some(Timers {
                requires_periodic_tasks: Some(true),
                last_reset_timestamp_seconds: Some(_),
                last_spawned_timestamp_seconds: Some(_),
            }),
            Lifecycle::Open,
            Some(false),
        )
    );

    // Each periodic tasks performs at most one action, so we need to wait for all the following
    // actions to complete:
    // (1) advance the Swap lifecycle
    // (2) set already_tried_to_auto_finalize
    // (3) unset requires_periodic_tasks
    state_machine.advance_time(Duration::from_secs(2 * ONE_WEEK_SECONDS));
    state_machine.tick();
    state_machine.advance_time(Duration::from_secs(100));
    state_machine.tick();
    state_machine.advance_time(Duration::from_secs(100));
    state_machine.tick();

    // Inspect the final state.
    assert_matches!(
        get_relevant_state_components(),
        (
            Some(Timers {
                requires_periodic_tasks: Some(false),
                last_reset_timestamp_seconds: Some(_),
                last_spawned_timestamp_seconds: Some(_),
            }),
            Lifecycle::Aborted,
            Some(true),
        )
    );
}

#[test]
fn test_swap_reset_timers() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the swap canister.
    let canister_id = {
        let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
        let args = Encode!(&swap_init(state_machine.time())).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_test(&state_machine, canister_id, 600, 60);
}

#[test]
fn test_governance_reset_timers() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the Governance canister.
    let canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let args = Encode!(&governance_init()).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_test(&state_machine, canister_id, 600, 60);
}

#[test]
fn test_root_reset_timers() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let canister_id = {
        let wasm = build_root_sns_wasm().wasm;
        let args = Encode!(&root_init()).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_test(
        &state_machine,
        canister_id,
        ONE_WEEK_SECONDS,
        ONE_DAY_SECONDS,
    );
}

#[test]
fn test_swap_reset_timers_cannot_be_spammed() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the swap canister.
    let canister_id = {
        let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
        let args = Encode!(&swap_init(state_machine.time())).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_cannot_be_spammed_test(&state_machine, canister_id, 600);
}

#[test]
fn test_governance_reset_timers_cannot_be_spammed() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let canister_id = {
        let wasm = build_governance_sns_wasm().wasm;
        let args = Encode!(&governance_init()).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_cannot_be_spammed_test(&state_machine, canister_id, 600);
}

#[test]
fn test_root_reset_timers_cannot_be_spammed() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let canister_id = {
        let wasm = build_root_sns_wasm().wasm;
        let args = Encode!(&root_init()).unwrap();
        state_machine
            .install_canister(wasm.clone(), args, None)
            .unwrap()
    };

    run_canister_reset_timers_cannot_be_spammed_test(&state_machine, canister_id, ONE_WEEK_SECONDS);
}
