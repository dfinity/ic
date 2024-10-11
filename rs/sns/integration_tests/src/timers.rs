use assert_matches::assert_matches;
use candid::{Decode, Encode, Principal};
use ic_sns_swap::pb::v1::{
    GetStateRequest, GetStateResponse, Init, Lifecycle, NeuronBasketConstructionParameters,
    ResetTimersRequest, ResetTimersResponse, Timers,
};
use ic_sns_test_utils::state_test_helpers::state_machine_builder_for_sns_tests;
use pretty_assertions::assert_eq;
use std::time::{Duration, SystemTime};

const TWO_WEEKS_SECONDS: u64 = 14 * 24 * 60 * 60;

fn swap_init(now: SystemTime) -> Init {
    let now = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let swap_due_timestamp_seconds = Some((now + Duration::from_secs(TWO_WEEKS_SECONDS)).as_secs());

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

#[test]
fn test_swap_disabled_eventually() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the swap canister.
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&swap_init(state_machine.time())).unwrap();
    let canister_id = state_machine
        .install_canister(wasm.clone(), args, None)
        .unwrap();

    state_machine.advance_time(Duration::from_secs(100));
    state_machine.tick();

    // Inspect the initial state.
    {
        let (timers, lifecycle, already_tried_to_auto_finalize) = {
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

        assert_eq!(lifecycle, Lifecycle::Open);

        assert_eq!(already_tried_to_auto_finalize, Some(false));

        assert_matches!(
            timers,
            Some(Timers {
                requires_periodic_tasks: Some(true),
                last_reset_timestamp_seconds: Some(_),
                last_spawned_timestamp_seconds: Some(_),
            })
        );
    }

    state_machine.advance_time(Duration::from_secs(TWO_WEEKS_SECONDS));
    state_machine.tick();

    // Inspect the final state.
    {
        let (timers, lifecycle, already_tried_to_auto_finalize) = {
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

        assert_eq!(lifecycle, Lifecycle::Aborted);

        assert_eq!(already_tried_to_auto_finalize, Some(true));

        assert_matches!(
            timers,
            Some(Timers {
                // This is the main postcondition of this test.
                requires_periodic_tasks: Some(false),
                last_reset_timestamp_seconds: Some(_),
                last_spawned_timestamp_seconds: Some(_),
            })
        );
    }
}

#[test]
fn test_swap_reset_timers() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Install the swap canister.
    let wasm = ic_test_utilities_load_wasm::load_wasm("../swap", "sns-swap-canister", &[]);
    let args = Encode!(&swap_init(state_machine.time())).unwrap();
    let canister_id = state_machine
        .install_canister(wasm.clone(), args, None)
        .unwrap();

    let last_spawned_timestamp_seconds = {
        let timers_right_after_init = {
            let payload = Encode!(&GetStateRequest {}).unwrap();
            let response = state_machine
                .execute_ingress(canister_id, "get_state", payload)
                .expect("Unable to call get_state on the Swap canister");
            let response = Decode!(&response.bytes(), GetStateResponse).unwrap();
            response.swap.unwrap().timers
        };

        let last_reset_timestamp_seconds = assert_matches!(timers_right_after_init, Some(Timers {
            requires_periodic_tasks: Some(true),
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds),
            last_spawned_timestamp_seconds: None,
        }) => last_reset_timestamp_seconds);

        state_machine.advance_time(Duration::from_secs(100));
        state_machine.tick();

        let timers_before_reset = {
            let payload = Encode!(&GetStateRequest {}).unwrap();
            let response = state_machine
                .execute_ingress(canister_id, "get_state", payload)
                .expect("Unable to call get_state on the Swap canister");
            let response = Decode!(&response.bytes(), GetStateResponse).unwrap();
            response.swap.unwrap().timers
        };

        let last_spawned_timestamp_seconds = assert_matches!(timers_before_reset, Some(Timers {
            requires_periodic_tasks: Some(true),
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds_1),
            last_spawned_timestamp_seconds: Some(last_spawned_timestamp_seconds),
        }) => {
            assert_eq!(last_reset_timestamp_seconds_1, last_reset_timestamp_seconds);
            last_spawned_timestamp_seconds
        });

        assert_eq!(
            last_spawned_timestamp_seconds,
            last_reset_timestamp_seconds + 100
        );
        last_spawned_timestamp_seconds
    };

    // Reset the timers.
    {
        let payload = Encode!(&ResetTimersRequest {}).unwrap();
        let response = state_machine
            .execute_ingress(canister_id, "reset_timers", payload)
            .expect("Unable to call reset_timers on the Swap canister");
        Decode!(&response.bytes(), ResetTimersResponse).unwrap();
    }

    // Inspect the sate after resetting the timers.
    {
        let last_spawned_before_reset_timestamp_seconds = last_spawned_timestamp_seconds;

        let timers_right_after_reset = {
            let payload = Encode!(&GetStateRequest {}).unwrap();
            let response = state_machine
                .execute_ingress(canister_id, "get_state", payload)
                .expect("Unable to call get_state on the Swap canister");
            let response = Decode!(&response.bytes(), GetStateResponse).unwrap();
            response.swap.unwrap().timers
        };

        let last_reset_timestamp_seconds = assert_matches!(timers_right_after_reset, Some(Timers {
            requires_periodic_tasks: Some(true),
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds),
            last_spawned_timestamp_seconds: None,
        }) => last_reset_timestamp_seconds);

        // last_spawned_before_reset_timestamp_seconds is from before the reset, as time did not yet
        // advance since the timers were reset.
        assert_eq!(
            last_reset_timestamp_seconds,
            last_spawned_before_reset_timestamp_seconds
        );

        state_machine.advance_time(Duration::from_secs(100));
        state_machine.tick();

        let timers_a_while_after_reset = {
            let payload = Encode!(&GetStateRequest {}).unwrap();
            let response = state_machine
                .execute_ingress(canister_id, "get_state", payload)
                .expect("Unable to call get_state on the Swap canister");
            let response = Decode!(&response.bytes(), GetStateResponse).unwrap();
            response.swap.unwrap().timers
        };

        let last_spawned_timestamp_seconds = assert_matches!(timers_a_while_after_reset, Some(Timers {
            requires_periodic_tasks: Some(true),
            last_reset_timestamp_seconds: Some(last_reset_timestamp_seconds_1),
            last_spawned_timestamp_seconds: Some(last_spawned_timestamp_seconds),
        }) => {
            assert_eq!(last_reset_timestamp_seconds_1, last_reset_timestamp_seconds);
            last_spawned_timestamp_seconds
        });

        assert_eq!(
            last_spawned_timestamp_seconds,
            last_spawned_before_reset_timestamp_seconds + 100
        );
    }
}
