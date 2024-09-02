use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::neuron_data_validation::NeuronDataValidationSummary;
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response::{Command, FollowResponse, SplitResponse},
    Topic,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::{get_neuron_1, get_neuron_2, get_neuron_3},
    state_test_helpers::{
        nns_set_followees_for_neuron, nns_split_neuron, query, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use serde_bytes::ByteBuf;
use std::time::Duration;

fn assert_no_validation_issues(state_machine: &StateMachine) {
    let response_bytes = query(
        state_machine,
        GOVERNANCE_CANISTER_ID,
        "get_neuron_data_validation_summary",
        Encode!(&{}).unwrap(),
    )
    .unwrap();
    let summary = Decode!(&response_bytes, NeuronDataValidationSummary).unwrap();
    assert_eq!(summary.current_validation_started_time_seconds, None);
    let current_issues_summary = summary.current_issues_summary.unwrap();
    assert_eq!(current_issues_summary.issue_groups, vec![]);
}

struct NeuronIndexesLens {
    subaccount: u64,
    principal: u64,
    following: u64,
    known_neuron: u64,
    account_id: u64,
}

fn assert_neuron_indexes_lens(
    state_machine: &StateMachine,
    neuron_indexes_lens: NeuronIndexesLens,
) {
    let response_bytes = query(
        state_machine,
        GOVERNANCE_CANISTER_ID,
        "http_request",
        Encode!(&HttpRequest {
            url: "/metrics".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
        })
        .unwrap(),
    )
    .unwrap();
    let response: HttpResponse = Decode!(&response_bytes, HttpResponse).unwrap();
    let response_body = String::from_utf8(response.body.into_vec()).unwrap();

    assert!(response_body.contains(&format!(
        "governance_subaccount_index_len {} ",
        neuron_indexes_lens.subaccount
    )));
    assert!(response_body.contains(&format!(
        "governance_principal_index_len {} ",
        neuron_indexes_lens.principal
    )));
    assert!(response_body.contains(&format!(
        "governance_following_index_len {} ",
        neuron_indexes_lens.following
    )));
    assert!(response_body.contains(&format!(
        "governance_known_neuron_index_len {} ",
        neuron_indexes_lens.known_neuron
    )));
    assert!(response_body.contains(&format!(
        "governance_account_id_index_len {} ",
        neuron_indexes_lens.account_id
    )));
}

#[test]
fn test_neuron_indexes_migrations() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Let heartbeat run and validation progress.
    for _ in 0..20 {
        state_machine.tick();
    }

    assert_neuron_indexes_lens(
        &state_machine,
        NeuronIndexesLens {
            subaccount: 3,
            principal: 3,
            following: 0,
            known_neuron: 0,
            account_id: 3,
        },
    );
    assert_no_validation_issues(&state_machine);

    let neuron_1 = get_neuron_1();
    let neuron_2 = get_neuron_2();
    let neuron_3 = get_neuron_3();

    // Follow will cause the neuron to be modified.
    let follow_response = nns_set_followees_for_neuron(
        &state_machine,
        neuron_3.principal_id,
        neuron_3.neuron_id,
        &[neuron_1.neuron_id, neuron_2.neuron_id],
        Topic::Governance as i32,
    )
    .command
    .expect("Manage neuron command failed");
    assert_eq!(follow_response, Command::Follow(FollowResponse {}));

    assert_neuron_indexes_lens(
        &state_machine,
        NeuronIndexesLens {
            subaccount: 3,
            principal: 3,
            following: 2,
            known_neuron: 0,
            account_id: 3,
        },
    );

    // Split will cause a neuron to be created.
    let split_response = nns_split_neuron(
        &state_machine,
        neuron_1.principal_id,
        neuron_1.neuron_id,
        500_000_000,
    )
    .command
    .expect("Manage neuron command failed");
    assert_matches!(split_response, Command::Split(SplitResponse { .. }));

    assert_neuron_indexes_lens(
        &state_machine,
        NeuronIndexesLens {
            subaccount: 4,
            principal: 4,
            following: 2,
            known_neuron: 0,
            account_id: 4,
        },
    );

    // Advance time so the validation can rerun.
    let two_days = Duration::from_secs(60 * 60 * 24 * 2);
    state_machine.advance_time(two_days);

    // Let heartbeat run and validation progress again.
    for _ in 0..20 {
        state_machine.tick();
    }

    assert_no_validation_issues(&state_machine);
}
