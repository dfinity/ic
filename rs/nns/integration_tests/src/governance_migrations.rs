use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::manage_neuron_response::Command;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        nns_claim_or_refresh_neuron, nns_disburse_neuron, nns_send_icp_to_claim_or_refresh_neuron,
        nns_start_dissolving, query, setup_nns_canisters_with_features,
        state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{AccountIdentifier, Tokens};
use serde_bytes::ByteBuf;
use std::time::Duration;

fn assert_metric(state_machine: &StateMachine, name: &str, value: u64) {
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

    let line = response_body
        .lines()
        .filter(|line| line.starts_with(name))
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .to_string();
    assert!(
        line.starts_with(&format!("{} {} ", name, value)),
        "{}",
        line
    );
}

#[test]
fn test_neuron_migration_from_heap_to_stable() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let test_user_principal = PrincipalId::new_self_authenticating(&[1]);
    let nonce = 123_456;
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(
            AccountIdentifier::new(test_user_principal, None),
            Tokens::from_e8s(2_000_000_000),
        )
        .build();
    // Make sure the test feature is not enabled. Otherwise new neurons will be created in the
    // stable memory, which makes the test precondition wrong.
    setup_nns_canisters_with_features(&state_machine, nns_init_payloads, &[]);
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        test_user_principal,
        Tokens::from_e8s(1_000_000_000),
        nonce,
    );
    let neuron_id = nns_claim_or_refresh_neuron(&state_machine, test_user_principal, nonce);

    // Let heartbeat/timer run.
    for _ in 0..20 {
        state_machine.tick();
    }

    // Make sure that the neuron is in the heap memory and active.
    assert_metric(
        &state_machine,
        "governance_garbage_collectable_neurons_count",
        0,
    );
    assert_metric(&state_machine, "governance_heap_neuron_count", 1);
    assert_metric(&state_machine, "governance_stable_memory_neuron_count", 0);

    // Advance time and disburse the neuron so that it's empty.
    nns_start_dissolving(&state_machine, test_user_principal, neuron_id).unwrap();
    let time_to_dissolve = Duration::from_secs(60 * 60 * 24 * 7);
    state_machine.advance_time(time_to_dissolve);
    let disburse_response =
        nns_disburse_neuron(&state_machine, test_user_principal, neuron_id, None, None);
    assert_matches!(disburse_response.command, Some(Command::Disburse(_)));

    // After 14 days the neuron will become inactive. Advance enough time for that.
    let time_to_become_inactive = Duration::from_secs(60 * 60 * 24 * 20);
    state_machine.advance_time(time_to_become_inactive);

    // Let timer run.
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(60 * 60));
        state_machine.tick();
    }

    // After the timer runs, the inactive (garbage collectable) neuron should be moved to the stable
    // memory.
    assert_metric(
        &state_machine,
        "governance_garbage_collectable_neurons_count",
        1,
    );
    assert_metric(&state_machine, "governance_heap_neuron_count", 0);
    assert_metric(&state_machine, "governance_stable_memory_neuron_count", 1);
}
