//! Make sure the governance canister scales

use candid::{Decode, Encode};
use canister_test::Project;
use ic_base_types::PrincipalId;
use ic_management_canister_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{ListProposalInfo, ListProposalInfoResponse};
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_nns_test_utils::state_test_helpers::{
    create_canister_id_at_position, nns_governance_get_proposal_info,
    nns_propose_upgrade_nns_canister, query, setup_nns_root_with_correct_canister_id,
    state_machine_builder_for_nns_tests, wait_for_canister_upgrade_to_succeed,
};

#[test]
fn governance_mem_test() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let state_setup_wasm = Project::cargo_bin_maybe_from_env("governance-mem-test-canister", &[]);
    create_canister_id_at_position(
        &state_machine,
        GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );

    state_machine
        .install_wasm_in_mode(
            GOVERNANCE_CANISTER_ID,
            CanisterInstallMode::Install,
            state_setup_wasm.bytes(),
            vec![],
        )
        .expect("Install did not work");

    setup_nns_root_with_correct_canister_id(&state_machine, RootCanisterInitPayload {});

    let real_gov_wasm = Project::cargo_bin_maybe_from_env("governance-canister", &[]);
    state_machine
        .upgrade_canister(
            GOVERNANCE_CANISTER_ID,
            real_gov_wasm.clone().bytes(),
            vec![],
        )
        .unwrap();

    let list_proposal_info = ListProposalInfo {
        limit: 1,
        before_proposal: None,
        exclude_topic: vec![],
        include_reward_status: vec![],
        include_status: vec![],
        include_all_manage_neuron_proposals: None,
        omit_large_fields: Some(false),
    };

    let proposals = query(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        "list_proposals",
        Encode!(&list_proposal_info).unwrap(),
    )
    .unwrap();

    let decoded = Decode!(&proposals, ListProposalInfoResponse).unwrap();

    assert_eq!(decoded.proposal_info.len(), 1);

    let wasm_hash = real_gov_wasm.sha256_hash();
    let module_arg = Encode!(&()).unwrap();
    let proposal_id = nns_propose_upgrade_nns_canister(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId {
            id: TEST_NEURON_1_ID,
        },
        GOVERNANCE_CANISTER_ID,
        real_gov_wasm.bytes(),
        module_arg,
        true,
    );

    state_machine.tick();

    wait_for_canister_upgrade_to_succeed(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        &wasm_hash,
        ROOT_CANISTER_ID.get(),
    );

    let proposal_info = nns_governance_get_proposal_info(
        &state_machine,
        proposal_id.id,
        PrincipalId::new_anonymous(),
    );

    assert_ne!(proposal_info.executed_timestamp_seconds, 0);

    // We now want to assert that the proposals still exist
    let mut list_proposal_info = list_proposal_info;
    list_proposal_info.limit = 2;
    let proposals = query(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        "list_proposals",
        Encode!(&list_proposal_info).unwrap(),
    )
    .unwrap();
    // We get 2 and drop 1 because we used an upgrade proposal (which we don't need to read)
    let decoded2 = Decode!(&proposals, ListProposalInfoResponse).unwrap();

    assert_eq!(
        decoded.proposal_info.first().unwrap(),
        decoded2.proposal_info.last().unwrap()
    );
}
