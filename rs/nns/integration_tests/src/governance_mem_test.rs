//! Make sure the governance canister scales

use candid::{Decode, Encode};
use canister_test::Project;
use ic_nns_governance::pb::v1::{ListProposalInfo, ListProposalInfoResponse};
use ic_nns_test_utils::state_test_helpers::{
    create_canister, query, state_machine_builder_for_nns_tests,
};

#[test]
fn governance_mem_test() {
    let state_machine = state_machine_builder_for_nns_tests().build();

    let state_setup_wasm = Project::cargo_bin_maybe_from_env("governance-mem-test-canister", &[]);
    let governance_canister_id =
        create_canister(&state_machine, state_setup_wasm, Some(vec![]), None);

    let real_gov_wasm = Project::cargo_bin_maybe_from_env("governance-canister", &[]);
    state_machine
        .upgrade_canister(
            governance_canister_id,
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
        governance_canister_id,
        "list_proposals",
        Encode!(&list_proposal_info).unwrap(),
    )
    .unwrap();

    let decoded = Decode!(&proposals, ListProposalInfoResponse).unwrap();

    assert_eq!(decoded.proposal_info.len(), 1);

    state_machine
        .upgrade_canister(governance_canister_id, real_gov_wasm.bytes(), vec![])
        .unwrap();

    // We now want to assert that the data is the same as before the second upgrade.
    let proposals = query(
        &state_machine,
        governance_canister_id,
        "list_proposals",
        Encode!(&list_proposal_info).unwrap(),
    )
    .unwrap();
    let decoded2 = Decode!(&proposals, ListProposalInfoResponse).unwrap();

    assert_eq!(decoded, decoded2);
}
