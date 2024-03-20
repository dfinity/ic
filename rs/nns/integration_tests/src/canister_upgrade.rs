use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_clients::canister_status::CanisterStatusType;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID};
use ic_nns_governance::pb::v1::{
    manage_neuron_response::{Command, MakeProposalResponse},
    proposal::Action,
    ExecuteNnsFunction, NnsFunction, Proposal,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{get_canister_status, nns_governance_make_proposal, setup_nns_canisters},
};
use ic_state_machine_tests::StateMachine;

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

#[test]
fn upgrade_canister() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let lifeline_canister_id = CanisterId::from_u64(LIFELINE_CANISTER_INDEX_IN_NNS_SUBNET);
    let root_status_before = get_canister_status(
        &state_machine,
        PrincipalId::new_anonymous(),
        ROOT_CANISTER_ID,
        lifeline_canister_id,
    )
    .unwrap();
    let old_module_hash = root_status_before.module_hash.clone().unwrap();
    let wasm = lifeline::LIFELINE_CANISTER_WASM;
    let new_module_hash = &ic_crypto_sha2::Sha256::hash(wasm);

    assert_ne!(old_module_hash.as_slice(), new_module_hash);

    let change_canister_request =
        ChangeCanisterRequest::new(true, CanisterInstallMode::Upgrade, lifeline_canister_id)
            .with_memory_allocation(ic_nns_constants::memory_allocation_of(lifeline_canister_id))
            .with_wasm(wasm.to_vec());
    let proposal = Proposal {
        title: Some("Upgrade NNS Canister".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::NnsCanisterUpgrade as i32,
            payload: Encode!(&change_canister_request).expect("Error encoding proposal payload"),
        })),
    };
    // make proposal with neuron 1, it has enough voting power such that the proposal will be accepted
    let response =
        nns_governance_make_proposal(&mut state_machine, n1.principal_id, n1.neuron_id, &proposal)
            .command
            .expect("Making NNS proposal failed");

    assert_matches!(
        response,
        Command::MakeProposal(MakeProposalResponse {
            proposal_id: Some(ic_nns_common::pb::v1::ProposalId { id: 1 }),
            ..
        })
    );

    // wait until canister is running again
    loop {
        if let Ok(root_status) = get_canister_status(
            &state_machine,
            PrincipalId::new_anonymous(),
            ROOT_CANISTER_ID,
            lifeline_canister_id,
        ) {
            if root_status.status == CanisterStatusType::Running {
                break;
            }
        }
    }
    let root_status_after = get_canister_status(
        &state_machine,
        PrincipalId::new_anonymous(),
        ROOT_CANISTER_ID,
        lifeline_canister_id,
    )
    .unwrap();

    // there was a memory increase in `root` due to storing the Wasm
    assert!(root_status_after.memory_size > root_status_before.memory_size);
    // the other fields didn't change
    assert_eq!(
        root_status_before.module_hash,
        root_status_after.module_hash
    );
    assert_eq!(
        root_status_before.settings.controllers,
        root_status_after.settings.controllers
    );
    assert_eq!(root_status_before.cycles, root_status_after.cycles);
}
