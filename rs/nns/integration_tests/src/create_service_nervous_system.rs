use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::{self as nns_common_pb, ProposalId};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::governance::test_data::CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING;
use ic_nns_governance_api::{
    ListProposalInfoRequest, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, ProposalActionRequest, ProposalStatus, Vote, governance_error::ErrorType,
    manage_neuron::RegisterVote, manage_neuron_response, proposal::Action,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    sns_wasm::add_real_wasms_to_sns_wasms,
    state_test_helpers::{
        SPECIFIED_CANISTER_ID, list_deployed_snses, nns_governance_make_proposal,
        nns_list_proposals, nns_wait_for_proposal_execution, set_controllers,
        setup_nns_canisters_with_features, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;
use lazy_static::lazy_static;
use maplit::hashset;
use std::collections::{HashMap, HashSet};

lazy_static! {
    static ref SNS_SUBNET_ID: SubnetId = PrincipalId::new_user_test_id(916030).into();
}

const ONE_TRILLION: u128 = 1_000_000_000_000;

/// Makes three CreateServiceNervousSystem proposals. The second one is not
/// allowed, because the first is still open. Then, the first proposal gets
/// adopted (allowing the third to be made) and executed. What should result is
/// a new SNS.
#[test]
fn test_several_proposals() {
    // Step 1: Prepare the world.

    let state_machine = state_machine_builder_for_nns_tests().build();

    // Step 1.1: Boot up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons_fund_neurons(100_000_000_000_000)
        .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .build();
    // Note that this uses production governance.
    setup_nns_canisters_with_features(&state_machine, nns_init_payload, /* features */ &[]);
    add_real_wasms_to_sns_wasms(&state_machine);
    let dapp_canister = state_machine.create_canister_with_cycles(
        Some(SPECIFIED_CANISTER_ID.get()),
        Cycles::zero(),
        None,
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        dapp_canister,
        vec![ROOT_CANISTER_ID.get()],
    );

    // In real life, DFINITY would top up SNS_WASM's cycle balance (and the SNS
    // is supposed to repay with ICP raised).
    state_machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION);

    // Step 2: Run code under test. Inspect intermediate results.

    // Step 2.1: Make a proposal. Leave it open so that the next proposal is
    // foiled.
    let response_1 = make_proposal(&state_machine, /* sns_number = */ 1, false);
    let response_1 = match response_1.command {
        Some(manage_neuron_response::Command::MakeProposal(resp)) => resp,
        _ => panic!("First proposal failed to be submitted: {response_1:#?}"),
    };
    let proposal_id_1 = response_1
        .proposal_id
        .unwrap_or_else(|| {
            panic!("First proposal response did not contain a proposal_id: {response_1:#?}")
        })
        .id;

    // Step 2.2: Make another proposal. This one should be foiled, because the
    // first proposal is still open.
    let response_2 = make_proposal(&state_machine, 666, false);
    match response_2.command {
        Some(manage_neuron_response::Command::Error(err)) => {
            assert_eq!(
                err.error_type,
                ErrorType::PreconditionFailed as i32,
                "{err:#?}",
            );
            assert!(err.error_message.contains("another open"), "{err:?}",);
        }
        _ => panic!("Second proposal should be invalid: {response_2:#?}"),
    }

    // Step 2.3: This unblocks more proposals from being made.
    execute_proposal(&state_machine, ProposalId { id: proposal_id_1 });

    // Step 2.4: Wait for proposal_1 to finish executing.
    nns_wait_for_proposal_execution(&state_machine, proposal_id_1);

    // Step 2.5: Finally, make a third proposal. This should now be allowed.
    let response_3 = make_proposal(&state_machine, 3, false);
    let response_3 = match response_3.command {
        Some(manage_neuron_response::Command::MakeProposal(response_3)) => response_3,
        _ => panic!("Third proposal failed to be submitted: {response_3:#?}"),
    };
    let proposal_id_3 = response_3
        .proposal_id
        .unwrap_or_else(|| {
            panic!("Third proposal response did not contain a proposal_id: {response_1:#?}")
        })
        .id;

    // Step 3: Inspect results.

    // Step 3.1: Inspect proposals.

    // There should only be two proposals of type CreateServiceNervousSystem.
    let final_proposals = nns_list_proposals(&state_machine, ListProposalInfoRequest::default())
        .proposal_info
        .into_iter()
        .filter_map(
            |proposal_info| match proposal_info.proposal.as_ref().unwrap().action {
                Some(Action::CreateServiceNervousSystem(_)) => {
                    let id = proposal_info.id.as_ref().unwrap().id;
                    Some((id, proposal_info))
                }
                _ => None,
            },
        )
        .collect::<HashMap<_, _>>();
    assert_eq!(
        final_proposals.keys().copied().collect::<HashSet<u64>>(),
        hashset! { proposal_id_1, proposal_id_3 },
        "{final_proposals:#?}",
    );

    let proposal_1 = final_proposals.get(&proposal_id_1).unwrap();
    let proposal_3 = final_proposals.get(&proposal_id_3).unwrap();

    assert_eq!(
        proposal_1.status,
        ProposalStatus::Executed as i32,
        "{proposal_1:#?}",
    );
    assert_eq!(
        proposal_3.status,
        ProposalStatus::Open as i32,
        "{proposal_1:#?}",
    );

    // Step 3.2: Inspect SNS(s).

    let snses = list_deployed_snses(&state_machine).instances;
    assert_eq!(snses.len(), 1, "{snses:#?}");
}

#[test]
fn test_nf_is_not_permitted() {
    // Step 1: Prepare the world.

    let state_machine = state_machine_builder_for_nns_tests().build();

    // Step 1.1: Boot up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons_fund_neurons(100_000_000_000_000)
        .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .build();
    // Use production governance (no test flags).
    setup_nns_canisters_with_features(&state_machine, nns_init_payload, /* features */ &[]);
    add_real_wasms_to_sns_wasms(&state_machine);
    let dapp_canister = state_machine.create_canister_with_cycles(
        Some(SPECIFIED_CANISTER_ID.get()),
        Cycles::zero(),
        None,
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        dapp_canister,
        vec![ROOT_CANISTER_ID.get()],
    );

    state_machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION);

    // Step 2: Run code under test.

    // Step 2.1: Make a proposal.  Should fail because it's using NF funding on non-test gov build.
    let response = make_proposal(&state_machine, /* sns_number = */ 1, true);
    assert_matches!(response.command,
        Some(manage_neuron_response::Command::Error(err))
            if err.error_type == ErrorType::InvalidProposal as i32 &&
            err.error_message.contains("NeuronsFundParticipation is not currently allowed"),
        "Expected an InvalidProposal error because NeuronsFundParticipation is not allowed on non-test builds.");
}

#[test]
fn test_nf_is_permitted_with_test_flag() {
    // Step 1: Prepare the world.

    let state_machine = state_machine_builder_for_nns_tests().build();

    // Step 1.1: Boot up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons_fund_neurons(100_000_000_000_000)
        .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .build();
    // Note that this uses governance with cfg(features = "test") enabled.
    setup_nns_canisters_with_features(
        &state_machine,
        nns_init_payload,
        /* features */ &["test"],
    );
    add_real_wasms_to_sns_wasms(&state_machine);
    let dapp_canister = state_machine.create_canister_with_cycles(
        Some(SPECIFIED_CANISTER_ID.get()),
        Cycles::zero(),
        None,
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        dapp_canister,
        vec![ROOT_CANISTER_ID.get()],
    );

    state_machine.add_cycles(SNS_WASM_CANISTER_ID, 200 * ONE_TRILLION);

    // Step 2: Run code under test.

    // Step 2.1: Make a proposal.  Should succeed because it's using NF funding on test gov build.
    // Should work without matched funding.
    let response = make_proposal(&state_machine, /* sns_number = */ 1, false);
    let response = match response.command {
        Some(manage_neuron_response::Command::MakeProposal(make_proposal)) => make_proposal,
        _ => panic!("Proposal failed to be submitted: {response:#?}"),
    };
    response.proposal_id.unwrap_or_else(|| {
        panic!("Proposal response did not contain a proposal_id: {response:#?}")
    });
}

/// Makes a CreateServiceNervousSystem proposal using test neuron 2.
fn make_proposal(
    state_machine: &StateMachine,
    sns_number: u64,
    nf_enabled: bool,
) -> ManageNeuronResponse {
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_2_ID,
    };

    let mut create_nervous_system = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
    if let Some(p) = create_nervous_system.swap_parameters.as_mut() {
        p.neurons_fund_participation = Some(nf_enabled);
    }

    nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        &MakeProposalRequest {
            title: Some(format!("Create SNS #{sns_number}")),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::CreateServiceNervousSystem(
                create_nervous_system.into(),
            )),
        },
    )
}

/// Makes test neuron 1 vote for the proposal. This should cause it to be
/// adopted and executed.
fn execute_proposal(state_machine: &StateMachine, proposal_id: ProposalId) {
    state_machine
        .execute_ingress_as(
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            Encode!(&ManageNeuronRequest {
                id: Some(nns_common_pb::NeuronId {
                    id: TEST_NEURON_1_ID
                }),
                command: Some(ManageNeuronCommandRequest::RegisterVote(RegisterVote {
                    proposal: Some(proposal_id),
                    vote: Vote::Yes as i32,
                })),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .unwrap();
}
