use candid::Encode;
use ic_base_types::CanisterId;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1 as nns_common_pb;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, RegisterVote},
    manage_neuron_response, proposal, ManageNeuron, ManageNeuronResponse, OpenSnsTokenSwap,
    Proposal, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    state_test_helpers::{nns_governance_make_proposal, setup_nns_canisters},
};
use ic_sns_swap::pb::v1::Params as SnsSwapParams;
use ic_state_machine_tests::StateMachine;

/// Submit three SetSnsTokenSwapOpenTimeWindow proposals. The first should succeed, the
/// second should fail because only one SetSnsTokenSwapOpenTimeWindow proposal can be open
/// at a time. After executing the first proposal, a third is submitted and should not be
/// rejected.
#[test]
fn test_only_one_sns_token_swap_proposal_can_be_open() {
    let mut state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let response = make_open_sns_token_swap_proposal(&mut state_machine);

    let make_proposal_response = match response.command {
        Some(manage_neuron_response::Command::MakeProposal(ref response)) => response,
        _ => panic!("First proposal failed to be submitted: {:#?}", response),
    };

    let proposal_id = make_proposal_response.proposal_id.unwrap_or_else(|| {
        panic!(
            "First proposal response did not contain a proposal_id: {:#?}",
            response
        )
    });

    let response2 = make_open_sns_token_swap_proposal(&mut state_machine);

    match response2.command {
        Some(manage_neuron_response::Command::Error(e)) => {
            assert!(
                e.error_message
                    .contains("at most one open OpenSnsTokenSwap"),
                "{:?}",
                e,
            );
        }
        _ => panic!("Second proposal should be invalid: {:#?}", response2),
    }

    // Execute the first proposal and test that another SetSnsTokenSwapOpenTimeWindow can
    // successfully be submitted
    execute_proposal(&mut state_machine, proposal_id);

    let response3 = make_open_sns_token_swap_proposal(&mut state_machine);

    let make_proposal_response3 = match response3.command {
        Some(manage_neuron_response::Command::MakeProposal(ref response)) => response,
        _ => panic!("Third proposal failed to be submitted: {:#?}", response3),
    };

    let _proposal_id = make_proposal_response3.proposal_id.unwrap_or_else(|| {
        panic!(
            "Third proposal response did not contain a proposal_id: {:#?}",
            response3
        )
    });
}

fn make_open_sns_token_swap_proposal(state_machine: &mut StateMachine) -> ManageNeuronResponse {
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_2_ID,
    };

    let now = state_machine
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let target_swap_canister_id = CanisterId::from_u64(14);

    let params = SnsSwapParams {
        max_icp_e8s: 42,
        min_icp_e8s: 42,
        min_participants: 1,
        max_participant_icp_e8s: 42,
        min_participant_icp_e8s: 42,
        sns_token_e8s: 42,
        swap_due_timestamp_seconds: now + 87500,
    };

    nns_governance_make_proposal(
        state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        &Proposal {
            title: Some("Open SNS Token Swap".to_string()),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::OpenSnsTokenSwap(OpenSnsTokenSwap {
                target_swap_canister_id: Some(target_swap_canister_id.into()),
                params: Some(params),
                community_fund_investment_e8s: Some(42),
            })),
        },
    )
}

fn execute_proposal(state_machine: &mut StateMachine, proposal_id: ProposalId) {
    state_machine
        .execute_ingress_as(
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            GOVERNANCE_CANISTER_ID,
            "manage_neuron",
            Encode!(&ManageNeuron {
                id: Some(nns_common_pb::NeuronId {
                    id: TEST_NEURON_1_ID
                }),
                command: Some(manage_neuron::Command::RegisterVote(RegisterVote {
                    proposal: Some(proposal_id),
                    vote: Vote::Yes as i32,
                })),
                neuron_id_or_subaccount: None
            })
            .unwrap(),
        )
        .unwrap();
}
