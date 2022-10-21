use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1 as nns_common_pb;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_governance::pb::v1::{
    manage_neuron::{self, RegisterVote},
    manage_neuron_response, proposal, ManageNeuron, ManageNeuronResponse, OpenSnsTokenSwap,
    Proposal, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    sns_wasm::{add_dummy_wasms_to_sns_wasms, deploy_new_sns},
    state_test_helpers::{
        nns_governance_make_proposal, set_up_universal_canister, setup_nns_canisters,
    },
};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_swap::pb::v1::{params::NeuronBasketConstructionParameters, Params as SnsSwapParams};
use ic_state_machine_tests::StateMachine;
use ic_types::Cycles;
use lazy_static::lazy_static;

lazy_static! {
    static ref SNS_SUBNET_ID: SubnetId = PrincipalId::new_user_test_id(916030).into();
}

/// Submit three SetSnsTokenSwapOpenTimeWindow proposals. The first should succeed, the
/// second should fail because only one SetSnsTokenSwapOpenTimeWindow proposal can be open
/// at a time. After executing the first proposal, a third is submitted and should not be
/// rejected.
#[test]
fn test_only_one_sns_token_swap_proposal_can_be_open() {
    // Step 1: Prepare the world.

    let mut state_machine = StateMachine::new();

    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);

    // Step 1.1: Boot up NNS.
    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_test_neurons()
        .with_sns_dedicated_subnets(state_machine.get_subnet_ids())
        .with_sns_wasm_access_controls(true)
        .with_sns_wasm_allowed_principals(vec![wallet_canister_id.into()])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payload);
    add_dummy_wasms_to_sns_wasms(&state_machine);

    // Step 1.2: Tell sns-wasm to create an SNS.
    let cycle_count = 50_000_000_000_000;
    let wallet_canister = set_up_universal_canister(&state_machine, Some(Cycles::new(cycle_count)));
    let deploy_new_sns_response = deploy_new_sns(
        &state_machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_values_for_testing(),
        cycle_count,
    );
    let swap_canister_id = deploy_new_sns_response.canisters.unwrap().swap.unwrap();

    // Step 1.3: Make an OpenSnsTokenSwap proposal, but leave it open so that
    // the next OpenSnsTokenSwap proposal is foiled.
    let response = make_open_sns_token_swap_proposal(&mut state_machine, swap_canister_id);

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

    // Step 2: Run the code under test.
    let response2 = make_open_sns_token_swap_proposal(&mut state_machine, swap_canister_id);

    // Step 3: Insepct the result. Expect it to be a fail.
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

    // Back to step 1.
    // Step 1.4: Approve and execute the first proposal.

    // Execute the first proposal and test that another SetSnsTokenSwapOpenTimeWindow can
    // successfully be submitted
    execute_proposal(&mut state_machine, proposal_id);

    // Back to step 2.
    // Step 2.2: Run the code under test again, but this time under favorable circumstances.
    let response3 = make_open_sns_token_swap_proposal(&mut state_machine, swap_canister_id);

    // Back to step 3.
    // Step 3.2: Inspect the result. This time, it should be a success.
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

fn make_open_sns_token_swap_proposal(
    state_machine: &mut StateMachine,
    target_swap_canister_id: PrincipalId,
) -> ManageNeuronResponse {
    let neuron_id = nns_common_pb::NeuronId {
        id: TEST_NEURON_2_ID,
    };

    let now = state_machine
        .time()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let params = SnsSwapParams {
        max_icp_e8s: 42,
        min_icp_e8s: 42,
        min_participants: 1,
        max_participant_icp_e8s: 42,
        min_participant_icp_e8s: 42,
        sns_token_e8s: 42,
        swap_due_timestamp_seconds: now + 87500,
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 3,
            dissolve_delay_interval_seconds: 7890000, // 3 months
        }),
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
                target_swap_canister_id: Some(target_swap_canister_id),
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
