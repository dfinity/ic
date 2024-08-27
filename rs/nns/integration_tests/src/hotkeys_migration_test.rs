use assert_matches::assert_matches;
use candid::{Decode, Encode};
use canister_test::WasmResult;
use ic_nervous_system_integration_tests::create_service_nervous_system_builder::CreateServiceNervousSystemBuilder;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    get_neurons_fund_audit_info_response,
    manage_neuron_response::{self, MakeProposalResponse},
    neurons_fund_snapshot::NeuronsFundNeuronPortion,
    proposal, GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse, MakeProposalRequest,
    ManageNeuronCommandRequest, ManageNeuronResponse, NeuronsFundAuditInfo,
    NeuronsFundParticipation, NeuronsFundSnapshot, ProposalActionRequest,
};
use ic_nns_test_utils::{
    sns_wasm::build_governance_sns_wasm,
    state_test_helpers::{
        nns_create_super_powerful_neuron, nns_governance_make_proposal,
        nns_propose_upgrade_nns_canister, wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_state_machine_tests::StateMachine;
use ic_types::PrincipalId;

fn get_neurons_fund_audit_info(
    state_machine: &StateMachine,
    proposal_id: ProposalId,
) -> GetNeuronsFundAuditInfoResponse {
    let result = state_machine
        .execute_ingress_as(
            PrincipalId::new_anonymous(),
            GOVERNANCE_CANISTER_ID,
            "get_neurons_fund_audit_info",
            Encode!(&GetNeuronsFundAuditInfoRequest {
                nns_proposal_id: Some(proposal_id)
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(result) => result,
        WasmResult::Reject(s) => {
            panic!("Call to get_neurons_fund_audit_info failed: {:#?}", s)
        }
    };
    Decode!(&result, GetNeuronsFundAuditInfoResponse).unwrap()
}

/// Create a state machine with the golden NNS state, then upgrade and downgrade the ICP
/// ledger canister suite.
#[allow(deprecated)]
#[test]
fn test_hotkey_principal_migration() {
    use get_neurons_fund_audit_info_response::{Ok, Result};

    let state_machine = new_state_machine_with_golden_nns_state_or_panic();
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(&state_machine, neuron_controller);

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .build();

    let proposal = MakeProposalRequest {
        title: Some("Create SNS for tests".to_string()),
        summary: "".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::CreateServiceNervousSystem(
            create_service_nervous_system,
        )),
    };

    let response = {
        let sender = neuron_controller;
        nns_governance_make_proposal(&state_machine, sender, neuron_id, &proposal)
    };

    // Deploy an SNS instance via proposal.
    let ManageNeuronResponse {
        command:
            Some(manage_neuron_response::Command::MakeProposal(MakeProposalResponse {
                proposal_id: Some(proposal_id),
                ..
            })),
    } = response
    else {
        panic!("Unexpected response: {:?}", response);
    };

    {
        let nns_governance_wasm = build_governance_sns_wasm();
        let nns_governance_hash = nns_governance_wasm.sha256_hash();
        let module_arg = Encode!(&()).unwrap();
        let _ = nns_propose_upgrade_nns_canister(
            &state_machine,
            neuron_controller,
            neuron_id,
            GOVERNANCE_CANISTER_ID,
            nns_governance_wasm.wasm,
            module_arg,
            false,
        );
        wait_for_canister_upgrade_to_succeed(
            &state_machine,
            GOVERNANCE_CANISTER_ID,
            &nns_governance_hash,
            ROOT_CANISTER_ID.into(),
        );
    }

    let neurons_fund_audit_info = get_neurons_fund_audit_info(&state_machine, proposal_id);
    {
        let neurons_fund_audit_info = neurons_fund_audit_info.clone();
        let neurons_fund_neuron_portions = assert_matches!(
            neurons_fund_audit_info,
            GetNeuronsFundAuditInfoResponse {
                result: Some(Result::Ok(Ok {
                    neurons_fund_audit_info: Some(NeuronsFundAuditInfo {
                        initial_neurons_fund_participation: Some(NeuronsFundParticipation {
                            neurons_fund_reserves: Some(NeuronsFundSnapshot {
                                neurons_fund_neuron_portions,
                            }),
                            ..
                        }),
                        final_neurons_fund_participation: None,
                        neurons_fund_refunds: None,
                    })
                }))
            } => neurons_fund_neuron_portions
        );
        assert_matches!(
            &neurons_fund_neuron_portions[..],
            [NeuronsFundNeuronPortion {
                hotkey_principal: Some(_),
                ..
            }]
        );
    };
}
