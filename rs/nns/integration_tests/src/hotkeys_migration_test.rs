use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    get_neurons_fund_audit_info_response,
    manage_neuron_response::{self, MakeProposalResponse},
    neurons_fund_snapshot::NeuronsFundNeuronPortion,
    proposal, GetNeuronsFundAuditInfoRequest, GetNeuronsFundAuditInfoResponse, ListProposalInfo,
    ListProposalInfoResponse, MakeProposalRequest, ManageNeuronCommandRequest,
    ManageNeuronResponse, NeuronsFundAuditInfo, NeuronsFundParticipation, NeuronsFundSnapshot,
    ProposalActionRequest, Topic,
};
use ic_nns_test_utils::{
    sns_wasm::build_governance_sns_wasm,
    state_test_helpers::{
        get_neurons_fund_audit_info, nns_create_super_powerful_neuron,
        nns_governance_make_proposal, nns_list_proposals, nns_propose_upgrade_nns_canister,
        wait_for_canister_upgrade_to_succeed,
    },
};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use ic_state_machine_tests::StateMachine;
use ic_types::PrincipalId;

fn all_but_csns() -> Vec<i32> {
    [
        Topic::Unspecified,
        Topic::NeuronManagement,
        Topic::ExchangeRate,
        Topic::NetworkEconomics,
        Topic::Governance,
        Topic::NodeAdmin,
        Topic::ParticipantManagement,
        Topic::SubnetManagement,
        Topic::NetworkCanisterManagement,
        Topic::Kyc,
        Topic::NodeProviderRewards,
        Topic::IcOsVersionDeployment,
        Topic::IcOsVersionElection,
        // Topic::SnsAndCommunityFund,
        Topic::ApiBoundaryNodeManagement,
        Topic::SubnetRental,
        Topic::ProtocolCanisterManagement,
        Topic::ServiceNervousSystemManagement,
    ]
    .into_iter()
    .map(i32::from)
    .collect()
}

#[allow(deprecated)]
#[test]
fn test_hotkey_principal_migration() {
    use get_neurons_fund_audit_info_response::{Ok, Result};

    let state_machine = new_state_machine_with_golden_nns_state_or_panic();
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(&state_machine, neuron_controller);

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

    let ListProposalInfoResponse { proposal_info } = nns_list_proposals(
        &state_machine,
        ListProposalInfo {
            limit: 100,
            before_proposal: None,
            exclude_topic: all_but_csns(),
            include_reward_status: vec![],
            include_status: vec![],
            include_all_manage_neuron_proposals: None,
            omit_large_fields: Some(true),
        },
    );

    let proposal_ids = proposal_info
        .into_iter()
        .map(|info| info.id.unwrap())
        .collect::<Vec<_>>();

    for proposal_id in proposal_ids {
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
            for neuron_portion in neurons_fund_neuron_portions {
                assert_matches!(
                    neuron_portion,
                    NeuronsFundNeuronPortion {
                        // The legacy field is still set.
                        hotkey_principal: Some(hotkey_principal),
                        // The new field set to the same value.
                        controller: Some(controller),
                        ..
                    } if hotkey_principal == controller
                );
            }
        };
    }
}
