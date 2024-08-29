use assert_matches::assert_matches;
use candid::Encode;
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    get_neurons_fund_audit_info_response, neurons_fund_snapshot::NeuronsFundNeuronPortion,
    GetNeuronsFundAuditInfoResponse, ListProposalInfo, ListProposalInfoResponse,
    NeuronsFundAuditInfo, NeuronsFundParticipation, NeuronsFundSnapshot, Topic,
};
use ic_nns_test_utils::{
    common::build_governance_wasm,
    state_test_helpers::{
        get_all_proposal_ids, get_neurons_fund_audit_info, nns_create_super_powerful_neuron,
        nns_list_proposals, nns_propose_upgrade_nns_canister, wait_for_canister_upgrade_to_succeed,
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

// clear && bazel test //rs/nns/integration_tests:hotkeys_migration_test  --test_env=SSH_AUTH_SOCK --test_output=streamed --test_arg=--nocapture
#[allow(deprecated)]
#[test]
fn test_hotkey_principal_migration() {
    use get_neurons_fund_audit_info_response::{Ok, Result};

    let state_machine = new_state_machine_with_golden_nns_state_or_panic();
    let neuron_controller = PrincipalId::new_self_authenticating(&[1, 2, 3, 4]);
    let neuron_id = nns_create_super_powerful_neuron(&state_machine, neuron_controller);

    {
        let nns_governance_wasm = build_governance_wasm();
        let nns_governance_hash = nns_governance_wasm.sha256_hash();
        let module_arg = Encode!(&()).unwrap();
        let _ = nns_propose_upgrade_nns_canister(
            &state_machine,
            neuron_controller,
            neuron_id,
            GOVERNANCE_CANISTER_ID,
            nns_governance_wasm.bytes(),
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

    let proposal_ids = get_all_proposal_ids(&state_machine, all_but_csns());
    assert!(
        !proposal_ids.is_empty(),
        "Smoke test failed: We expect to have at some proposals."
    );

    let mut neuron_portions = vec![];

    for proposal_id in proposal_ids {
        let neurons_fund_audit_info = get_neurons_fund_audit_info(&state_machine, proposal_id);
        // Old SNSes might not have audit info.
        let (
            initial_neurons_fund_participation,
            final_neurons_fund_participation,
            neurons_fund_refunds,
        ) = if let GetNeuronsFundAuditInfoResponse {
            result:
                Some(Result::Ok(Ok {
                    neurons_fund_audit_info:
                        Some(NeuronsFundAuditInfo {
                            initial_neurons_fund_participation,
                            final_neurons_fund_participation,
                            neurons_fund_refunds,
                        }),
                })),
        } = neurons_fund_audit_info
        {
            (
                initial_neurons_fund_participation,
                final_neurons_fund_participation,
                neurons_fund_refunds,
            )
        } else {
            (None, None, None)
        };

        // Old SNSes might not have initial_neurons_fund_participation.
        if let Some(NeuronsFundParticipation {
            neurons_fund_reserves:
                Some(NeuronsFundSnapshot {
                    neurons_fund_neuron_portions,
                }),
            ..
        }) = initial_neurons_fund_participation
        {
            neuron_portions.extend(neurons_fund_neuron_portions.into_iter());
        }
        // Conversely, final_neurons_fund_participation might not be specified even for new SNSes
        // that have ongoing swaps.
        if let Some(NeuronsFundParticipation {
            neurons_fund_reserves:
                Some(NeuronsFundSnapshot {
                    neurons_fund_neuron_portions,
                }),
            ..
        }) = final_neurons_fund_participation
        {
            neuron_portions.extend(neurons_fund_neuron_portions.into_iter());
        }
        // There may or may not be refunds.
        if let Some(NeuronsFundSnapshot {
            neurons_fund_neuron_portions,
        }) = neurons_fund_refunds
        {
            neuron_portions.extend(neurons_fund_neuron_portions.into_iter());
        }
    }

    // Smoke test: We have some data that needs migrating.
    assert!(!neuron_portions.is_empty());

    // Assert that all collected neuron portions have been migrated correctly.
    for neuron_portion in neuron_portions {
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
}
