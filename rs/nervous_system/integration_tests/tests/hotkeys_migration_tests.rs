use assert_matches::assert_matches;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers,
    pocket_ic_helpers::{nns, upgrade_nns_canister_to_tip_of_master_or_panic},
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::{
    get_neurons_fund_audit_info_response, neurons_fund_snapshot::NeuronsFundNeuronPortion,
    GetNeuronsFundAuditInfoResponse, NeuronsFundAuditInfo, NeuronsFundParticipation,
    NeuronsFundSnapshot,
};

#[allow(deprecated)]
#[test]
fn test_hotkey_principal_migration() {
    use get_neurons_fund_audit_info_response::{Ok, Result};

    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .build();

    // Deploy an SNS instance via proposal.
    let sns_instance_label = "1";
    let (_, proposal_id) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        sns_instance_label,
    );

    upgrade_nns_canister_to_tip_of_master_or_panic(&pocket_ic, GOVERNANCE_CANISTER_ID);

    let neurons_fund_audit_info =
        nns::governance::get_neurons_fund_audit_info(&pocket_ic, proposal_id);
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
