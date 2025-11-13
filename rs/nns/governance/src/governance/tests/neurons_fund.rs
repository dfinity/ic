use super::*;
use crate::{
    pb::v1::create_service_nervous_system::SwapParameters,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use assert_matches::assert_matches;
use ic_nervous_system_common::E8;
use ic_nervous_system_proto::pb::v1 as pb;
use ic_nns_governance_api as pb_api;
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use test_data::CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING;

#[test]
fn proposal_passes_if_not_too_many_nf_neurons_can_occur() {
    let proposal_id = ProposalId { id: 123 };
    let create_service_nervous_system = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
    let governance_init = GovernanceCanisterInitPayloadBuilder::new()
        .with_test_neurons_fund_neurons(500_000 * E8)
        .build();
    let mut governance = Governance::new(
        governance_init,
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    governance.heap_data.proposals.insert(
        proposal_id.id,
        ProposalData {
            id: Some(proposal_id),
            ..ProposalData::default()
        },
    );
    // Run code under test
    governance
        .draw_maturity_from_neurons_fund(&proposal_id, &create_service_nervous_system)
        .unwrap();
}

#[test]
fn proposal_fails_if_too_many_nf_neurons_can_occur() {
    let num_neurons_fund_neurons = 5_001;
    let maturity_equivalent_icp_e8s = u64::MAX / num_neurons_fund_neurons;
    let proposal_id = ProposalId { id: 123 };
    let create_service_nervous_system = {
        let create_service_nervous_system =
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
        let swap_parameters = SwapParameters {
            // This avoids all neurons having less than `minimum_participant_icp` in terms of
            // their proportional maturity amounts eligible for SNS swap participation.
            minimum_participant_icp: Some(pb::Tokens {
                e8s: Some(E8 / 100),
            }),
            ..create_service_nervous_system
                .swap_parameters
                .clone()
                .unwrap()
        };
        CreateServiceNervousSystem {
            swap_parameters: Some(swap_parameters),
            ..create_service_nervous_system
        }
    };
    let governance_init = {
        let proto_neuron = GovernanceCanisterInitPayloadBuilder::new()
            .with_test_neurons_fund_neurons(maturity_equivalent_icp_e8s)
            .build()
            .neurons
            .into_iter()
            .find_map(|(_, neuron)| {
                if neuron.joined_community_fund_timestamp_seconds.unwrap() > 0 {
                    Some(neuron)
                } else {
                    None
                }
            })
            .unwrap();
        let neurons = (0..num_neurons_fund_neurons)
            .map(|id| pb_api::Neuron {
                id: Some(NeuronId { id }),
                ..proto_neuron.clone()
            })
            .collect();
        GovernanceCanisterInitPayloadBuilder::new()
            .with_additional_neurons(neurons)
            .build()
    };
    let mut governance = Governance::new(
        governance_init,
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );
    governance.heap_data.proposals.insert(
        proposal_id.id,
        ProposalData {
            id: Some(proposal_id),
            ..ProposalData::default()
        },
    );
    // Run code under test
    let err = governance
        .draw_maturity_from_neurons_fund(&proposal_id, &create_service_nervous_system)
        .unwrap_err();

    let expected_error_sub_message = format!(
        "The maximum number of Neurons' Fund participants ({num_neurons_fund_neurons}) \
        must not exceed MAX_NEURONS_FUND_PARTICIPANTS ({MAX_NEURONS_FUND_PARTICIPANTS}).",
    );
    assert_matches!(err, GovernanceError {
        error_type,
        error_message,
    } => {
        assert_eq!(ErrorType::try_from(error_type).unwrap(), ErrorType::InvalidProposal);
        assert!(
            error_message.contains(&expected_error_sub_message),
            "Observed error:\n{error_message}\ndoes not contain expected substring `{expected_error_sub_message}`."
        );
    });
}

#[test]
fn proposal_fails_if_no_nf_neurons_exist() {
    let proposal_id = ProposalId { id: 123 };
    let create_service_nervous_system = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();
    let governance_init = GovernanceCanisterInitPayloadBuilder::new().build();
    let mut governance = Governance::new(
        governance_init,
        Arc::<MockEnvironment>::default(),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );
    governance.heap_data.proposals.insert(
        proposal_id.id,
        ProposalData {
            id: Some(proposal_id),
            ..ProposalData::default()
        },
    );
    // Run code under test
    let err = governance
        .draw_maturity_from_neurons_fund(&proposal_id, &create_service_nervous_system)
        .unwrap_err();

    let expected_error_sub_message = "Cannot compute Neurons' Fund participation \
        intervals, as total_maturity_equivalent_icp_e8s = 0";
    assert_matches!(err, GovernanceError {
        error_type,
        error_message,
    } => {
        assert_eq!(ErrorType::try_from(error_type).unwrap(), ErrorType::InvalidProposal);
        assert!(
            error_message.contains(expected_error_sub_message),
            "Observed error:\n{error_message}\ndoes not contain expected substring `{expected_error_sub_message}`."
        );
    });
}
