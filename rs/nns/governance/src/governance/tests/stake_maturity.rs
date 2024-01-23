use crate::{
    governance::{
        tests::{MockEnvironment, StubCMC, StubIcpLedger},
        Governance,
    },
    pb::v1::{
        manage_neuron::StakeMaturity,
        manage_neuron_response::{MergeMaturityResponse, StakeMaturityResponse},
        neuron, Governance as GovernanceProto, Neuron,
    },
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use maplit::btreemap;

#[test]
fn test_stake_maturity() {
    let principal_1 = PrincipalId::new_user_test_id(1);
    let neuron_1 = Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(principal_1),
        cached_neuron_stake_e8s: 23,
        account: b"a__4___8__12__16__20__24__28__32".to_vec(),
        // One year
        dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
        maturity_e8s_equivalent: 1000,
        staked_maturity_e8s_equivalent: Some(100),
        ..Default::default()
    };

    let mut governance = Governance::new(
        GovernanceProto {
            neurons: btreemap! {
                1 => neuron_1
            },
            ..GovernanceProto::default()
        },
        Box::new(MockEnvironment::new(vec![], 0)),
        Box::new(StubIcpLedger {}),
        Box::new(StubCMC {}),
    );

    let request = StakeMaturity {
        percentage_to_stake: Some(40),
    };
    let responses = governance
        .stake_maturity_of_neuron(&NeuronId { id: 1 }, &principal_1, &request)
        .expect("Expected call to succeed");

    let (stake_maturity_response, legacy_merge_maturity_response) = responses;

    assert_eq!(
        stake_maturity_response,
        StakeMaturityResponse {
            maturity_e8s: 600,
            staked_maturity_e8s: 500
        }
    );
    assert_eq!(
        legacy_merge_maturity_response,
        MergeMaturityResponse {
            merged_maturity_e8s: 400,
            new_stake_e8s: 523
        }
    );
}
