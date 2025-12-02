use crate::neuron::{DissolveStateAndAge, NeuronBuilder};
use crate::test_utils::MockRandomness;
use crate::{
    governance::{
        Governance,
        tests::{MockEnvironment, StubCMC, StubIcpLedger},
    },
    pb::v1::manage_neuron::StakeMaturity,
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::manage_neuron_response::StakeMaturityResponse;
use std::sync::Arc;

#[test]
fn test_stake_maturity() {
    let mut governance = Governance::new(
        Default::default(),
        Arc::new(MockEnvironment::new(vec![], 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    let principal_1 = PrincipalId::new_user_test_id(1);
    let neuron = NeuronBuilder::new_for_test(
        1,
        DissolveStateAndAge::NotDissolving {
            dissolve_delay_seconds: 31557600,
            aging_since_timestamp_seconds: 0,
        },
    )
    .with_controller(principal_1)
    .with_cached_neuron_stake_e8s(23)
    .with_maturity_e8s_equivalent(1000)
    .with_staked_maturity_e8s_equivalent(100)
    .build();
    governance.add_neuron(1, neuron).unwrap();

    let request = StakeMaturity {
        percentage_to_stake: Some(40),
    };

    let stake_maturity_response = governance
        .stake_maturity_of_neuron(&NeuronId { id: 1 }, &principal_1, &request)
        .expect("Expected call to succeed");

    assert_eq!(
        stake_maturity_response,
        StakeMaturityResponse {
            maturity_e8s: 600,
            staked_maturity_e8s: 500
        }
    );
}
