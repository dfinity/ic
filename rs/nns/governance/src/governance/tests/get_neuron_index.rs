use crate::neuron::{DissolveStateAndAge, NeuronBuilder};
use crate::neuron_store::MAX_NEURON_PAGE_SIZE;
use crate::test_utils::MockRandomness;
use crate::{
    governance::Governance,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::GetNeuronIndexRequest;
use ic_nns_governance_api::{
    Governance as ApiGovernance, ListNeurons, NetworkEconomics, list_neurons::NeuronSubaccount,
};
use icp_ledger::Subaccount;
use std::sync::Arc;

#[test]
fn test_get_neuron_index() {
    // This user doesn't control any neurons.
    let user_id = PrincipalId::new_user_test_id(1001);

    let neurons = (1..=1000u64)
        .map(|id| {
            NeuronBuilder::new_for_test(
                id,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 0,
                },
            )
            .with_controller(PrincipalId::new_user_test_id(id))
            .build()
        })
        .collect::<Vec<_>>();

    let mut governance = Governance::new(
        ApiGovernance {
            economics: Some(NetworkEconomics {
                voting_power_economics: Some(Default::default()),
                ..Default::default()
            }),
            ..Default::default()
        },
        Arc::new(MockEnvironment::new(Default::default(), 0)),
        Arc::new(StubIcpLedger {}),
        Arc::new(StubCMC {}),
        Box::new(MockRandomness::new()),
    );

    for neuron in neurons {
        governance.add_neuron(neuron.id().id, neuron).unwrap();
    }

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: None,
        page_size: None,
    };

    let response = governance
        .get_neuron_index(request, user_id)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_eq!(response.neurons.len(), MAX_NEURON_PAGE_SIZE as usize);

    // let response_with_no_page_number = governance.neuron_store.list_all_neurons_paginated(
    //     NeuronId { id: 0 },
    //     MAX_NEURON_PAGE_SIZE,
    //     user_id,
    //     governance.env.now(),
    //     governance.voting_power_economics(),
    // );

    // assert_eq!(
    //     response_with_no_page_number.len(),
    //     MAX_NEURON_PAGE_SIZE as usize
    // );
}
