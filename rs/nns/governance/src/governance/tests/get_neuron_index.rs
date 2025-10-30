use std::sync::Arc;

use crate::neuron::{DissolveStateAndAge, NeuronBuilder};
use crate::neuron_store::MAX_NEURON_PAGE_SIZE;
use crate::test_utils::MockRandomness;
use crate::{
    governance::Governance,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use crate::{
    temporarily_disable_comprehensive_neuron_list, temporarily_enable_comprehensive_neuron_list,
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::{GetNeuronIndexRequest, NeuronInfo};
use ic_nns_governance_api::{Governance as ApiGovernance, NetworkEconomics};

fn make_governance_for_neuron_index() -> Governance {
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

    for id in 1..=500_u64 {
        let neuron = NeuronBuilder::new_for_test(
            id,
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds: 100,
                aging_since_timestamp_seconds: 0,
            },
        )
        .with_controller(PrincipalId::new_user_test_id(id))
        .build();

        governance.add_neuron(id, neuron).unwrap();
    }

    governance
}

// This user doesn't control any neurons.
static NEURONLESS_USER_ID: PrincipalId = PrincipalId::new_user_test_id(1001);

#[track_caller]
fn assert_neuron_index(neurons: &[NeuronInfo], start_id: u64, size: usize) {
    assert_eq!(neurons.len(), size);
    for (i, neuron) in neurons.iter().enumerate() {
        let expected_id = start_id + i as u64;
        let neuron_id = neuron.id.unwrap().id;
        assert_eq!(
            neuron_id, expected_id,
            "Expected neuron ID {} but found {}",
            expected_id, neuron_id
        );
    }
}

#[test]
fn test_get_neuron_index_empty_args() {
    let _temp = temporarily_enable_comprehensive_neuron_list();

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: None,
        page_size: None,
    };

    let response = governance
        .get_neuron_index(request, NEURONLESS_USER_ID)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_neuron_index(&response.neurons, 1, MAX_NEURON_PAGE_SIZE as usize);
}

#[test]
fn test_get_neuron_index_large_page() {
    let _temp = temporarily_enable_comprehensive_neuron_list();

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: None,
        page_size: Some(500),
    };

    let response = governance
        .get_neuron_index(request, NEURONLESS_USER_ID)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_neuron_index(&response.neurons, 1, MAX_NEURON_PAGE_SIZE as usize);
}

#[test]
fn test_get_neuron_index_multiple_pages() {
    let _temp = temporarily_enable_comprehensive_neuron_list();

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 0 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance
        .get_neuron_index(request, NEURONLESS_USER_ID)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_neuron_index(&response.neurons, 1, MAX_NEURON_PAGE_SIZE as usize);

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 300 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance
        .get_neuron_index(request, NEURONLESS_USER_ID)
        .expect("Expected valid GetNeuronIndexResponse");

    // We expect only 200 neurons on the last page.
    // Because there are 500 neurons total and we have already fetched 300.
    assert_neuron_index(&response.neurons, MAX_NEURON_PAGE_SIZE as u64 + 1, 200);
}

#[test]
fn test_get_neuron_index_disabled() {
    let _temp = temporarily_disable_comprehensive_neuron_list();

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 0 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance.get_neuron_index(request, NEURONLESS_USER_ID);

    assert!(response.is_err());
}
