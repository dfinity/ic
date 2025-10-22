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
use ic_nns_governance_api::GetNeuronIndexRequest;
use ic_nns_governance_api::{Governance as ApiGovernance, NetworkEconomics};
use std::sync::Arc;

fn make_governance_for_neuron_index() -> Governance {
    let neurons = (1..=500u64)
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
    governance
}

#[test]
fn test_get_neuron_index_empty_args() {
    let _temp = temporarily_enable_comprehensive_neuron_list();
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
}

#[test]
fn test_get_neuron_index_large_page() {
    let _temp = temporarily_enable_comprehensive_neuron_list();
    // This user doesn't control any neurons.
    let user_id = PrincipalId::new_user_test_id(1001);

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: None,
        page_size: Some(500),
    };

    let response = governance
        .get_neuron_index(request, user_id)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_eq!(response.neurons.len(), MAX_NEURON_PAGE_SIZE as usize);
}

#[test]
fn test_get_neuron_index_multiple_pages() {
    let _temp = temporarily_enable_comprehensive_neuron_list();
    // This user doesn't control any neurons.
    let user_id = PrincipalId::new_user_test_id(1001);

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 0 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance
        .get_neuron_index(request, user_id)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_eq!(response.neurons.len(), MAX_NEURON_PAGE_SIZE as usize);

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 300 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance
        .get_neuron_index(request, user_id)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_eq!(response.neurons.len(), 200);
}

#[test]
fn test_get_neuron_index_disabled() {
    let _temp = temporarily_disable_comprehensive_neuron_list();
    // This user doesn't control any neurons.
    let user_id = PrincipalId::new_user_test_id(1001);

    let governance = make_governance_for_neuron_index();

    let request = GetNeuronIndexRequest {
        exclusive_start_neuron_id: Some(NeuronId { id: 0 }),
        page_size: Some(MAX_NEURON_PAGE_SIZE),
    };

    let response = governance
        .get_neuron_index(request, user_id)
        .expect("Expected valid GetNeuronIndexResponse");

    assert_eq!(response.neurons.len(), 0);
}
