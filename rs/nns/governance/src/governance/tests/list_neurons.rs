use crate::neuron::{DissolveStateAndAge, NeuronBuilder};
use crate::test_utils::MockRandomness;
use crate::{
    governance::Governance,
    test_utils::{MockEnvironment, StubCMC, StubIcpLedger},
};
use ic_base_types::PrincipalId;
use ic_nns_governance_api::{
    Governance as ApiGovernance, ListNeurons, NetworkEconomics, list_neurons::NeuronSubaccount,
};
use icp_ledger::Subaccount;
use std::sync::Arc;

#[test]
fn test_list_neurons_with_paging() {
    let user_id = PrincipalId::new_user_test_id(100);

    let neurons = (1..1000u64)
        .map(|id| {
            NeuronBuilder::new_for_test(
                id,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 0,
                },
            )
            .with_controller(user_id)
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

    let mut request = ListNeurons {
        neuron_ids: vec![],
        include_neurons_readable_by_caller: true,
        include_empty_neurons_readable_by_caller: Some(true),
        include_public_neurons_in_full_neurons: None,
        page_number: None,
        page_size: None,
        neuron_subaccounts: Some(vec![]),
    };

    let response_with_no_page_number = governance.list_neurons(&request, user_id);
    request.page_number = Some(0);
    let response_with_0_page_number = governance.list_neurons(&request, user_id);

    assert_eq!(response_with_0_page_number, response_with_no_page_number);
    assert_eq!(response_with_0_page_number.full_neurons.len(), 500);
    assert_eq!(response_with_0_page_number.total_pages_available, Some(2));

    let response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: Some(1),
            page_size: None,
            neuron_subaccounts: None,
        },
        user_id,
    );

    assert_eq!(response.full_neurons.len(), 499);
    assert_eq!(response.total_pages_available, Some(2));

    // Assert maximum page size cannot be exceeded
    let response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: Some(0),
            page_size: Some(501),
            neuron_subaccounts: None,
        },
        user_id,
    );

    assert_eq!(response.full_neurons.len(), 500);
    assert_eq!(response.total_pages_available, Some(2));
}

#[test]
fn test_list_neurons_by_subaccounts_and_ids() {
    let user_id = PrincipalId::new_user_test_id(100);

    let neurons = (1..1000u64)
        .map(|id| {
            NeuronBuilder::new_for_test(
                id,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 0,
                },
            )
            .with_subaccount(
                Subaccount::try_from(
                    crate::test_utils::test_subaccount_for_neuron_id(id).as_slice(),
                )
                .unwrap(),
            )
            .with_controller(user_id)
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

    let request = ListNeurons {
        neuron_ids: (1..501).collect(),
        include_neurons_readable_by_caller: false,
        include_empty_neurons_readable_by_caller: None,
        include_public_neurons_in_full_neurons: None,
        page_number: None,
        page_size: None,
        neuron_subaccounts: Some(
            (501..1000)
                .map(|id| NeuronSubaccount {
                    subaccount: crate::test_utils::test_subaccount_for_neuron_id(id),
                })
                .collect(),
        ),
    };

    let response_1 = governance.list_neurons(&request, user_id);
    assert_eq!(response_1.full_neurons.len(), 500);
    assert_eq!(response_1.total_pages_available, Some(2));

    let response_2 = governance.list_neurons(
        &ListNeurons {
            neuron_ids: (1..501).collect(),
            include_neurons_readable_by_caller: false,
            include_empty_neurons_readable_by_caller: None,
            include_public_neurons_in_full_neurons: None,
            page_number: Some(1),
            page_size: None,
            neuron_subaccounts: Some(
                (501..1000)
                    .map(|id| NeuronSubaccount {
                        subaccount: crate::test_utils::test_subaccount_for_neuron_id(id),
                    })
                    .collect(),
            ),
        },
        user_id,
    );

    assert_eq!(response_2.full_neurons.len(), 499);
    assert_eq!(response_2.total_pages_available, Some(2));
}
