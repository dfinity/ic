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
    let controller = PrincipalId::new_user_test_id(100);

    let neurons = (1..1_000_u64)
        .map(|id| {
            NeuronBuilder::new_for_test(
                id,
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 0,
                },
            )
            .with_controller(controller)
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

    let response_with_no_page_number = governance.list_neurons(&request, controller);
    request.page_number = Some(0);
    let response_with_0_page_number = governance.list_neurons(&request, controller);

    assert_eq!(response_with_0_page_number, response_with_no_page_number);
    assert_eq!(response_with_0_page_number.full_neurons.len(), 50);
    assert_eq!(response_with_0_page_number.total_pages_available, Some(20));

    // Request the last page.
    let response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: Some(19),
            page_size: None,
            neuron_subaccounts: None,
        },
        controller,
    );

    // Since the controller has 999 neurons, and the maximum page size is 50,
    // the last page would only have 49 neurons in it.
    assert_eq!(response.full_neurons.len(), 49);
    assert_eq!(response.total_pages_available, Some(20));

    // Assert maximum page size cannot be exceeded
    let response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: Some(0),
            page_size: Some(51),
            neuron_subaccounts: None,
        },
        controller,
    );

    assert_eq!(response.full_neurons.len(), 50);
    assert_eq!(response.total_pages_available, Some(20));
}

#[test]
fn test_list_neurons_by_subaccounts_and_ids() {
    let controller = PrincipalId::new_user_test_id(100);

    let neurons = (1..1_000_u64)
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
            .with_controller(controller)
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

    let first_page_request = ListNeurons {
        neuron_ids: (1..501).collect(),
        include_neurons_readable_by_caller: false,
        include_empty_neurons_readable_by_caller: None,
        include_public_neurons_in_full_neurons: None,
        page_number: None,
        page_size: None,
        neuron_subaccounts: Some(
            (501..1_000)
                .map(|id| NeuronSubaccount {
                    subaccount: crate::test_utils::test_subaccount_for_neuron_id(id),
                })
                .collect(),
        ),
    };

    let first_page_response = governance.list_neurons(&first_page_request, controller);
    assert_eq!(first_page_response.full_neurons.len(), 50);
    assert_eq!(first_page_response.total_pages_available, Some(20));

    let last_page_response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: (1..501).collect(),
            include_neurons_readable_by_caller: false,
            include_empty_neurons_readable_by_caller: None,
            include_public_neurons_in_full_neurons: None,
            page_number: Some(19),
            page_size: None,
            neuron_subaccounts: Some(
                (501..1_000)
                    .map(|id| NeuronSubaccount {
                        subaccount: crate::test_utils::test_subaccount_for_neuron_id(id),
                    })
                    .collect(),
            ),
        },
        controller,
    );

    assert_eq!(last_page_response.full_neurons.len(), 49);
    assert_eq!(last_page_response.total_pages_available, Some(20));
}
