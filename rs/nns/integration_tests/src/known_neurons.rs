use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::{
    DeregisterKnownNeuron, KnownNeuron, KnownNeuronData, ListKnownNeuronsResponse, TopicToFollow,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        list_known_neurons, nns_claim_or_refresh_neuron, nns_deregister_known_neuron,
        nns_governance_get_neuron_info, nns_increase_dissolve_delay, nns_register_known_neuron,
        nns_send_icp_to_claim_or_refresh_neuron, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use icp_ledger::{AccountIdentifier, Tokens};

/// Integration test for the known neuron functionality including deregistration.
///
/// The test does the following:
/// - Start with 3 neurons, none of them "known".
/// - Assert entire list_known_neurons response equals empty list initially.
/// - Register a name for two of them via governance proposals.
/// - Assert entire list_known_neurons response equals expected 2-neuron list.
/// - Deregister one of the known neurons via governance proposal.
/// - Assert entire list_known_neurons response equals expected 1-neuron list.
/// - Update the remaining known neuron to have a description.
/// - Assert entire list_known_neurons response equals expected 1-neuron list with description.
#[test]
fn test_known_neurons() {
    // Step 1.1: Prepare the world by setting up NNS canisters with 2 principals both with 10 ICP.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let principal_1 = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let principal_2 = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (
                AccountIdentifier::new(principal_1, None),
                Tokens::from_e8s(1_000_000_000),
            ),
            (
                AccountIdentifier::new(principal_2, None),
                Tokens::from_e8s(1_000_000_000),
            ),
        ])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 1.2: Claim 3 neurons - principal 1 has 2 neurons, principal 2 has 1 neuron. All with 2 ICPs.
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_1,
        Tokens::from_e8s(200_000_000),
        1,
    );
    let neuron_id_1 = nns_claim_or_refresh_neuron(&state_machine, principal_1, 1);

    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_1,
        Tokens::from_e8s(200_000_000),
        2,
    );
    let neuron_id_2 = nns_claim_or_refresh_neuron(&state_machine, principal_1, 2);

    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_2,
        Tokens::from_e8s(200_000_000),
        3,
    );
    let neuron_id_3 = nns_claim_or_refresh_neuron(&state_machine, principal_2, 3);

    // Step 1.3: Increase dissolve delay to enable proposal making.
    nns_increase_dissolve_delay(&state_machine, principal_1, neuron_id_1, ONE_YEAR_SECONDS)
        .expect("Failed to increase dissolve delay for neuron 1");

    // Step 1.4: Verify that initially there are no known neurons.
    assert_eq!(
        list_known_neurons(&state_machine),
        ListKnownNeuronsResponse {
            known_neurons: vec![],
        }
    );

    // Step 2: Register two neurons as known neurons.
    nns_register_known_neuron(
        &state_machine,
        principal_1,
        neuron_id_1,
        KnownNeuron {
            id: Some(NeuronId { id: neuron_id_2.id }),
            known_neuron_data: Some(KnownNeuronData {
                name: "NeuronTwo".to_string(),
                description: Some("Second test neuron".to_string()),
                links: Some(vec![]),
                committed_topics: Some(vec![]),
            }),
        },
    );
    nns_register_known_neuron(
        &state_machine,
        principal_1,
        neuron_id_1,
        KnownNeuron {
            id: Some(NeuronId { id: neuron_id_3.id }),
            known_neuron_data: Some(KnownNeuronData {
                name: "NeuronThree".to_string(),
                description: None,
                links: Some(vec![]),
                committed_topics: Some(vec![]),
            }),
        },
    );

    // Step 3: Verify that both neurons are now known neurons and get_neuron_info returns the KnownNeuronData.
    assert_eq!(
        list_known_neurons(&state_machine),
        ListKnownNeuronsResponse {
            known_neurons: vec![
                KnownNeuron {
                    id: Some(NeuronId { id: neuron_id_3.id }),
                    known_neuron_data: Some(KnownNeuronData {
                        name: "NeuronThree".to_string(),
                        description: None,
                        links: Some(vec![]),
                        committed_topics: Some(vec![]),
                    }),
                },
                KnownNeuron {
                    id: Some(NeuronId { id: neuron_id_2.id }),
                    known_neuron_data: Some(KnownNeuronData {
                        name: "NeuronTwo".to_string(),
                        description: Some("Second test neuron".to_string()),
                        links: Some(vec![]),
                        committed_topics: Some(vec![]),
                    }),
                },
            ],
        }
    );
    assert_eq!(
        nns_governance_get_neuron_info(&state_machine, principal_1, neuron_id_2.id)
            .unwrap()
            .known_neuron_data
            .unwrap(),
        KnownNeuronData {
            name: "NeuronTwo".to_string(),
            description: Some("Second test neuron".to_string()),
            links: Some(vec![]),
            committed_topics: Some(vec![]),
        }
    );
    assert_eq!(
        nns_governance_get_neuron_info(&state_machine, principal_1, neuron_id_3.id)
            .unwrap()
            .known_neuron_data
            .unwrap(),
        KnownNeuronData {
            name: "NeuronThree".to_string(),
            description: None,
            links: Some(vec![]),
            committed_topics: Some(vec![]),
        }
    );

    // Step 4: Deregister one of the known neurons.
    nns_deregister_known_neuron(
        &state_machine,
        principal_1,
        neuron_id_1,
        DeregisterKnownNeuron {
            id: Some(NeuronId { id: neuron_id_2.id }),
        },
    );

    // Step 5: Verify that only one known neuron remains and the get_neuron_info doesn't return the
    // KnownNeuronData for the deregistered neuron.
    assert_eq!(
        list_known_neurons(&state_machine),
        ListKnownNeuronsResponse {
            known_neurons: vec![KnownNeuron {
                id: Some(NeuronId { id: neuron_id_3.id }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "NeuronThree".to_string(),
                    description: None,
                    links: Some(vec![]),
                    committed_topics: Some(vec![]),
                }),
            }],
        }
    );
    assert_eq!(
        nns_governance_get_neuron_info(&state_machine, principal_1, neuron_id_2.id)
            .unwrap()
            .known_neuron_data,
        None,
    );

    // Step 6: Upate the remaininig known neuron to have a description.
    nns_register_known_neuron(
        &state_machine,
        principal_1,
        neuron_id_1,
        KnownNeuron {
            id: Some(NeuronId { id: neuron_id_3.id }),
            known_neuron_data: Some(KnownNeuronData {
                name: "NeuronThree".to_string(),
                description: Some("Third test neuron".to_string()),
                links: Some(vec!["https://example.com".to_string()]),
                committed_topics: Some(vec![
                    Some(TopicToFollow::NetworkEconomics),
                    Some(TopicToFollow::Governance),
                ]),
            }),
        },
    );

    // Step 7: Verify that the known neuron now has a description through list_known_neurons and get_neuron_info.
    assert_eq!(
        list_known_neurons(&state_machine),
        ListKnownNeuronsResponse {
            known_neurons: vec![KnownNeuron {
                id: Some(NeuronId { id: neuron_id_3.id }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "NeuronThree".to_string(),
                    description: Some("Third test neuron".to_string()),
                    links: Some(vec!["https://example.com".to_string()]),
                    committed_topics: Some(vec![
                        Some(TopicToFollow::NetworkEconomics),
                        Some(TopicToFollow::Governance)
                    ]),
                }),
            }],
        }
    );
    assert_eq!(
        nns_governance_get_neuron_info(&state_machine, principal_1, neuron_id_3.id)
            .unwrap()
            .known_neuron_data
            .unwrap(),
        KnownNeuronData {
            name: "NeuronThree".to_string(),
            description: Some("Third test neuron".to_string()),
            links: Some(vec!["https://example.com".to_string()]),
            committed_topics: Some(vec![
                Some(TopicToFollow::NetworkEconomics),
                Some(TopicToFollow::Governance)
            ]),
        }
    );
}
