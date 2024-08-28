use dfn_candid::{candid, candid_one};
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_3_ID,
};
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_governance_api::pb::v1::{
    manage_neuron::NeuronIdOrSubaccount, manage_neuron_response::Command as CommandResponse,
    GovernanceError, KnownNeuron, KnownNeuronData, ListKnownNeuronsResponse, MakeProposalRequest,
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, NeuronInfo,
    ProposalActionRequest, ProposalStatus,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::wait_for_final_state,
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
};

/// Integration test for the known neuron functionality.
///
/// The test does the following:
/// - Start with 3 neurons, none of them "known".
/// - Register a name for two of them.
/// - Assert than when querying the known neurons by id the result is the
///   expected one.
/// - Assert than when querying all known neurons the result is the expected
///   one.
#[test]
fn test_known_neurons() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();

        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Submit two proposal to register a name for a neuron, and then wait until both
        // are executed. Proposals are submitted by neuron 1, because it has
        // enough stake to have them accepted immediately.
        let result_1: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_1_ID,
                        },
                    )),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Naming neuron 2.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::RegisterKnownNeuron(KnownNeuron {
                                id: Some(NeuronId {
                                    id: TEST_NEURON_2_ID,
                                }),
                                known_neuron_data: Some(KnownNeuronData {
                                    name: "NeuronTwo".to_string(),
                                    description: None,
                                }),
                            })),
                        },
                    ))),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");
        let result_2: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        ic_nns_common::pb::v1::NeuronId {
                            id: TEST_NEURON_1_ID,
                        },
                    )),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Naming neuron 3.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::RegisterKnownNeuron(KnownNeuron {
                                id: Some(NeuronId {
                                    id: TEST_NEURON_3_ID,
                                }),
                                known_neuron_data: Some(KnownNeuronData {
                                    name: "NeuronThree".to_string(),
                                    description: None,
                                }),
                            })),
                        },
                    ))),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid_1 = match result_1
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            some_error => {
                panic!(
                    "Cannot find proposal id in response. The response is: {:?}",
                    some_error
                )
            }
        };
        let pid_2 = match result_2
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            some_error => {
                panic!(
                    "Cannot find proposal id in response. The response is: {:?}",
                    some_error
                )
            }
        };

        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid_1))
                .await
                .status(),
            ProposalStatus::Executed
        );
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, ProposalId::from(pid_2))
                .await
                .status(),
            ProposalStatus::Executed
        );

        // Check that neuron 2 has the correct name
        let ni: Result<NeuronInfo, GovernanceError> = nns_canisters
            .governance
            .query_("get_neuron_info", candid, (TEST_NEURON_2_ID,))
            .await
            .expect("Error calling the neuron_info api.");
        assert_eq!(
            "NeuronTwo",
            ni.as_ref()
                .unwrap()
                .known_neuron_data
                .as_ref()
                .unwrap()
                .name
        );

        let expected_known_neurons = vec![
            KnownNeuron {
                id: Some(NeuronId {
                    id: TEST_NEURON_2_ID,
                }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "NeuronTwo".to_string(),
                    description: None,
                }),
            },
            KnownNeuron {
                id: Some(NeuronId {
                    id: TEST_NEURON_3_ID,
                }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "NeuronThree".to_string(),
                    description: None,
                }),
            },
        ];
        let list_known_neurons_response: ListKnownNeuronsResponse = nns_canisters
            .governance
            .query_("list_known_neurons", candid, ())
            .await
            .expect("Error calling list known neurons api.");
        let mut sorted_response_known_neurons = list_known_neurons_response.known_neurons;
        sorted_response_known_neurons
            .sort_by(|a, b| a.id.as_ref().unwrap().id.cmp(&b.id.as_ref().unwrap().id));
        assert_eq!(sorted_response_known_neurons, expected_known_neurons);

        Ok(())
    });
}
