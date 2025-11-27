use dfn_candid::{candid, candid_one};
use ic_canister_client_sender::Sender;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, Neuron, NodeProvider, ProposalActionRequest, ProposalInfo, Vote,
    add_or_remove_node_provider::Change,
    manage_neuron::{self, NeuronIdOrSubaccount},
    manage_neuron_response::Command as CommandResponse,
    neuron::DissolveState,
    test_api::TimeWarp,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
};
use std::time::SystemTime;

#[test]
fn test_deadline_is_extended_with_wait_for_quiet() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let now_timestamp_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();

        nns_init_payload_builder.with_initial_invariant_compliant_mutations();
        nns_init_payload_builder.with_test_neurons();

        // WFQ deadline extensions require the majority of cast votes to switch from
        // for yes->no or no->yes, all without a majority of voting power deciding the
        // entire proposal. To achieve this configuration in this given test, in addition
        // to the test_neurons, add a fourth neuron with enough stake to flip the vote,
        // but not decide the proposal.
        let neuron_id_4 = NeuronId::from(nns_init_payload_builder.governance.new_neuron_id());
        let neuron_4_subaccount = nns_init_payload_builder.governance.make_subaccount().into();
        let neuron_4_owner_keypair = &TEST_NEURON_1_OWNER_KEYPAIR;
        let neuron_4_owner_principal_id = *TEST_NEURON_1_OWNER_PRINCIPAL;
        nns_init_payload_builder.governance.proto.neurons.insert(
            neuron_id_4.id,
            Neuron {
                id: Some(neuron_id_4),
                account: neuron_4_subaccount,
                controller: Some(neuron_4_owner_principal_id),
                cached_neuron_stake_e8s: 200_000_000,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_DAY_SECONDS * 365)),
                voting_power_refreshed_timestamp_seconds: Some(now_timestamp_seconds),
                ..Default::default()
            },
        );

        let nns_init_payload = nns_init_payload_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Submit a proposal to add a node provider, but submit with a neuron that
        // doesn't have majority voting power.
        let result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: TEST_NEURON_2_ID,
                    })),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(
                        MakeProposalRequest {
                            title: Some("Just want to add this NP.".to_string()),
                            summary: "".to_string(),
                            url: "".to_string(),
                            action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(
                                AddOrRemoveNodeProvider {
                                    change: Some(Change::ToAdd(NodeProvider {
                                        id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                                        reward_account: None,
                                    })),
                                },
                            )),
                        },
                    ))),
                },
                &Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let pid = match result
            .panic_if_error("Error making proposal")
            .command
            .unwrap()
        {
            CommandResponse::MakeProposal(resp) => resp.proposal_id.unwrap(),
            some_error => {
                panic!("Cannot find proposal id in response. The response is: {some_error:?}")
            }
        };

        let pi: Option<ProposalInfo> = nns_canisters
            .governance
            .query_("get_proposal_info", candid, (pid.id,))
            .await
            .unwrap();

        let initial_deadline = pi.unwrap().deadline_timestamp_seconds.unwrap();

        // Set the TimeWarp one day in the future so a change to the WFQ deadline has a measurable
        // effect
        let delta_s = ONE_DAY_SECONDS as i64;
        () = nns_canisters
            .governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await?;

        // Now vote against the proposal, the deadline should be extended.
        let _result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id_4)),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::RegisterVote(
                        manage_neuron::RegisterVote {
                            proposal: Some(pid),
                            vote: Vote::No as i32,
                        },
                    )),
                },
                &Sender::from_keypair(neuron_4_owner_keypair),
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let final_proposal_info: Option<ProposalInfo> = nns_canisters
            .governance
            .query_("get_proposal_info", candid, (pid.id,))
            .await
            .unwrap();

        let final_deadline = final_proposal_info
            .as_ref()
            .unwrap()
            .deadline_timestamp_seconds
            .unwrap();

        assert!(
            final_deadline > initial_deadline,
            "{initial_deadline:?}\n{final_proposal_info:#?}",
        );

        Ok(())
    });
}
