use dfn_candid::candid;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_ID, TEST_NEURON_2_OWNER_KEYPAIR,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    registry::get_value_or_panic,
};
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use maplit::btreemap;

#[test]
fn test_submit_update_node_rewards_table_proposal() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let new_entries = btreemap! {
            "CH".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 240,
                        reward_coefficient_percent: None,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 350,
                        reward_coefficient_percent: None,
                    },
                }
            }
        };

        let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            NnsFunction::UpdateNodeRewardsTable,
            payload.clone(),
            "<proposal created by test_submit_update_node_rewards_table_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Should have 1 pending proposals
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 1);

        // Cast votes.
        let input = (TEST_NEURON_1_ID, proposal_id, Vote::Yes);
        let _result: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "forward_vote",
                candid,
                input,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .expect("Vote failed");

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status,
            ProposalStatus::Executed as i32
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let table = get_value_or_panic::<NodeRewardsTable>(
            &nns_canisters.registry,
            NODE_REWARDS_TABLE_KEY.as_bytes(),
        )
        .await;

        assert_eq!(table.table.len(), 1);

        let ch = &table.table.get("CH").unwrap().rates;
        assert_eq!(
            ch.get("default").unwrap().xdr_permyriad_per_node_per_month,
            240
        );
        assert_eq!(
            ch.get("small").unwrap().xdr_permyriad_per_node_per_month,
            350
        );
        assert!(ch.get("storage_upgrade").is_none());

        Ok(())
    });
}
