use dfn_candid::candid;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_nns_common::{
    registry::encode_or_panic,
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR};
use ic_nns_governance::pb::v1::{ManageNeuronResponse, NnsFunction, ProposalStatus, Vote};
use ic_nns_test_utils::{
    governance::{get_pending_proposals, submit_external_update_proposal, wait_for_final_state},
    ids::{TEST_NEURON_1_ID, TEST_NEURON_2_ID},
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
    registry::get_value,
};
use ic_protobuf::registry::provisional_whitelist::v1::ProvisionalWhitelist;
use ic_registry_keys::make_provisional_whitelist_record_key;
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use std::str::FromStr;

#[test]
fn test_submit_and_accept_clear_provisional_whitelist_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let principal_id = PrincipalId::from_str(
            "5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae",
        )
        .unwrap();
        let key = make_provisional_whitelist_record_key();
        let initial_provisional_whitelist = ProvisionalWhitelist {
            list_type: 2,
            set: vec![principal_id.into()],
        };

        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                mutations: vec![insert(
                    key.as_bytes().to_vec(),
                    encode_or_panic(&initial_provisional_whitelist),
                )],
                preconditions: vec![],
            }])
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let provisional_whitelist_after_setup: ProvisionalWhitelist =
            get_value(&nns_canisters.registry, key.as_bytes()).await;

        assert_eq!(
            provisional_whitelist_after_setup,
            initial_provisional_whitelist
        );

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            NnsFunction::ClearProvisionalWhitelist,
            (),
            "<proposal created by test_submit_and_accept_clear_provisional_whitelist_proposal>"
                .to_string(),
            "".to_string(),
        )
        .await;

        // Should have 1 pending proposal.
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
                .status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let provisional_whitelist_after_update: ProvisionalWhitelist =
            get_value(&nns_canisters.registry, key.as_bytes()).await;

        assert_eq!(
            provisional_whitelist_after_update,
            ProvisionalWhitelist {
                list_type: 2,
                set: vec![],
            }
        );
        Ok(())
    });
}
