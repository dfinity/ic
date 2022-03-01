use crate::node_provider_remuneration::add_node_provider;
use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_nns_constants::ids::{
    TEST_NEURON_1_OWNER_KEYPAIR, TEST_USER1_KEYPAIR, TEST_USER1_PRINCIPAL,
};
use ic_nns_governance::pb::v1::{GovernanceError, NodeProvider, UpdateNodeProvider};
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ledger_canister::AccountIdentifier;

#[test]
fn test_update_node_provider() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Define the set of node operators and node providers
        let node_provider_id_1 = *TEST_USER1_PRINCIPAL;
        let node_provider_1_account = AccountIdentifier::from(node_provider_id_1);
        let node_provider_1 = NodeProvider {
            id: Some(node_provider_id_1),
            reward_account: None,
        };

        // Add Node Providers
        add_node_provider(&nns_canisters, node_provider_1.clone()).await;

        // Check the node provider was added
        let get_node_provider_by_caller_result: Result<NodeProvider, GovernanceError> =
            nns_canisters
                .governance
                .query_from_sender(
                    "get_node_provider_by_caller",
                    candid_one,
                    (),
                    &Sender::from_keypair(&TEST_USER1_KEYPAIR),
                )
                .await
                .expect("Error calling get_node_provider_by_caller");

        assert_eq!(get_node_provider_by_caller_result.unwrap(), node_provider_1);

        let update = UpdateNodeProvider {
            reward_account: Some(node_provider_1_account.into()),
        };

        let update_node_provider_result: Result<(), GovernanceError> = nns_canisters
            .governance
            .update_from_sender(
                "update_node_provider",
                candid_one,
                update,
                &Sender::from_keypair(&TEST_USER1_KEYPAIR),
            )
            .await
            .expect("Error calling update_node_provider");

        assert!(update_node_provider_result.is_ok());

        // Check the node provider was updated
        let get_node_provider_by_caller_result: Result<NodeProvider, GovernanceError> =
            nns_canisters
                .governance
                .query_from_sender(
                    "get_node_provider_by_caller",
                    candid_one,
                    (),
                    &Sender::from_keypair(&TEST_USER1_KEYPAIR),
                )
                .await
                .expect("Error calling get_node_provider_by_caller");

        let expected_node_provider = NodeProvider {
            id: Some(node_provider_id_1),
            reward_account: Some(node_provider_1_account.into()),
        };

        assert_eq!(
            get_node_provider_by_caller_result.unwrap(),
            expected_node_provider
        );

        // Check that this NodeProvider record isn't returned to another user
        let get_node_provider_by_caller_result: Result<NodeProvider, GovernanceError> =
            nns_canisters
                .governance
                .query_from_sender(
                    "get_node_provider_by_caller",
                    candid_one,
                    (),
                    &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
                )
                .await
                .expect("Error calling get_node_provider_by_caller");

        assert!(get_node_provider_by_caller_result.is_err());

        Ok(())
    });
}
