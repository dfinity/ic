use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_governance::pb::v1::NodeProvider;
use ic_nns_test_utils::governance::{add_node_provider, list_node_providers};
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};

#[test]
fn test_list_node_providers() {
    local_test_on_nns_subnet(|runtime| async move {
        // given nns canisters with test neurons
        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.with_test_neurons();
        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // when we start with no node providers
        let response = list_node_providers(&nns_canisters.governance).await;
        assert_eq!(response.node_providers.len(), 0);

        // and add a node provider
        let node_provider_1 = NodeProvider {
            id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            reward_account: None,
        };
        add_node_provider(&nns_canisters, node_provider_1.clone()).await;

        // then count goes up 1
        let response = list_node_providers(&nns_canisters.governance).await;
        assert_eq!(response.node_providers.len(), 1);
        assert_eq!(response.node_providers[0], node_provider_1);
        // when we do that again
        let node_provider_2 = NodeProvider {
            id: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
            reward_account: None,
        };
        add_node_provider(&nns_canisters, node_provider_2.clone()).await;

        // then count goes up to 2
        let response = list_node_providers(&nns_canisters.governance).await;
        assert_eq!(response.node_providers.len(), 2);
        assert_eq!(response.node_providers[0], node_provider_1);
        assert_eq!(response.node_providers[1], node_provider_2);

        Ok(())
    });
}
