use dfn_candid::candid_one;
use ic_nns_governance::pb::v1::NetworkEconomics;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};

#[test]
fn test_get_network_economics() {
    local_test_on_nns_subnet(|runtime| async move {
        let network_economics = NetworkEconomics {
            neuron_minimum_stake_e8s: 100 * 100_000_000,
            ..Default::default()
        };

        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.governance.proto.economics = Some(network_economics.clone());

        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let fetched_network_economics: NetworkEconomics = nns_canisters
            .governance
            .query_("get_network_economics_parameters", candid_one, ())
            .await
            .expect("Error calling get_network_economics_parameters");

        assert_eq!(network_economics, fetched_network_economics);
        Ok(())
    });
}
