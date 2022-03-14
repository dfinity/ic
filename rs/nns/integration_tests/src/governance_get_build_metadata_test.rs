//! Make sure the governance canister scales

use dfn_candid::candid;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance::pb::v1::{neuron::DissolveState, Neuron};
use ic_nns_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};

#[test]
fn get_build_metadata_test() {
    local_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        // Boot up the IC.
        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.with_test_neurons();
        let neuron_id_4 = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_4_subaccount = nns_builder.governance.make_subaccount().into();
        assert_eq!(
            nns_builder.governance.proto.neurons.insert(
                neuron_id_4.id,
                Neuron {
                    id: Some(neuron_id_4.clone()),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 123_000_000_000,
                    account: neuron_4_subaccount,
                    not_for_profit: true,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Request build metadata.
        let response: String = nns_canisters
            .governance
            .query_("get_build_metadata", candid, ())
            .await?;

        // Inspect the response.
        for phrase in [
            "profile: ",
            "optimization_level: ",
            "crate_name: ",
            "enabled_features: ",
            "compiler_version: ",
        ] {
            assert!(
                response.contains(phrase),
                "Failed to find {} in response:\n{}",
                phrase,
                response
            );
        }

        Ok(())
    });
}
