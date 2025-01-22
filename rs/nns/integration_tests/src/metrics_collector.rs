use candid::Principal;
use ic_base_types::CanisterId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    install_nns_canisters, STARTING_CYCLES_PER_CANISTER,
};
use ic_nns_test_utils::common::build_mainnet_metrics_collector_wasm;
use pocket_ic::PocketIcBuilder;

#[tokio::test]
async fn test_node_metrics_collector() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    // Step 0: Install the (master) NNS canisters.
    install_nns_canisters(&pocket_ic, vec![], true, None, vec![]).await;

    // Step 3: Deploy the node-metrics-collector canister
    let metrics_collector_wasm = build_mainnet_metrics_collector_wasm();
    let metrics_collector_id = Principal::from(CanisterId::from_u64(20));
    let canister_id = pocket_ic
        .create_canister_with_id(None, None, metrics_collector_id)
        .await
        .expect("Unable to create the canister in which the Ledger would be installed");
    pocket_ic
        .install_canister(
            canister_id,
            metrics_collector_wasm.bytes().to_vec(),
            vec![],
            None,
        )
        .await;

    pocket_ic
        .add_cycles(metrics_collector_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    // Give the governance canister some time to initialize so that we do not hit the
    // following error:
    // Could not claim neuron: Unavailable: Neuron ID generation is not available
    // currently. Likely due to uninitialized RNG.
    pocket_ic
        .advance_time(std::time::Duration::from_secs(90000))
        .await;
    pocket_ic.tick().await;

    pocket_ic
        .query_call(
            metrics_collector_id,
            Principal::anonymous(),
            "node_metrics_history",
            vec![],
        )
        .await
        .unwrap();
}
