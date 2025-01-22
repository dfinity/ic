use candid::{Encode, Principal};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_management_canister_types::NodeMetricsHistoryArgs;
use ic_nervous_system_integration_tests::pocket_ic_helpers::STARTING_CYCLES_PER_CANISTER;
use ic_nns_test_utils::common::build_mainnet_metrics_collector_wasm;
use pocket_ic::PocketIcBuilder;
use std::str::FromStr;

#[tokio::test]
async fn test_node_metrics_collector() {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_fiduciary_subnet()
        .build_async()
        .await;

    // Step 0: Install the (master) NNS canisters.

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

    let _ = pocket_ic
        .query_call(
            metrics_collector_id,
            Principal::anonymous(),
            "node_metrics_history",
            Encode!(&NodeMetricsHistoryArgs {
                subnet_id: PrincipalId::from_str(
                    "ewlco-wjy6h-oafn4-sjmhf-litbm-aout5-atu3t-ygdsc-mqpmz-vpx73-sae"
                )
                .unwrap(),
                start_at_timestamp_nanos: 0
            })
            .unwrap(),
        )
        .await;
}
