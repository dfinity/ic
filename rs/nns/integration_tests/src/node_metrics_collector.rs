use candid::{Decode, Encode, Principal};
use ic_cdk::api::management_canister::main::CanisterId;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    install_nns_canisters, load_registry_mutations,
};
use ic_nns_test_utils::common::build_mainnet_metrics_collector_wasm;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use tempfile::TempDir;

const RUNTIME_DAYS: u64 = 3;
const DAY_HOURS: u64 = 24;
const BLOCK_INTERVAL_SECONDS: u64 = 60 * 60;

/// Advances the PocketIC state by a given number of days, producing one block per hour.
async fn advance_pocket_ic_time(pocket_ic: &PocketIc, days: u64) {
    for _ in 0..days {
        for _ in 0..DAY_HOURS {
            pocket_ic
                .advance_time(std::time::Duration::from_secs(BLOCK_INTERVAL_SECONDS))
                .await;
            pocket_ic.tick().await;
        }
    }
}

async fn query_node_metrics(
    pocket_ic: &PocketIc,
    canister_id: CanisterId,
    subnet_id: Principal,
) -> Vec<NodeMetricsHistoryResponse> {
    let response = pocket_ic
        .query_call(
            canister_id,
            Principal::anonymous(),
            "node_metrics_history",
            Encode!(&NodeMetricsHistoryArgs {
                subnet_id: subnet_id.into(),
                start_at_timestamp_nanos: 0,
            })
            .unwrap(),
        )
        .await
        .unwrap();

    Decode!(&response, Vec<NodeMetricsHistoryResponse>).unwrap()
}

#[tokio::test]
async fn test_node_metrics_collector() {
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Setup PocketIC with initial subnets and records
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let initial_mutations = load_registry_mutations(registry_proto_path);
    let mutate_request = RegistryAtomicMutateRequest {
        mutations: initial_mutations,
        ..Default::default()
    };
    let with_mainnet_nns_canisters = false;
    install_nns_canisters(
        &pocket_ic,
        vec![],
        with_mainnet_nns_canisters,
        Some(vec![mutate_request]),
        vec![],
    )
    .await;

    // Advance time for the initial runtime period
    advance_pocket_ic_time(&pocket_ic, RUNTIME_DAYS).await;

    // Install node_metrics_collector canister in the NNS subnet
    let nns_subnet = pocket_ic.topology().await.get_nns().unwrap();
    let canister_id = pocket_ic
        .create_canister_on_subnet(None, None, nns_subnet)
        .await;
    let metrics_collector_wasm = build_mainnet_metrics_collector_wasm();
    pocket_ic
        .install_canister(
            canister_id,
            metrics_collector_wasm.bytes().to_vec(),
            vec![],
            None,
        )
        .await;

    // Give some ticks for the node metrics collector to backfill past metrics
    pocket_ic.tick().await;
    pocket_ic.tick().await;
    pocket_ic.tick().await;

    // Validate metrics backfilled for the past RUNTIME_DAYS days
    let application_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let node_metrics = query_node_metrics(&pocket_ic, canister_id, application_subnet).await;

    assert_eq!(node_metrics.len(), RUNTIME_DAYS as usize);

    // Advance time for another RUNTIME_DAYS and validate again
    advance_pocket_ic_time(&pocket_ic, RUNTIME_DAYS).await;
    let node_metrics = query_node_metrics(&pocket_ic, canister_id, application_subnet).await;

    assert_eq!(node_metrics.len(), RUNTIME_DAYS as usize * 2);

    // Validate all blocks are recorded
    let blocks_proposed_day_0 = node_metrics[0].node_metrics[0].num_blocks_proposed_total;
    let blocks_proposed_day_1 = node_metrics[1].node_metrics[0].num_blocks_proposed_total;

    assert_eq!(blocks_proposed_day_1 - blocks_proposed_day_0, DAY_HOURS);
}
