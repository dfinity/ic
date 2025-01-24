use candid::{Decode, Encode, Principal};
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_nervous_system_integration_tests::pocket_ic_helpers::{install_nns_canisters, load_registry_mutations};
use ic_nns_test_utils::common::build_mainnet_metrics_collector_wasm;
use pocket_ic::PocketIcBuilder;
use tempfile::TempDir;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;

#[tokio::test]
async fn test_node_metrics_collector() {
    const DAY_HRS: u64 = 24;

    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Setup PocketIC with inital subnets and records
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
    install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, Some(vec![mutate_request]), vec![]).await;

    // Install node_metrics_collector canister in nns subnet
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

    for _ in 0..3 {
        for _ in 0..DAY_HRS{
            // Blocks production 1 block every hour
            pocket_ic
                .advance_time(std::time::Duration::from_secs(60 * 60))
                .await;
            pocket_ic.tick().await;
        }
    }

    let application_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let application_subnet_metrics = pocket_ic
        .query_call(
            canister_id,
            Principal::anonymous(),
            "node_metrics_history",
            Encode!(&NodeMetricsHistoryArgs {
                subnet_id: application_subnet.into(),
                start_at_timestamp_nanos: 0
            })
                .unwrap(),
        ).await.unwrap();

    let node_metrics  = Decode!(&application_subnet_metrics, Vec<NodeMetricsHistoryResponse>).unwrap();
    assert_eq!(node_metrics.len(), 3);

    let blocks_proposed_day_0 = node_metrics[0].node_metrics[0].num_blocks_proposed_total;
    let blocks_proposed_day_1 = node_metrics[1].node_metrics[0].num_blocks_proposed_total;

    // In one day 24 blocks are proposed
    assert_eq!(blocks_proposed_day_1 - blocks_proposed_day_0, 24);
}
