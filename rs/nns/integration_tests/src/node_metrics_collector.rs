use candid::{Decode, Encode, Principal};
use ic_cdk::api::management_canister::main::CanisterId;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_nns_canisters;
use ic_nns_init::read_initial_registry_mutations;
use ic_nns_test_utils::common::build_mainnet_metrics_collector_wasm;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use itertools::Itertools;
use pocket_ic::common::rest::{BlockmakerConfigs, RawSubnetBlockmaker, TickConfigs};
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;

const DAY_HOURS: u64 = 24;
const SEVEN_DAYS: u64 = 7;

/// Advances PocketIC time by the given number of hours, simulating one block per hour.
async fn advance_pocket_ic_time(pocket_ic: &PocketIc, hours: u64, tick_configs: &TickConfigs) {
    for _ in 0..hours {
        pocket_ic.advance_time(Duration::from_secs(3600)).await;
        pocket_ic.tick_with_configs(tick_configs.clone()).await;
    }
}

/// Queries node metrics from the specified canister.
async fn query_node_metrics(
    pocket_ic: &PocketIc,
    canister_id: CanisterId,
    subnet_id: Principal,
    start_at_timestamp_nanos: u64,
) -> Vec<NodeMetricsHistoryResponse> {
    let response = pocket_ic
        .query_call(
            canister_id,
            Principal::anonymous(),
            "node_metrics_history",
            Encode!(&NodeMetricsHistoryArgs {
                subnet_id: subnet_id.into(),
                start_at_timestamp_nanos,
            })
            .unwrap(),
        )
        .await
        .expect("Failed to query node metrics");

    Decode!(&response, Vec<NodeMetricsHistoryResponse>)
        .expect("Failed to decode node metrics response")
}

#[tokio::test]
async fn test_node_metrics_collector() {
    let state_dir = TempDir::new().expect("Failed to create temp directory");
    let state_dir_path = state_dir.path().to_path_buf();
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path.clone())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Initialize PocketIC with subnets and registry records
    let registry_proto_path = state_dir_path.join("registry.proto");
    let initial_mutations = read_initial_registry_mutations(registry_proto_path);
    let mutate_request = RegistryAtomicMutateRequest {
        mutations: initial_mutations,
        ..Default::default()
    };
    install_nns_canisters(
        &pocket_ic,
        vec![],
        false,
        Some(vec![mutate_request]),
        vec![],
    )
    .await;

    let topology = pocket_ic.topology().await;
    let application_subnet = topology.get_app_subnets()[0];
    let nns_subnet = topology.get_nns().unwrap();
    let sns_subnet = topology.get_sns().unwrap();

    // Assign blockmakers per subnet
    let mut blockmakers_per_subnet = BTreeMap::new();
    for subnet in [nns_subnet, sns_subnet, application_subnet] {
        let blockmaker_node = topology.subnet_configs.get(&subnet).unwrap().node_ids[0].clone();
        blockmakers_per_subnet.insert(
            subnet,
            RawSubnetBlockmaker {
                subnet: subnet.into(),
                blockmaker: blockmaker_node,
                failed_blockmakers: vec![],
            },
        );
    }

    let tick_configs = TickConfigs {
        blockmakers: Some(BlockmakerConfigs {
            blockmakers_per_subnet: blockmakers_per_subnet.values().cloned().collect_vec(),
        }),
    };

    // Simulate block production for 70 days (Mainnet stores 60 days of metrics)
    advance_pocket_ic_time(&pocket_ic, DAY_HOURS * 70, &tick_configs).await;

    // Deploy and initialize the node_metrics_collector canister on the NNS subnet
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

    // Trigger metric backfilling by calling tick multiple times
    for _ in 0..3 {
        pocket_ic.tick().await;
    }

    // Query and validate node metrics
    for subnet in [nns_subnet, sns_subnet, application_subnet] {
        let from_system_time =
            pocket_ic.get_time().await - Duration::from_secs(60 * 60 * 24 * SEVEN_DAYS);
        let node_metrics = query_node_metrics(
            &pocket_ic,
            canister_id,
            subnet,
            from_system_time
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        )
        .await;

        assert_eq!(
            node_metrics.len(),
            SEVEN_DAYS as usize,
            "Unexpected number of metric entries"
        );

        let expected_blockmaker = Principal::from(
            blockmakers_per_subnet
                .get(&subnet)
                .unwrap()
                .blockmaker
                .clone(),
        );

        for daily_metrics in node_metrics {
            let mut previous_num_blocks = daily_metrics.node_metrics[0].num_blocks_proposed_total;

            for metrics in &daily_metrics.node_metrics[1..] {
                assert_eq!(
                    metrics.num_blocks_proposed_total,
                    previous_num_blocks + 24,
                    "num_blocks_proposed_total does not increase by 24 as expected"
                );
                previous_num_blocks = metrics.num_blocks_proposed_total;
            }

            assert_eq!(daily_metrics.node_metrics.len(), 1);
            assert_eq!(
                Principal::from(daily_metrics.node_metrics[0].node_id),
                expected_blockmaker
            );
        }
    }
}
