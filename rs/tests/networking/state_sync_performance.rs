/* tag::catalog[]

Title:: State Sync performance test

Runbook::
. setup a testnet with a single node
. install nns and state sync canisters
. grow the state of the subnet by expanding states of the state sync canisters
. add 12 additional nodes
. fetch state sync durations of joining nodes via metrics

end::catalog[] */

use anyhow::Result;
use canister_test::Canister;
use futures::future::join_all;
use ic_consensus_threshold_sig_system_test_utils::execute_proposal;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        farm::HostFeature,
        group::SystemTestGroup,
        ic::{ImageSizeGiB, InternetComputer, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{FixedNetworkSimulation, SimulateNetwork},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            SshSession,
        },
    },
    systest,
    util::{block_on, runtime_from_url},
};
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use rejoin_test_lib::{
    assert_state_sync_has_happened, install_statesync_test_canisters, modify_canister_heap,
};
use slog::info;
use std::time::Duration;

const INITIAL_NODES: usize = 1;
const TOTAL_NODES: usize = 13;

const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(150); // artificial added latency

const SIZE_LEVEL: usize = 1;
const NUM_CANISTERS: usize = 4;

pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM: &str =
    "state_sync_duration_seconds_sum{status=\"ok\"}";
pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT: &str =
    "state_sync_duration_seconds_count{status=\"ok\"}";

fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .with_default_vm_resources(VmResources {
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(
                30 + 2 * NUM_CANISTERS as u64 * SIZE_LEVEL as u64,
            )),
            ..VmResources::default()
        })
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(99))
                .with_unit_delay(Duration::from_millis(200))
                .with_initial_notary_delay(Duration::from_millis(200))
                .add_nodes(INITIAL_NODES),
        )
        .with_unassigned_nodes(TOTAL_NODES - INITIAL_NODES)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let topology = env.topology_snapshot();

    for subnet in topology.subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Nodes failed to come up healthy")
        }
    }

    for node in topology.unassigned_nodes() {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be healthy");
    }

    topology.root_subnet().apply_network_settings(
        FixedNetworkSimulation::new()
            .with_latency(LATENCY)
            .with_bandwidth(BANDWIDTH_MBITS),
    );
    env.sync_with_prometheus();

    let nns_node = topology.root_subnet().nodes().next().unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Failed to install NNS canisters");
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

    let agent_node = topology
        .root_subnet()
        .nodes()
        .next()
        .expect("Failed to get agent node");

    block_on(async {
        info!(
            logger,
            "Installing universal canister on a node {} ...",
            agent_node.get_public_url()
        );

        let endpoint_runtime = runtime_from_url(
            agent_node.get_public_url(),
            agent_node.effective_canister_id(),
        );
        let canisters =
            install_statesync_test_canisters(&env, &endpoint_runtime, NUM_CANISTERS).await;

        info!(
            logger,
            "Start expanding the canister heap. The total size of all canisters will be {} MiB.",
            SIZE_LEVEL * NUM_CANISTERS * 128
        );
        modify_canister_heap(
            logger.clone(),
            canisters.clone(),
            SIZE_LEVEL,
            NUM_CANISTERS,
            false,
            0,
        )
        .await;

        info!(
            logger,
            "Expanded the subnet state size. Growing the subnet to {} nodes", TOTAL_NODES
        );

        let new_nodes = topology.unassigned_nodes().collect::<Vec<_>>();
        let add_nodes_payload = AddNodesToSubnetPayload {
            subnet_id: topology.root_subnet().subnet_id.get(),
            node_ids: topology
                .unassigned_nodes()
                .map(|subnet| subnet.node_id)
                .collect(),
        };

        execute_proposal(
            &governance,
            NnsFunction::AddNodeToSubnet,
            add_nodes_payload,
            &format!("Grow subnet to {} nodes", TOTAL_NODES),
            &logger,
        )
        .await;

        let topology = topology
            .block_for_newer_registry_version()
            .await
            .expect("Failed to wait for new topology version");
        env.sync_with_prometheus();

        // Wait for the new nodes to report healthy
        for subnet in topology.subnets() {
            for node in subnet.nodes() {
                node.await_status_is_healthy_async()
                    .await
                    .expect("Nodes failed to come up healthy")
            }
        }
        info!(logger, "All newly joined nodes report healthy");

        let state_syncs = new_nodes
            .into_iter()
            .map(|node| async { assert_state_sync_has_happened(&logger, node, 0).await })
            .collect::<Vec<_>>();
        let state_sync_durations = join_all(state_syncs).await;

        let min = state_sync_durations
            .iter()
            .fold(f64::MAX, |acc, val| f64::min(acc, *val));
        let max = state_sync_durations
            .iter()
            .fold(f64::MIN, |acc, val| f64::max(acc, *val));
        let avg = state_sync_durations.iter().sum::<f64>() / (state_sync_durations.len() as f64);
        info!(
            logger,
            "State sync durations: min: {}, avg: {}, max: {}", min, avg, max
        );
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
