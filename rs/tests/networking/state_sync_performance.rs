/* tag::catalog[]

Title:: State Sync performance test

Runbook::
. setup a testnet with a single node
. install nns and state sync canisters
. grow the state of the subnet by expanding states of the state sync canisters

TODO: Document the test
end::catalog[] */

use anyhow::Result;
use canister_test::Canister;
use ic_consensus_threshold_sig_system_test_utils::{
    empty_subnet_update, execute_update_subnet_proposal,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{ImageSizeGiB, InternetComputer, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{FixedNetworkSimulation, SimulateNetwork},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    systest,
    util::{block_on, runtime_from_url, UniversalCanister},
};
use ic_types::Height;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use rejoin_test_lib::{install_statesync_test_canisters, modify_canister_heap};
use slog::info;
use std::time::Duration;

const INITIAL_NODES: usize = 1;
const TOTAL_NODES: usize = 13;

const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(150); // artificial added latency

const SIZE_LEVEL: usize = 16;
const NUM_CANISTERS: usize = 8;

const LATEST_CERTIFIED_HEIGHT: &str = "state_manager_latest_certified_height";

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
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(99))
                .with_unit_delay(Duration::from_millis(100))
                .with_initial_notary_delay(Duration::from_millis(100))
                .add_nodes(INITIAL_NODES),
        )
        .with_unassigned_nodes(TOTAL_NODES - INITIAL_NODES)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let topology = env.topology_snapshot();
    topology.subnets().for_each(|subnet| {
        subnet.nodes().for_each(|node| {
            node.await_status_is_healthy()
                .expect("Nodes failed to come up healty")
        })
    });

    topology.unassigned_nodes().for_each(|node| {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be healthy");
    });

    topology.root_subnet().apply_network_settings(
        FixedNetworkSimulation::new()
            .with_latency(LATENCY)
            .with_bandwidth(BANDWIDTH_MBITS),
    );
    env.sync_with_prometheus();

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
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
        let agent = agent_node.build_default_agent_async().await;
        let universal_canister = UniversalCanister::new_with_retries(
            &agent,
            agent_node.effective_canister_id(),
            &logger,
        )
        .await;

        let endpoint_runtime = runtime_from_url(
            agent_node.get_public_url(),
            agent_node.effective_canister_id(),
        );
        let canisters =
            install_statesync_test_canisters(env, &endpoint_runtime, NUM_CANISTERS).await;

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

        let disable_signing_payload = UpdateSubnetPayload {
            subnet_id: topology.root_subnet().subnet_id,
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(
            &governance,
            disable_signing_payload,
            &format!("Grow subnet to {} nodes", TOTAL_NODES),
            &logger,
        )
        .await;

        let res =
            fetch_metrics::<u64>(&logger, agent_node.clone(), vec![LATEST_CERTIFIED_HEIGHT]).await;
        let latest_certified_height = res[LATEST_CERTIFIED_HEIGHT][0];
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
