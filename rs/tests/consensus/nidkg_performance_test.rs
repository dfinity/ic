use anyhow::Result;
use ic_system_test_driver::driver::ic::VmResourceOverrides;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use futures::future::join_all;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet},
    simulate_network::{FixedNetworkSimulation, SimulateNetwork},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder, SshSession},
};
use ic_system_test_driver::nns::{
    await_proposal_execution, get_software_version_from_snapshot,
    submit_create_application_subnet_proposal,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, runtime_from_url};
use registry_canister::mutations::do_create_subnet::CanisterCyclesCostSchedule;
use slog::info;

const NNS_NODES_COUNT: usize = 40;
const NEW_SUBNETS_COUNT: usize = 10;
const NODES_PER_NEW_SUBNET: usize = 4;
const UNASSIGNED_NODES_COUNT: usize = NEW_SUBNETS_COUNT * NODES_PER_NEW_SUBNET;

const NNS_DKG_DEALINGS_PER_BLOCK: usize = 10;

const APPLY_NETWORK_SIMULATION: bool = true;
const BANDWIDTH_MBITS: u32 = 300;
const LATENCY: Duration = Duration::from_millis(120);

fn setup(env: TestEnv) {
    let vm_resources = VmResourceOverrides {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    info!(
        env.logger(),
        "Deploying NiDKG performance testnet with {} system-subnet nodes, {} unassigned nodes, and {} DKG dealings/block",
        NNS_NODES_COUNT,
        UNASSIGNED_NODES_COUNT,
        NNS_DKG_DEALINGS_PER_BLOCK
    );

    let mut nns_subnet = Subnet::new(SubnetType::System)
        .with_required_host_features(vec![HostFeature::Performance])
        .with_resource_overrides(vm_resources)
        .add_nodes(NNS_NODES_COUNT);
    nns_subnet.dkg_dealings_per_block = Some(NNS_DKG_DEALINGS_PER_BLOCK);

    InternetComputer::new()
        .add_subnet(nns_subnet)
        .with_unassigned_nodes(UNASSIGNED_NODES_COUNT)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    let topology_snapshot = env.topology_snapshot();
    topology_snapshot
        .subnets()
        .flat_map(|subnet| subnet.nodes())
        .for_each(|node| node.await_status_is_healthy().unwrap());
    topology_snapshot
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();
    let initial_subnet_ids: HashSet<_> = topology_snapshot.subnets().map(|s| s.subnet_id).collect();
    let nns_node = topology_snapshot.root_subnet().nodes().next().unwrap();

    let unassigned_node_ids = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id)
        .collect::<Vec<_>>();
    assert_eq!(unassigned_node_ids.len(), UNASSIGNED_NODES_COUNT);

    info!(log, "Installing NNS canisters");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = ic_system_test_driver::nns::get_governance_canister(&nns_runtime);
    let version = block_on(get_software_version_from_snapshot(&nns_node))
        .expect("Could not obtain replica software version from the NNS node");

    if APPLY_NETWORK_SIMULATION {
        let network_simulation = FixedNetworkSimulation::new()
            .with_latency(LATENCY)
            .with_bandwidth(BANDWIDTH_MBITS);
        info!(
            log,
            "Applying network simulation to NNS subnet: {} Mbit/s, {:?} latency",
            BANDWIDTH_MBITS,
            LATENCY
        );
        topology_snapshot
            .root_subnet()
            .apply_network_settings(network_simulation);
    } else {
        info!(log, "Network simulation disabled");
    }

    info!(
        log,
        "Starting create-subnet proposals with {} nodes per subnet from {} unassigned nodes",
        NODES_PER_NEW_SUBNET,
        unassigned_node_ids.len()
    );
    let node_groups = unassigned_node_ids
        .chunks(NODES_PER_NEW_SUBNET)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    assert_eq!(node_groups.len(), NEW_SUBNETS_COUNT);
    info!(
        log,
        "Submitting and awaiting {} proposals in parallel", NEW_SUBNETS_COUNT
    );

    let execution_results = block_on(async {
        join_all(node_groups.into_iter().enumerate().map(|(idx, node_ids)| {
            let governance = governance.clone();
            let log = log.clone();
            let version = version.clone();
            async move {
                info!(
                    log,
                    "Submitting create-subnet proposal {}/{} for nodes {:?}",
                    idx + 1,
                    NEW_SUBNETS_COUNT,
                    node_ids
                );
                let proposal_id = submit_create_application_subnet_proposal(
                    &governance,
                    node_ids,
                    version,
                    Some(CanisterCyclesCostSchedule::Normal),
                )
                .await;
                let start = Instant::now();
                let is_executed = await_proposal_execution(
                    &log,
                    &governance,
                    proposal_id,
                    Duration::from_secs(1),
                    Duration::from_secs(10 * 60),
                )
                .await;
                assert!(
                    is_executed,
                    "proposal {proposal_id} did not execute in time"
                );
                (proposal_id, start.elapsed())
            }
        }))
        .await
    });

    let count = execution_results.len();
    let mut min_secs = f64::INFINITY;
    let mut max_secs = 0.0_f64;
    let mut sum_secs = 0.0_f64;
    for (proposal_id, elapsed) in execution_results {
        let secs = elapsed.as_secs_f64();
        min_secs = min_secs.min(secs);
        max_secs = max_secs.max(secs);
        sum_secs += secs;
        info!(
            log,
            "Proposal {proposal_id} executed {:.2}s after submission", secs
        );
    }
    let avg_secs = sum_secs / count as f64;

    info!(
        log,
        "Execution latency after submission for {} proposals: min {:.2}s, avg {:.2}s, max {:.2}s",
        count,
        min_secs,
        avg_secs,
        max_secs
    );
    env.emit_report(format!(
        "NiDKG performance (submit->execute): proposals={} min={:.2}s avg={:.2}s max={:.2}s",
        count, min_secs, avg_secs, max_secs
    ));

    let expected_total_subnets = initial_subnet_ids.len() + count;
    info!(
        log,
        "Waiting for topology to show {} total subnets", expected_total_subnets
    );
    let mut refreshed_snapshot = topology_snapshot;
    while refreshed_snapshot.subnets().count() < expected_total_subnets {
        refreshed_snapshot = block_on(refreshed_snapshot.block_for_newer_registry_version())
            .expect("Failed to fetch updated topology snapshot");
    }

    let newly_created_subnets = refreshed_snapshot
        .subnets()
        .filter(|subnet| !initial_subnet_ids.contains(&subnet.subnet_id))
        .collect::<Vec<_>>();
    assert_eq!(newly_created_subnets.len(), count);

    info!(
        log,
        "Asserting health for all {} newly created subnets",
        newly_created_subnets.len()
    );
    for subnet in newly_created_subnets {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap());
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(Duration::from_secs(15 * 60))
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
