use anyhow::Result;
use std::time::{Duration, Instant};

use futures::future::join_all;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::HasPrometheus,
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder, SshSession},
};
use ic_system_test_driver::nns::{
    await_proposal_execution, get_software_version_from_snapshot,
    submit_create_application_subnet_proposal, vote_on_proposal,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, runtime_from_url};
use registry_canister::mutations::do_create_subnet::CanisterCyclesCostSchedule;
use slog::info;

const NNS_NODES_COUNT: usize = 40;
const DEFAULT_UNASSIGNED_NODES_COUNT: usize = 10;
const DEFAULT_NNS_DKG_DEALINGS_PER_BLOCK: usize = 10;

fn setup(env: TestEnv) {
    let unassigned_nodes_count = std::env::var("UNASSIGNED_NODES_COUNT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_UNASSIGNED_NODES_COUNT);
    let nns_dkg_dealings_per_block = std::env::var("NNS_DKG_DEALINGS_PER_BLOCK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_NNS_DKG_DEALINGS_PER_BLOCK);

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    info!(
        env.logger(),
        "Deploying nIDKG performance testnet with {} system-subnet nodes, {} unassigned nodes, and {} DKG dealings/block",
        NNS_NODES_COUNT,
        unassigned_nodes_count,
        nns_dkg_dealings_per_block
    );

    let mut nns_subnet = Subnet::new(SubnetType::System)
        .with_required_host_features(vec![HostFeature::Performance])
        .with_default_vm_resources(vm_resources)
        .add_nodes(NNS_NODES_COUNT);
    nns_subnet.dkg_dealings_per_block = Some(nns_dkg_dealings_per_block);

    InternetComputer::new()
        .add_subnet(nns_subnet)
        .with_unassigned_nodes(unassigned_nodes_count)
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
    let nns_node = topology_snapshot.root_subnet().nodes().next().unwrap();

    let unassigned_node_ids = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id)
        .collect::<Vec<_>>();
    assert!(
        !unassigned_node_ids.is_empty(),
        "Expected at least one unassigned node to create single-node subnets"
    );

    info!(log, "Installing NNS canisters");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = ic_system_test_driver::nns::get_governance_canister(&nns_runtime);
    let version = block_on(get_software_version_from_snapshot(&nns_node))
        .expect("Could not obtain replica software version from the NNS node");

    info!(
        log,
        "Starting {} create-subnet proposals (one unassigned node per subnet)",
        unassigned_node_ids.len()
    );
    let submit_start = Instant::now();
    let mut proposal_ids = Vec::with_capacity(unassigned_node_ids.len());
    for (idx, node_id) in unassigned_node_ids.iter().cloned().enumerate() {
        info!(
            log,
            "Submitting create-subnet proposal {}/{} for node {}",
            idx + 1,
            unassigned_node_ids.len(),
            node_id
        );
        let proposal_id = block_on(submit_create_application_subnet_proposal(
            &governance,
            vec![node_id],
            version.clone(),
            Some(CanisterCyclesCostSchedule::Normal),
        ));
        proposal_ids.push(proposal_id);
    }
    let submit_elapsed = submit_start.elapsed();

    info!(
        log,
        "Submitted all {} proposals in {:.2}s; voting and awaiting execution in parallel",
        proposal_ids.len(),
        submit_elapsed.as_secs_f64()
    );
    let execution_results = block_on(async {
        join_all(proposal_ids.into_iter().map(|proposal_id| {
            let governance = governance.clone();
            let log = log.clone();
            async move {
                vote_on_proposal(&governance, proposal_id).await;
                let start = Instant::now();
                let is_executed = await_proposal_execution(
                    &log,
                    &governance,
                    proposal_id,
                    Duration::from_secs(1),
                    Duration::from_secs(2 * 60),
                )
                .await;
                assert!(is_executed, "proposal {proposal_id} did not execute in time");
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
        info!(log, "Proposal {proposal_id} executed {:.2}s after voting", secs);
    }
    let avg_secs = sum_secs / count as f64;

    info!(
        log,
        "Execution latency after voting for {} proposals: min {:.2}s, avg {:.2}s, max {:.2}s",
        count,
        min_secs,
        avg_secs,
        max_secs
    );
    env.emit_report(format!(
        "nIDKG performance (vote->execute): proposals={} min={:.2}s avg={:.2}s max={:.2}s",
        count,
        min_secs,
        avg_secs,
        max_secs
    ));
}

fn teardown(env: TestEnv) {
    let should_download_prometheus_data =
        std::env::var("DOWNLOAD_P8S_DATA").is_ok_and(|v| v == "true" || v == "1");
    if should_download_prometheus_data {
        env.download_prometheus_data_dir_if_exists();
        env.emit_report(String::from(
            "Downloaded prometheus data to 'prometheus-data-dir.tar.zst' in the test output \
            directory. You can now use `rs/tests/run-p8s.sh` script to play with the metrics",
        ));
    } else {
        env.emit_report(String::from(
            "Not downloading the prometheus data. \
            If you want to download it on the next test run, \
            please pass `--test_env DOWNLOAD_P8S_DATA=1` as an argument to the `ict` command",
        ));
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .with_timeout_per_test(Duration::from_secs(120 * 60))
        .add_test(systest!(test))
        .with_teardown(teardown)
        .execute_from_args()?;
    Ok(())
}
