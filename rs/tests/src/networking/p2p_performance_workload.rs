use ic_system_test_driver::{
    canister_api::{CallMode, GenericRequest},
    driver::{
        farm::HostFeature,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{ProductionSubnetTopology, SimulateNetwork},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationBuilder, SubnetSnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    util::{agent_observes_canister_module, block_on, spawn_round_robin_workload_engine},
};

use anyhow::bail;
use ic_agent::Agent;
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info, Logger};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const CANISTER_METHOD: &str = "write";
// Duration of each request is placed into one of the two categories - below or above this threshold.
const APP_DURATION_THRESHOLD: Duration = Duration::from_secs(60);
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

const JAEGER_VM_NAME: &str = "jaeger-vm";

// 5 minutes
const DOWNLOAD_PROMETHEUS_WAIT_TIME: Duration = Duration::from_secs(60 * 60);

// Create an IC with two subnets, with variable number of nodes.
// Install NNS canister on system subnet.
pub fn config(
    env: TestEnv,
    nodes_nns_subnet: usize,
    nodes_app_subnet: usize,
    network_simulation: Option<ProductionSubnetTopology>,
    boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
) {
    let logger = env.logger();
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("failed to start prometheus VM");

    let path = get_dependency_path("rs/tests/jaeger_uvm_config_image.zst");

    UniversalVm::new(JAEGER_VM_NAME.to_string())
        .with_required_host_features(vec![HostFeature::Performance])
        .with_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(16)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        })
        .with_config_img(path)
        .start(&env)
        .expect("failed to setup Jaeger Universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(JAEGER_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let jaeger_ipv6 = universal_vm.ipv6;

    info!(
        logger,
        "Jaeger frontend available at: http://[{}]:16686", jaeger_ipv6
    );

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(16)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
        boot_image_minimal_size_gibibytes,
    };
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .with_jaeger_addr(SocketAddr::new(IpAddr::V6(jaeger_ipv6), 4317))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .add_nodes(nodes_nns_subnet),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .add_nodes(nodes_app_subnet),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    env.sync_with_prometheus();
    info!(logger, "Step 1: Installing NNS canisters ...");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }

    if let Some(network_simulation) = network_simulation {
        info!(&logger, "Setting simulated packet loss and RTT.");

        env.topology_snapshot()
            .subnets()
            .filter(|s| s.subnet_type() == SubnetType::Application)
            .for_each(|s| s.apply_network_settings(network_simulation.clone()));
    }
}

// Run a test with configurable number of update requests per second,
// size of the payload, duration of the test. The requests are sent
// to the replica.
pub fn test(
    env: TestEnv,
    rps: usize,
    payload_size_bytes: usize,
    duration: Duration,
    download_prometheus_data: bool,
) {
    let log = env.logger();
    info!(
        &log,
        "Checking readiness of all nodes after the IC setup ..."
    );
    let top_snapshot = env.topology_snapshot();
    top_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet ..."
    );
    let app_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let app_canister = app_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        &log,
        "Installation of counter canisters on both subnets has succeeded."
    );

    info!(&log, "Step 3: Instantiate and start workloads.");
    // Workload sends messages to canisters via node agents, so we create them.
    let app_agents = create_agents_for_subnet(&log, &app_subnet);
    info!(
        &log,
        "Asserting all agents observe the installed canister ..."
    );
    block_on(async {
        for agent in app_agents.iter() {
            ic_system_test_driver::retry_with_msg_async!(
                format!("observing canister module {}", app_canister.to_string()),
                &log,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(agent, &app_canister).await {
                        true => Ok(()),
                        false => bail!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();
        }
    });
    info!(&log, "All agents observe the installed canister module.");
    if rps == 0 {
        info!(&log, "Step 4: No workload will be started.");
        std::thread::sleep(duration);
    } else {
        info!(&log, "Step 5: Start workload.");
        // Spawn one workload per subnet against the counter canister.
        let payload: Vec<u8> = vec![0; payload_size_bytes];
        let handle_app_workload = {
            let requests = vec![GenericRequest::new(
                app_canister,
                CANISTER_METHOD.to_string(),
                payload.clone(),
                CallMode::UpdateNoPolling,
            )];
            spawn_round_robin_workload_engine(
                log.clone(),
                requests,
                app_agents,
                rps,
                duration,
                REQUESTS_DISPATCH_EXTRA_TIMEOUT,
                vec![APP_DURATION_THRESHOLD],
            )
        };

        let load_metrics_app = handle_app_workload
            .join()
            .expect("Workload execution against Application subnet failed.");
        info!(
            &log,
            "Step 6: Collect metrics from the workloads and perform assertions ..."
        );
        info!(&log, "App subnet metrics {load_metrics_app}");
        let requests_count_below_threshold_app =
            load_metrics_app.requests_count_below_threshold(APP_DURATION_THRESHOLD);
        info!(
            &log,
            "Application subnet: requests below {} sec: requests_count={:?}\nFailure calls: {}",
            APP_DURATION_THRESHOLD.as_secs(),
            requests_count_below_threshold_app,
            load_metrics_app.failure_calls(),
        );
    }

    // Download Prometheus data if required.
    if download_prometheus_data {
        info!(
            &log,
            "Waiting {:?} before download.", DOWNLOAD_PROMETHEUS_WAIT_TIME
        );
        std::thread::sleep(DOWNLOAD_PROMETHEUS_WAIT_TIME);
        info!(&log, "Downloading p8s data");
        env.download_prometheus_data_dir_if_exists();
    }
}

fn create_agents_for_subnet(log: &Logger, subnet: &SubnetSnapshot) -> Vec<Agent> {
    subnet
        .nodes()
        .map(|node| {
            debug!(
                &log,
                "Agent for the node with id={} from the {:?} subnet will be used for the workload.",
                node.node_id,
                subnet.subnet_type()
            );
            node.build_default_agent()
        })
        .collect::<_>()
}
