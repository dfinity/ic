//! System test that sets up a 13 node APP subnet to benchmark the subnet
//! when execution rounds are pushed to 2B instructions on average
//! (roughly ~1 sec round duration on average)
//!
//! The execution rounds are filled by installing universal canisters that
//! each concurrently call `stable_fill()` with `NUMBER_OF_BYTES_TO_WRITE` bytes.
//!
//! To run the benchmark, run the following command in the dev environment:
//! ict test //rs/tests/execution:fill_execution_rounds_workload -k -- --test_tmpdir=test_tmpdir --test_timeout=60000

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use ic_registry_routing_table::CanisterIdRanges;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        farm::HostFeature,
        group::SystemTestGroup,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{ProductionSubnetTopology, SimulateNetwork},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
            IcNodeContainer,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
    util::{block_on, UniversalCanister},
};
use ic_universal_canister::PayloadBuilder;
use slog::info;
use std::{
    cmp::max,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

// 40 minutes
const WORKLOAD_RUNTIME: Duration = Duration::from_secs(60 * 60);

/// Number of canisters that will be installed and executing the workload in parallel.
const CONCURRENT_REQUESTS: usize = 100;

/// 1 GiB
const NUMBER_OF_BYTES_TO_WRITE: u32 = 800 * 1024 * 1024;

/// Per page is 64KiB. Should support NUMBER_OF_BYTES_TO_WRITE + some padding.
const PAGES: u32 = ((NUMBER_OF_BYTES_TO_WRITE) / (64 * 1024) as u32) * 2;

/// Production value is 600ms
const TUNED_INITIAL_NOTARIZATION_DELAY: Duration = Duration::from_millis(600);

const DOWNLOAD_PROMETHEUS_DATA: bool = true;
// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);

/// Simulate RTT and Packet loss
const NETWORK_SIMULATION: ProductionSubnetTopology = ProductionSubnetTopology::IO67;
const SUBNET_SIZE: usize = 13;

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA;
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA;
    let config = |env| config(env, SUBNET_SIZE, TUNED_INITIAL_NOTARIZATION_DELAY);
    let test = |env| {
        fill_execution_rounds(
            env,
            WORKLOAD_RUNTIME,
            NUMBER_OF_BYTES_TO_WRITE,
            PAGES,
            CONCURRENT_REQUESTS,
            DOWNLOAD_PROMETHEUS_DATA,
        )
    };
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}

const JAEGER_VM_NAME: &str = "jaeger-vm";

const MAX_CANISTERS_INSTALLING_IN_PARALLEL: usize = 10;

pub fn config(env: TestEnv, subnet_size: usize, initial_notary_delay: Duration) {
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
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(1024)),
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
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .with_jaeger_addr(SocketAddr::new(IpAddr::V6(jaeger_ipv6), 4317))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .with_initial_notary_delay(initial_notary_delay)
                .add_nodes(subnet_size),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    env.sync_with_prometheus();

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");

    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }

    info!(&logger, "Setting simulated packet loss and RTT.");
    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();

    app_subnet.apply_network_settings(NETWORK_SIMULATION);
}

pub fn fill_execution_rounds(
    env: TestEnv,
    duration: Duration,
    data: u32,
    pages: u32,
    concurrent_requests: usize,
    download_prometheus_data: bool,
) {
    let log = env.logger();
    info!(
        &log,
        "Checking readiness of all nodes after the IC setup ..."
    );
    let node = env.get_first_healthy_application_node_snapshot();
    info!(&log, "Installing universal canister");

    let agent = node.build_default_agent();

    let mut universal_canisters = Vec::new();

    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is an application subnet");

    info!(&log, "Creating universal canisters");
    let mut futures = FuturesUnordered::new();

    let canister_id_ranges: CanisterIdRanges =
        TryFrom::try_from(subnet.subnet_canister_ranges()).expect("Is well formed");
    let mut canister_id = canister_id_ranges
        .start()
        .expect("Canister ID range is not empty");

    let mut currently_installing_canisters = 0;

    // Install 10 canisters at a time.
    for _ in 0..max(MAX_CANISTERS_INSTALLING_IN_PARALLEL, concurrent_requests) {
        futures.push(UniversalCanister::new_with_params_with_retries(
            &agent,
            canister_id.get(),
            None,
            None,
            Some(pages),
            &log,
        ));
        canister_id = canister_id_ranges
            .generate_canister_id(Some(canister_id))
            .expect("Canister ID can be generated");

        currently_installing_canisters += 1;
    }

    block_on(async {
        while let Some(universal_canister) = futures.next().await {
            universal_canisters.push(universal_canister);

            if currently_installing_canisters < concurrent_requests {
                futures.push(UniversalCanister::new_with_params_with_retries(
                    &agent,
                    canister_id.get(),
                    None,
                    None,
                    Some(pages),
                    &log,
                ));
                canister_id = canister_id_ranges
                    .generate_canister_id(Some(canister_id))
                    .expect("Canister ID can be generated");

                currently_installing_canisters += 1;
            }
        }
    });

    info!(
        &log,
        "Created {}/{} universal canisters",
        universal_canisters.len(),
        concurrent_requests
    );

    let mut futures = FuturesUnordered::new();

    info!(&log, "Generating futures");
    for universal_canister in universal_canisters {
        let log_clone = log.clone();
        futures.push(async move {
            let now = std::time::Instant::now();
            let mut bytes = 0;
            loop {
                if now.elapsed() > duration {
                    break;
                }

                info!(&log_clone, "Sending update request");
                let payload = PayloadBuilder::default()
                    .stable_fill(0, bytes, data)
                    .message_payload()
                    .append_and_reply()
                    .build();

                let result = universal_canister.update(payload).await;
                if let Err(err) = result {
                    info!(&log_clone, "Update failed: {:?}", err);
                }
                bytes += 1;
            }
        })
    }

    // Poll the workload futures to completion
    block_on(async { while futures.next().await.is_some() {} });

    // Download Prometheus data if required.
    if download_prometheus_data {
        info!(&log, "Waiting before download.");
        std::thread::sleep(Duration::from_secs(100));
        info!(&log, "Downloading p8s data");
        env.download_prometheus_data_dir_if_exists();
    }
}
