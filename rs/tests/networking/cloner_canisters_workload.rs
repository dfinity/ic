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
use candid::{CandidType, Encode};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_agent::{CanisterAgent, HasCanisterAgentCapability},
    driver::{
        farm::HostFeature,
        group::SystemTestGroup,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, HasWasm, IcNodeContainer},
    },
    systest,
};
use serde::{Deserialize, Serialize};
use slog::info;
use std::time::Duration;

// 4 hours minutes
const WORKLOAD_RUNTIME: Duration = Duration::from_secs(4 * 60 * 60);

// 5 minutes
const DOWNLOAD_PROMETHEUS_WAIT_TIME: Duration = Duration::from_secs(5 * 60);

// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);

const CLONER_CANISTER_WASM: &str = "rs/tests/src/cloner_canister.wasm.gz";
const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";

const SUBNET_SIZE: usize = 13;

// 100,000 canisters, with 500 batches, will take ~25 minutes to set up.
// Yields 280-310ms commit and certify times.
// We need minimum 350+ms, so we should probably push this to 150,000 canisters.
const NUMBER_OF_CANISTERS: u64 = 125_000;
const CANISTERS_PER_BATCH: u64 = 500;
const ITERATIONS: u64 = NUMBER_OF_CANISTERS / CANISTERS_PER_BATCH;

/// This number should not exceed the length of the canister output queue,
/// which is currently 500.
const CLONER_CANISTER_BATCH_SIZE: u64 = 250;
const INITIAL_CYCLES: u64 = 10_u64.pow(11); // 100B Cycles

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA;
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA;
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(install_cloner_canisters))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .execute_from_args()?;
    Ok(())
}

pub fn config(env: TestEnv) {
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    info!(
        &logger,
        "Step 1: Starting the IC with a subnet of size {SUBNET_SIZE}.",
    );

    // set up IC overriding the default resources to be more powerful
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)), // <- 512 GB
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    InternetComputer::new()
        .with_default_vm_resources(vm_resources)
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(SUBNET_SIZE))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    env.sync_with_prometheus();

    // Await Replicas
    info!(
        &logger,
        "Step 2: Checking readiness of all replica nodes..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .await_all_nodes_healthy()
            .expect("Failed waiting for all nodes to become healthy")
    });
}

pub fn install_cloner_canisters(env: TestEnv) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let top_snapshot = env.topology_snapshot();
    let logger = env.logger();
    top_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    let app_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let counter_canister_bytes = env.load_wasm(COUNTER_CANISTER_WAT);
    for i in 0..ITERATIONS {
        let counter_canister_bytes_clone = counter_canister_bytes.clone();
        info!(&logger, "{i}/{ITERATIONS}: Installing cloner canister.");
        let cloner_canister_id =
            app_node.create_and_install_canister_with_arg(CLONER_CANISTER_WASM, None);
        info!(
            &logger,
            "{i}/{ITERATIONS}: Succeeded installing cloner canister, {}.", cloner_canister_id
        );

        info!(
            &logger,
            "{i}/{ITERATIONS}: Spinning up {CANISTERS_PER_BATCH} canisters."
        );

        rt.block_on(async {
            let CanisterAgent { agent } = app_node.build_canister_agent().await;

            let args = Encode!(&SpinupCanistersArgs {
                canisters_number: CANISTERS_PER_BATCH,
                wasm_module: counter_canister_bytes_clone,
                initial_cycles: INITIAL_CYCLES, // 1B Cycles
                batch_size: CLONER_CANISTER_BATCH_SIZE,
                arg: vec![],
            })
            .unwrap();
            // time this call
            let timer = std::time::Instant::now();
            match agent
                .update(&cloner_canister_id, "spinup_canisters")
                .with_arg(args)
                .call_and_wait()
                .await
            {
                Ok(_) => {
                    info!(&logger, "{i}/{ITERATIONS}: Successfully spun up canisters.");
                }
                Err(err) => {
                    info!(
                        &logger,
                        " {i}/{ITERATIONS}:Failed to spin up canisters: {:?}", err
                    );
                }
            }
            info!(
                &logger,
                "{i}/{ITERATIONS}: Time taken to spin up canisters: {:?}",
                timer.elapsed()
            );
        });
    }

    // keep the workload running for a while
    info!(&logger, "Step 5: Finished spinning up canisters.");

    let time_to_wait_for_download = WORKLOAD_RUNTIME - DOWNLOAD_PROMETHEUS_WAIT_TIME;
    info!(
        &logger,
        "Waiting {:?} before download.", time_to_wait_for_download
    );
    std::thread::sleep(time_to_wait_for_download);
    info!(&logger, "Step 6: Downloading prometheus data");
    env.download_prometheus_data_dir_if_exists();
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct SpinupCanistersArgs {
    pub canisters_number: u64,
    pub initial_cycles: u64,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub batch_size: u64,
}
