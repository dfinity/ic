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
use futures::stream::{FuturesUnordered, StreamExt};
use ic_registry_routing_table::CanisterIdRanges;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_agent::{CanisterAgent, HasCanisterAgentCapability},
    driver::{
        farm::HostFeature,
        group::SystemTestGroup,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{simulate_network, NetworkSimulation, ProductionSubnetTopology},
        test_env::TestEnv,
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasDependencies, HasPublicApiUrl, HasTopologySnapshot,
            HasWasm, IcNodeContainer,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
    util::{block_on, UniversalCanister},
};
use ic_universal_canister::PayloadBuilder;
use serde::{Deserialize, Serialize};
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

// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);

const SUBNET_SIZE: usize = 1;

const CLONER_CANISTER_WASM: &str = "rs/tests/src/cloner_canister.wasm.gz";
const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA;
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA;
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(install_cloner_canisters))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}

const MAX_CANISTERS_INSTALLING_IN_PARALLEL: usize = 10;

pub fn config(env: TestEnv) {
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    info!(
        &logger,
        "Step 1: Checking readiness of all replica nodes..."
    );

    InternetComputer::new()
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

    info!(&logger, "Step 3: Installing cloner canister.");
    let app_node = app_subnet.nodes().next().unwrap();
    let cloner_canister_id =
        app_node.create_and_install_canister_with_arg(CLONER_CANISTER_WASM, None);
    info!(
        &logger,
        "Succeeded installing cloner canister, {}.", cloner_canister_id
    );

    let counter_canister_bytes = env.load_wasm(COUNTER_CANISTER_WAT);

    info!(&logger, "Step 4: Spinning up canisters.");

    rt.block_on(async {
        let CanisterAgent { agent } = app_node.build_canister_agent().await;

        let args = Encode!(&SpinupCanistersArgs {
            canisters_number: 10_000,
            wasm_module: counter_canister_bytes,
            initial_cycles: 10_u64.pow(10), // 1B Cycles
            batch_size: 250,
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
                info!(&logger, "Successfully spun up canisters.");
            }
            Err(err) => {
                info!(&logger, "Failed to spin up canisters: {:?}", err);
            }
        }
        info!(
            &logger,
            "Time taken to spin up canisters: {:?}",
            timer.elapsed()
        );
    });

    info!(&logger, "Step 5: Finished spinning up canisters.");

    // sleep for 60 min
    std::thread::sleep(Duration::from_secs(60 * 60));
}

#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct SpinupCanistersArgs {
    pub canisters_number: u64,
    pub initial_cycles: u64,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
    pub batch_size: u64,
}
