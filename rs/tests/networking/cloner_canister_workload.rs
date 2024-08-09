//! System test that sets up a 13 node APP subnet to benchmark the subnet
//! when the installing a large number of canisters. The canisters are created
//! by installing a `cloner canister`, which spins up large batches of canisters
//! in parallel.
//!
//! To run the benchmark, run the following command in the dev container:
//! ict test //rs/tests/networking:cloner_canister -k -- --test_timeout=600000 --test_tmpdir=test_tmpdir
//!
//! Wait for output to show the console links to the VMs.
//! Use "Ctrl + F" to search for "/console"
//! 2024-08-07 09:45:55.378 INFO[setup:rs/tests/driver/src/driver/log_events.rs:20:0] {"event_name":"vm_console_link_created_event","body":{"url":"https://farm.dfinity.systems/group/cloner-canisters-workload--1723023931452/vm/3aazi-jrwkv-znyt4-2sliu-stgro-p6dql-ac6sv-53e5j-y3ebi-eofm6-dae/console/","vm_name":"3aazi-jrwkv-znyt4-2sliu-stgro-p6dql-ac6sv-53e5j-y3ebi-eofm6-dae"}}
//!
//! Use the console link to stop and start the replica process in order to start a catch up process.
//! To stop the replica use the command:
//! `systemctl stop ic-replica`
//!
//! To start the replica again, use the command:
//! `systemctl start ic-replica`

use anyhow::Result;
use candid::Encode;
use cloner_canister_types::SpinupCanistersArgs;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_agent::{CanisterAgent, HasCanisterAgentCapability},
    driver::{
        farm::HostFeature,
        group::SystemTestGroup,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{load_wasm, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
};
use slog::info;
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60); // 4 hours

/// Time to keep the testnet alive once all canisters are installed
const TESTNET_LIFETIME_AFTER_SETUP: Duration = Duration::from_secs(60 * 60); // 1 hour

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";

const SUBNET_SIZE: usize = 13;
const INITIAL_NOTARY_DELAY: Duration = Duration::from_millis(200);

// 100,000 canisters, with 500 batches, will take ~25 minutes to set up.
// Yields 280-310ms commit and certify times.
// We need minimum 350+ms, so we should probably push this to 150,000 canisters.
const NUMBER_OF_CANISTERS_TO_INSTALL: u64 = 200_000;
const CANISTERS_INSTALLED_PER_CLONER_CANISTER: u64 = 500;
const AMOUNT_OF_CLONER_CANISTERS: u64 =
    NUMBER_OF_CANISTERS_TO_INSTALL / CANISTERS_INSTALLED_PER_CLONER_CANISTER;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(install_cloner_canisters))
        .with_timeout_per_test(TEST_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    info!(
        &logger,
        "Step 1: Starting the IC with a subnet of size {SUBNET_SIZE}.",
    );

    // Production-like resources
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)), //  512 GB
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    InternetComputer::new()
        .with_default_vm_resources(vm_resources)
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(SUBNET_SIZE)
                .with_initial_notary_delay(INITIAL_NOTARY_DELAY),
        )
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
    let counter_canister_bytes = load_wasm(COUNTER_CANISTER_WAT);

    info!(
        &logger,
        "Sending ingress messages to {:?}. Be careful to not kill this node while spinning up canisters, otherwise the installation of cloner canisters will fail.",
        app_node.get_public_url().to_string()
    );

    for i in 0..AMOUNT_OF_CLONER_CANISTERS {
        let counter_canister_bytes_clone = counter_canister_bytes.clone();
        info!(
            &logger,
            "{i}/{AMOUNT_OF_CLONER_CANISTERS}: Installing cloner canister."
        );
        let cloner_canister_id = app_node.create_and_install_canister_with_arg(
            &std::env::var("CLONER_CANISTER_WASM_PATH").expect("CLONER_CANISTER_WASM_PATH not set"),
            None,
        );
        info!(
            &logger,
            "{i}/{AMOUNT_OF_CLONER_CANISTERS}: Succeeded installing cloner canister, {}.",
            cloner_canister_id
        );

        info!(
            &logger,
            "{i}/{AMOUNT_OF_CLONER_CANISTERS}: Spinning up {CANISTERS_INSTALLED_PER_CLONER_CANISTER} canisters."
        );

        rt.block_on(async {
            let CanisterAgent { agent } = app_node.build_canister_agent().await;

            let args = Encode!(&SpinupCanistersArgs {
                canisters_number: CANISTERS_INSTALLED_PER_CLONER_CANISTER,
                wasm_module: counter_canister_bytes_clone,
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
                    info!(
                        &logger,
                        "{i}/{AMOUNT_OF_CLONER_CANISTERS}: Successfully spun up canisters."
                    );
                }
                Err(err) => {
                    info!(
                        &logger,
                        " {i}/{AMOUNT_OF_CLONER_CANISTERS}:Failed to spin up canisters: {:?}", err
                    );
                }
            }
            info!(
                &logger,
                "{i}/{AMOUNT_OF_CLONER_CANISTERS}: Time taken to spin up canisters: {:?}",
                timer.elapsed()
            );
        });
    }

    // keep the workload running for a while
    info!(&logger, "Step 5: Finished spinning up canisters.");
    info!(
        &logger,
        "Waiting {:?} before downloading prometheus data.", TESTNET_LIFETIME_AFTER_SETUP
    );
    std::thread::sleep(TESTNET_LIFETIME_AFTER_SETUP);
    info!(&logger, "Step 6: Downloading prometheus data");
    env.download_prometheus_data_dir_if_exists();
}
