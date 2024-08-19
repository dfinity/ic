// This is a template showing how to run performance tests. Once a specific metric of interest
// is identified, one can create a separate test that displays it in a reproducible manner.
// For example throughput_with_small_messages.rs or throughput_with_large_messages.rs.
//
// Set up a testnet for interactive performance testing allocated in our performance DC (dm1):
// 26-node System subnet, single boundary node and a p8s (with grafana) VM.
// All nodes use the following resources: 64 vCPUs, 488GiB of RAM and 500 GiB disk.
//
// This test additionally installs the NNS.
//
// You can setup this test by executing the following commands:
//
//   $ gitlab-ci/container/container-run.sh
//   $ ict test consensus_performance_test_colocate --keepalive -- --test_tmpdir=./performance
//
// The --test_tmpdir=./performance will store the test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i performance/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node by looking for a log line like:
//
//   Apr 11 15:34:10.175 INFO[rs/tests/src/driver/farm.rs:94:0]
//     VM(h2tf2-odxlp-fx5uw-kvn43-bam4h-i4xmw-th7l2-xxwvv-dxxpz-bs3so-iqe)
//     Host: ln1-dll10.ln1.dfinity.network
//     IPv6: 2a0b:21c0:4003:2:5051:85ff:feec:6864
//     vCPUs: 64
//     Memory: 512142680 KiB
//
// To get access to P8s and Grafana look for the following log lines:
//
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:168:0]
//     Prometheus Web UI at http://prometheus.performance--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:170:0]
//     IC Progress Clock at http://grafana.performance--1681227226065.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:169:0]
//     Grafana at http://grafana.performance--1681227226065.testnet.farm.dfinity.systems
//
// Happy testing!

use anyhow::Result;
use futures::future::join_all;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_with_customizations_and_check_progress,
    subnet::enable_chain_key_signing_on_subnet,
};
use ic_consensus_threshold_sig_system_test_utils::{
    run_chain_key_signature_test, ChainSignatureRequest,
};
use ic_management_canister_types::MasterPublicKeyId;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    simulate_network::{FixedNetworkSimulation, SimulateNetwork},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsCustomizations},
};
use ic_system_test_driver::generic_workload_engine::engine::Engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    block_on, get_app_subnet_and_node, get_nns_node, MessageCanister,
};
use ic_types::Height;
use slog::{error, info};
use std::fs::create_dir_all;
use std::io::prelude::*;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

// Environment parameters
const NODES_COUNT: usize = 25;
const SUCCESS_THRESHOLD: f64 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TESTING_PERIOD: Duration = Duration::from_secs(900); // testing time under load
const COOLDOWN_PERIOD: Duration = Duration::from_secs(300); // sleep time before downloading p8s data
const DKG_INTERVAL: u64 = 499;
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

// Network parameters
const BANDWIDTH_MBITS: u32 = 80; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(120); // artificial added latency
const NETWORK_SIMULATION: FixedNetworkSimulation = FixedNetworkSimulation::new()
    .with_latency(LATENCY)
    .with_bandwidth(BANDWIDTH_MBITS);

// Signature parameters
const PRE_SIGNATURES_TO_CREATE: u32 = 30;
const MAX_QUEUE_SIZE: u32 = 10;
const CANISTER_COUNT: usize = 4;
const SIGNATURE_REQUESTS_PER_SECOND: f64 = 2.5;
const SCHNORR_MSG_SIZE_BYTES: usize = 2_096_000; // 2MiB minus some message overhead

const BENCHMARK_REPORT_FILE: &str = "benchmark/benchmark.json";

// The signature schemes and key names to be used during the test.
// Requests will be sent to each key in round robin order.
fn make_key_ids() -> Vec<MasterPublicKeyId> {
    vec![
        ic_consensus_threshold_sig_system_test_utils::make_ecdsa_key_id(),
        // ic_consensus_threshold_sig_system_test_utils::make_bip340_key_id(),
        // ic_consensus_threshold_sig_system_test_utils::make_eddsa_key_id(),
    ]
}

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: make_key_ids()
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            max_queue_size: MAX_QUEUE_SIZE,
                            pre_signatures_to_create_in_advance: PRE_SIGNATURES_TO_CREATE,
                            key_id,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                })
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    env.sync_with_prometheus();
}

pub fn test(env: TestEnv) {
    tecdsa_performance_test(env, false, false);
}

pub fn tecdsa_performance_test(
    env: TestEnv,
    apply_network_settings: bool,
    download_p8s_data: bool,
) {
    let log = env.logger();

    let duration: Duration = TESTING_PERIOD;
    let rps = SIGNATURE_REQUESTS_PER_SECOND;

    let topology_snapshot = env.topology_snapshot();
    let nns_node = get_nns_node(&topology_snapshot);
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &nns_agent,
        nns_node.effective_canister_id(),
    ));

    let (app_subnet, app_node) = get_app_subnet_and_node(&topology_snapshot);
    let app_agent = app_node.with_default_agent(|agent| async move { agent });

    info!(
        log,
        "Step 1: Enabling threshold signing and ensuring it works"
    );
    let keys = enable_chain_key_signing_on_subnet(
        &nns_node,
        &nns_canister,
        app_subnet.subnet_id,
        make_key_ids(),
        &log,
    );

    for (key_id, public_key) in keys {
        run_chain_key_signature_test(&nns_canister, &log, &key_id, public_key);
    }

    info!(log, "Step 2: Installing Message canisters");
    let principals = (0..CANISTER_COUNT)
        .map(|_| {
            block_on(MessageCanister::new_with_cycles(
                &app_agent,
                app_node.effective_canister_id(),
                u128::MAX,
            ))
            .canister_id()
        })
        .collect::<Vec<_>>();
    let mut requests = vec![];
    for principal in principals {
        for key_id in make_key_ids() {
            requests.push(ChainSignatureRequest::new(
                principal,
                key_id,
                SCHNORR_MSG_SIZE_BYTES,
            ))
        }
    }

    if apply_network_settings {
        info!(log, "Optional Step: Modify all nodes' traffic using tc");
        app_subnet.apply_network_settings(NETWORK_SIMULATION);
    }

    // create the runtime that lives until this variable is dropped.
    info!(
        env.logger(),
        "Step 3: Start tokio runtime: worker_threads={}, blocking_threads={}",
        MAX_RUNTIME_THREADS,
        MAX_RUNTIME_BLOCKING_THREADS
    );
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let agents = join_all(
            app_subnet
                .nodes()
                .map(|n| async move { n.build_canister_agent().await }),
        )
        .await;

        info!(log, "Step 4: Instantiate and start the workload generator");
        let generator = move |idx: usize| {
            let request = requests[idx % requests.len()].clone();
            let agent = agents[idx % agents.len()].clone();
            async move {
                let request_outcome = canister_requests![
                    idx,
                    1 * agent => request,
                ];
                request_outcome.into_test_outcome()
            }
        };

        let metrics = Engine::new(log.clone(), generator, rps, duration)
            .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
            .execute_simply(log.clone())
            .await;

        info!(log, "Reporting workload execution results");
        env.emit_report(format!("{}", metrics));
        info!(log, "Step 5: Assert expected number of successful requests");
        let requests_count = rps * duration.as_secs_f64();
        let min_expected_success_calls = (SUCCESS_THRESHOLD * requests_count) as usize;
        info!(
            log,
            "Minimal expected number of success calls {}", min_expected_success_calls,
        );

        let timestamp =
            chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339();

        let json_report = serde_json::json!(
            {
                "benchmark_name": "tecdsa_performance_test",
                "timestamp": timestamp,
                "package": "replica-benchmarks",
                "benchmark_results": {
                    "success_calls": metrics.success_calls() as f32,
                    "failure_calls": metrics.failure_calls() as f32,
                    "success_rps": metrics.success_calls() as f32 / TESTING_PERIOD.as_secs() as f32
                }
            }
        );

        let json_report_str = serde_json::to_string_pretty(&json_report).unwrap();

        info!(log, "json benchmark report:\n{json_report_str}");

        let report_path = env.base_path().join(BENCHMARK_REPORT_FILE);

        let create_dir_result = match report_path.parent() {
            Some(dir_path) => create_dir_all(dir_path),
            None => Ok(()),
        };

        let open_and_write_to_file_result =
            ic_sys::fs::write_atomically(&report_path, |f| f.write_all(json_report_str.as_bytes()));

        match create_dir_result.and(open_and_write_to_file_result) {
            Ok(()) => info!(log, "Benchmark report written to {}", report_path.display()),
            Err(e) => error!(log, "Failed to write benchmark report: {}", e),
        }

        if cfg!(feature = "upload_perf_systest_results") {
            // elastic search url
            const ES_URL: &str =
                "https://elasticsearch.testnet.dfinity.network/ci-performance-test/_doc";
            const NUM_UPLOAD_ATTEMPS: usize = 3;
            info!(
                log,
                "Starting to upload performance test results to {ES_URL}"
            );

            for i in 1..=NUM_UPLOAD_ATTEMPS {
                info!(
                    log,
                    "Uploading performance test results attempt {}/{}", i, NUM_UPLOAD_ATTEMPS
                );

                let client = reqwest::Client::new();
                match client.post(ES_URL).json(&json_report).send().await {
                    Ok(response) => {
                        info!(
                            log,
                            "Successfully uploaded performance test results: {response:?}"
                        );
                        break;
                    }
                    Err(e) => error!(log, "Failed to upload performance test results: {e:?}"),
                }
            }
        }

        if download_p8s_data {
            info!(log, "Sleeping for {} seconds", COOLDOWN_PERIOD.as_secs());
            std::thread::sleep(COOLDOWN_PERIOD);
            info!(log, "Downloading prometheus data");
            env.download_prometheus_data_dir_if_exists();
        } else {
            assert!(metrics.success_calls() >= min_expected_success_calls);
        }
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
