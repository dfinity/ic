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
//   $ ci/container/container-run.sh
//   $ ict test tecdsa_performance_test_colocate --keepalive -- --test_tmpdir=./performance --test_env DOWNLOAD_P8S_DATA=1 --test_env NODES_COUNT=40
//
// The --test_tmpdir=./performance will store the test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i performance/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of IC nodes by looking for the "IC TopologySnapshot" in the logs:
//
// [...] TEST_LOG: ============================================== IC TopologySnapshot, registry version 1 ==============================================
// [...] TEST_LOG: Subnet id=s7nx3-ohrn3-yr3me-2u2uz-ggc3p-sxctl-6gi4m-24zkp-xbkv6-7awbl-eqe, index=0, type=System
// [...] TEST_LOG:    Node id=gi22p-z65m6-2je6o-ofjrq-dgbhz-oovnh-qt5r4-ipuzz-zgr6s-zadz5-5ae, ipv6=2602:fb2b:100:10:50c0:4aff:fe48:621c, index=0
// [...] TEST_LOG: Subnet id=skbnp-ytnyv-g45vf-lxmc7-uo4d4-uul7e-uqlmt-obllg-ayzue-vqlbb-bae, index=1, type=Application
// [...] TEST_LOG:    Node id=hubhq-5a45w-jikdq-mmt2k-dtfou-w5kkl-hhqap-akg77-ucuti-iy7ea-sae, ipv6=2602:fb2b:100:10:5060:c4ff:feb4:7698, index=0
// [...] TEST_LOG:    Node id=ahm26-luzd4-ip3xt-oma5e-f7mzd-xkmne-52tun-jtf2n-qhoe6-gpmyt-dae, ipv6=2602:fb2b:100:10:50fb:c3ff:fe3d:e3d1, index=1
// [...] TEST_LOG:    Node id=ellje-2rvws-jx6v5-acjhp-uogh2-3gm2z-utyc3-avgre-56u3f-ybbk3-fae, ipv6=2602:fb2b:100:10:5033:d9ff:fea5:1c7b, index=2
// =====================================================================================================================================
//
// To get live access to P8s and Grafana while the test is running look for the following log lines:
//
// [...] TEST_LOG: [...] {"event_name":"prometheus_vm_created_event","body":"Prometheus Web UI at http://prometheus.tecdsa-performance-test-colocate--1758706685338.testnet.farm.dfinity.systems"}
// [...] TEST_LOG: [...] {"event_name":"grafana_instance_created_event","body":"Grafana at http://grafana.tecdsa-performance-test-colocate--1758706685338.testnet.farm.dfinity.systems"}
// [...] TEST_LOG: [...] {"event_name":"ic_progress_clock_created_event","body":"IC Progress Clock at http://grafana.tecdsa-performance-test-colocate--1758706685338.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now"}
//
// To inspect the metrics after the test has finished, exit the dev container
// and run a local p8s and Grafana on the downloaded p8s data directory using:
//
//   $ rs/tests/run-p8s.sh --grafana-dashboards-dir ~/k8s/bases/apps/ic-dashboards performance/_tmp/*/setup/colocated_test/tests/test/universal_vms/prometheus/prometheus-data-dir.tar.zst
//
// Note this this script requires Nix so make sure it's installed (https://nixos.org/download/).
// The script also requires a local clone of https://github.com/dfinity-ops/k8s containing the Grafana dashboards.
//
// Then, on your laptop, forward the Grafana port 3000 to your devenv:
//
//   $ ssh devenv -L 3000:localhost:3000 -N
//
// and load http://localhost:3000/ in your browser to inspect the dashboards.
//
// Happy testing!

use anyhow::Result;
use futures::future::join_all;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_with_customizations_and_check_progress,
    subnet::enable_chain_key_signing_on_subnet,
};
use ic_consensus_threshold_sig_system_test_utils::{
    ChainSignatureRequest, run_chain_key_signature_test,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::HasPrometheus,
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
    MessageCanister, SignerCanister, block_on, get_app_subnet_and_node, get_nns_node,
};
use ic_types::Height;
use slog::{error, info};
use std::fs::create_dir_all;
use std::io::prelude::*;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

// Environment parameters
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
const PRE_SIGNATURES_TO_CREATE: u32 = 40;
const MAX_QUEUE_SIZE: u32 = 30;
const CANISTER_COUNT: usize = 4;
const SIGNATURE_REQUESTS_PER_SECOND: f64 = 9.0;

const SMALL_MSG_SIZE_BYTES: usize = 32;
#[allow(dead_code)]
const LARGE_MSG_SIZE_BYTES: usize = 10_484_000; // 10MiB minus some message overhead

// By default, we keep a small message size, to avoid permanent heavy test load.
// Change to LARGE_MSG_SIZE_BYTES to test large signature requests.
const MSG_SIZE_BYTES: usize = SMALL_MSG_SIZE_BYTES;

const BENCHMARK_REPORT_FILE: &str = "benchmark/benchmark.json";

// The signature schemes and key names to be used during the test.
// Requests will be sent to each key in round robin order.
fn make_key_ids() -> Vec<MasterPublicKeyId> {
    // `TECDSA_PERFORMANCE_TEST_KEY_IDS` is a comma-separated string without
    // spaces. It is used to select the key ids to be used during the test.
    let key_ids_string = std::env::var("TECDSA_PERFORMANCE_TEST_KEY_IDS").expect(
        "Failed to fetch key ids from the TECDSA_PERFORMANCE_TEST_KEY_IDS environment variable.",
    );

    let key_ids_split: std::collections::HashSet<&str> = key_ids_string.split(',').collect();

    if key_ids_split.is_empty() {
        panic!("No keys defined in TECDSA_PERFORMANCE_TEST_KEY_IDS");
    }

    let mut result = vec![];

    for key_id in key_ids_split {
        match key_id {
            "schnorr_bip340" => {
                result.push(ic_consensus_threshold_sig_system_test_utils::make_bip340_key_id());
            }
            "schnorr_ed25519" => {
                result.push(ic_consensus_threshold_sig_system_test_utils::make_eddsa_key_id());
            }
            "ecdsa_secp256k1" => {
                result.push(ic_consensus_threshold_sig_system_test_utils::make_ecdsa_key_id());
            }
            "vetkd_bls12_381_g2" => {
                result.push(ic_consensus_threshold_sig_system_test_utils::make_vetkd_key_id());
            }
            _ => panic!(
                "Unknown key id {key_id} in the environment variable TECDSA_PERFORMANCE_TEST_KEY_IDS={key_ids_string}. \
                Allowed are vetkd_bls12_381_g2, schnorr_bip340, schnorr_ed25519, and ecdsa_secp256k1. Also note that \
                the key ids should be comma-separated without spaces.",
            ),
        }
    }

    result
}

pub fn setup(env: TestEnv) {
    let nodes_count: usize = std::env::var("NODES_COUNT")
        .or(std::env::var("DEFAULT_NODES_COUNT"))
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .expect(
            "Failed to parse NODES_COUNT or DEFAULT_NODES_COUNT environment variable as an usize!",
        );

    info!(
        env.logger(),
        "Deploying a testnet with a {nodes_count}-node application subnet ...",
    );

    let key_ids = make_key_ids();
    info!(env.logger(), "Running the test with key ids: {:?}", key_ids);

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_required_host_features(vec![
                    HostFeature::Performance,
                    HostFeature::Supermicro,
                ])
                .with_default_vm_resources(vm_resources)
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_required_host_features(vec![HostFeature::Performance, HostFeature::Dell])
                .with_default_vm_resources(vm_resources)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_chain_key_config(ChainKeyConfig {
                    key_configs: key_ids
                        .into_iter()
                        .map(|key_id| KeyConfig {
                            max_queue_size: MAX_QUEUE_SIZE,
                            pre_signatures_to_create_in_advance: PRE_SIGNATURES_TO_CREATE,
                            key_id,
                        })
                        .collect(),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                })
                .add_nodes(nodes_count),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
}

pub fn test(env: TestEnv) {
    let download_p8s_data =
        std::env::var("DOWNLOAD_P8S_DATA").is_ok_and(|v| v == "true" || v == "1");
    tecdsa_performance_test(env, false, download_p8s_data);
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

    info!(log, "Step 2: Installing Signer canisters");
    let principals = (0..CANISTER_COUNT)
        .map(|_| {
            block_on(SignerCanister::new_with_cycles(
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
            // The derivation path can vary either in length or in size of the elements.
            // For simplicity, we test one derivation element of maximum size. We could
            // also test a big number of small elements, but this would imply a larger
            // serialization overhead (as it would include the length of each element),
            // which we would need to account for in the LARGE_MSG_SIZE_BYTES constant.
            //
            // For Schnorr, we test a large message and a keep the derivation path small,
            // as the latter is tested in ECDSA.
            //
            // For VetKD, we can vary either the context size or the input size. For simplicity,
            // we test a large input size.

            let (method_name, payload) = match key_id.clone() {
                MasterPublicKeyId::Ecdsa(key_id) => {
                    ChainSignatureRequest::large_ecdsa_method_and_payload(1, MSG_SIZE_BYTES, key_id)
                }
                MasterPublicKeyId::Schnorr(key_id) => {
                    ChainSignatureRequest::large_schnorr_method_and_payload(
                        MSG_SIZE_BYTES,
                        1,
                        0,
                        key_id,
                        None,
                    )
                }
                MasterPublicKeyId::VetKd(key_id) => {
                    ChainSignatureRequest::large_vetkd_method_and_payload(MSG_SIZE_BYTES, 0, key_id)
                }
            };

            requests.push(ChainSignatureRequest {
                principal,
                method_name,
                key_id,
                payload,
            });
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
        env.emit_report(format!("{metrics}"));
        info!(log, "Step 5: Assert expected number of successful requests");
        let requests_count = rps * duration.as_secs_f64();
        let min_expected_success_calls = (SUCCESS_THRESHOLD * requests_count) as usize;
        info!(
            log,
            "Minimal expected number of success calls {}", min_expected_success_calls,
        );

        let timestamp =
            chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339();

        let benchmark_name = std::env::var("BENCHMARK_NAME").unwrap_or_else(|e| {
            error!(
                log,
                "failed to fetch BENCHMARK_NAME environment variable: {e:?}"
            );
            "unknown_benchmark_name".to_string()
        });

        let json_report = serde_json::json!(
            {
                "benchmark_name": benchmark_name.as_str(),
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
            ic_sys::fs::write_atomically(&report_path, ic_sys::fs::Clobber::Yes, |f| {
                f.write_all(json_report_str.as_bytes())
            });

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
