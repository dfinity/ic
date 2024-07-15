use crate::nns_dapp::set_authorized_subnets;
use crate::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use crate::orchestrator::utils::subnet_recovery::{
    enable_chain_key_signing_on_subnet, run_chain_key_signature_test,
};
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_api::{CallMode, Request};
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, SshSession};
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{
        HasTopologySnapshot, IcNodeContainer, NnsCanisterWasmStrategy, NnsCustomizations,
    },
};
use ic_system_test_driver::generic_workload_engine::engine::Engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::util::{
    block_on, get_app_subnet_and_node, get_nns_node, MessageCanister,
};

use candid::{CandidType, Deserialize, Encode, Principal};
use futures::future::join_all;
use ic_config::subnet_config::{ECDSA_SIGNATURE_FEE, SCHNORR_SIGNATURE_FEE};
use ic_management_canister_types::{
    DerivationPath, EcdsaKeyId, MasterPublicKeyId, Payload, SchnorrKeyId, SignWithECDSAArgs,
    SignWithECDSAReply, SignWithSchnorrArgs, SignWithSchnorrReply,
};
use ic_message::ForwardParams;
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig};
use ic_registry_subnet_type::SubnetType;
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
const DEVICE_NAME: &str = "enp1s0"; // network interface name
const BANDWIDTH_MBITS: u32 = 80; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(120); // artificial added latency
const LATENCY_JITTER: Duration = Duration::from_millis(20);

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
        crate::tecdsa::make_ecdsa_key_id(),
        // crate::tecdsa::make_bip340_key_id(),
        // crate::tecdsa::make_eddsa_key_id(),
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
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        NnsCustomizations::default(),
    );
    set_authorized_subnets(&env);
    env.sync_with_prometheus();
}

#[derive(Clone)]
pub struct ChainSignatureRequest {
    pub key_id: MasterPublicKeyId,
    pub principal: Principal,
    pub payload: Vec<u8>,
}

impl ChainSignatureRequest {
    pub fn new(principal: Principal, key_id: MasterPublicKeyId) -> Self {
        let params = match key_id.clone() {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => Self::ecdsa_params(ecdsa_key_id),
            MasterPublicKeyId::Schnorr(schnorr_key_id) => Self::schnorr_params(schnorr_key_id),
        };
        let payload = Encode!(&params).unwrap();

        Self {
            key_id,
            principal,
            payload,
        }
    }

    fn ecdsa_params(ecdsa_key_id: EcdsaKeyId) -> ForwardParams {
        let signature_request = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: ecdsa_key_id,
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_ecdsa".to_string(),
            cycles: ECDSA_SIGNATURE_FEE.get() * 2,
            payload: Encode!(&signature_request).unwrap(),
        }
    }

    fn schnorr_params(schnorr_key_id: SchnorrKeyId) -> ForwardParams {
        let signature_request = SignWithSchnorrArgs {
            message: [1; SCHNORR_MSG_SIZE_BYTES].to_vec(),
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: schnorr_key_id,
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_schnorr".to_string(),
            cycles: SCHNORR_SIGNATURE_FEE.get() * 2,
            payload: Encode!(&signature_request).unwrap(),
        }
    }
}

#[derive(CandidType, Deserialize, Debug)]
pub enum SignWithChainKeyReply {
    Ecdsa(SignWithECDSAReply),
    Schnorr(SignWithSchnorrReply),
}

impl Request<SignWithChainKeyReply> for ChainSignatureRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.principal
    }
    fn method_name(&self) -> String {
        "forward".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    fn parse_response(&self, raw_response: &[u8]) -> anyhow::Result<SignWithChainKeyReply> {
        Ok(match self.key_id {
            MasterPublicKeyId::Ecdsa(_) => {
                SignWithChainKeyReply::Ecdsa(SignWithECDSAReply::decode(raw_response)?)
            }
            MasterPublicKeyId::Schnorr(_) => {
                SignWithChainKeyReply::Schnorr(SignWithSchnorrReply::decode(raw_response)?)
            }
        })
    }
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
            requests.push(ChainSignatureRequest::new(principal, key_id))
        }
    }

    if apply_network_settings {
        info!(log, "Optional Step: Modify all nodes' traffic using tc");
        app_subnet.nodes().for_each(|node| {
            info!(log, "Modifying node {}", node.get_ip_addr());
            let session = node
                .block_on_ssh_session()
                .expect("Failed to ssh into node");
            node.block_on_bash_script_from_session(&session, &limit_tc_ssh_command())
                .expect("Failed to execute bash script from session");
        });
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

/**
 * 1. Delete existing tc rules (if present).
 * 2. Add a root qdisc (queueing discipline) for an htb (hierarchical token bucket).
 * 3. Add a class with bandwidth limit.
 * 4. Add a qdisc to introduce latency with jitter.
 * 5. Add a filter to associate IPv6 traffic with the class and specific port.
 * 6. Read the active tc rules.
 */
fn limit_tc_ssh_command() -> String {
    let cfg = ic_system_test_driver::util::get_config();
    let p2p_listen_port = cfg.transport.unwrap().listening_port;
    format!(
        r#"set -euo pipefail
sudo tc qdisc del dev {device} root 2> /dev/null || true
sudo tc qdisc add dev {device} root handle 1: htb default 10
sudo tc class add dev {device} parent 1: classid 1:10 htb rate {bandwidth_mbit}mbit ceil {bandwidth_mbit}mbit
sudo tc qdisc add dev {device} parent 1:10 handle 10: netem delay {latency_ms}ms {jitter_ms}ms
sudo tc filter add dev {device} parent 1: protocol ipv6 prio 1 u32 match ip6 dport {p2p_listen_port} 0xFFFF flowid 1:10
sudo tc qdisc show dev {device}
"#,
        device = DEVICE_NAME,
        bandwidth_mbit = BANDWIDTH_MBITS,
        latency_ms = LATENCY.as_millis(),
        jitter_ms = LATENCY_JITTER.as_millis(),
        p2p_listen_port = p2p_listen_port
    )
}
