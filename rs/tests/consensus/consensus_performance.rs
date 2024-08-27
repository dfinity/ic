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
//   $ ict test consensus_performance_colocate --keepalive -- --test_tmpdir=./performance
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
// To access the NNS or II dapps look for the following log lines:
//
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:99:0]
//     Internet Identity: https://qhbym-qaaaa-aaaaa-aaafq-cai.ic0.farm.dfinity.systems
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:103:0]
//     NNS frontend dapp: https://qsgjb-riaaa-aaaaa-aaaga-cai.ic0.farm.dfinity.systems
//
// Happy testing!

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_api::{CallMode, GenericRequest};
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::IcNodeSnapshot;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    simulate_network::{FixedNetworkSimulation, SimulateNetwork},
    test_env::TestEnv,
    test_env_api::{
        read_dependency_from_env_to_string, HasTopologySnapshot, IcNodeContainer, NnsCustomizations,
    },
};
use ic_system_test_driver::generic_workload_engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetrics, LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    assert_canister_counter_with_retries, get_app_subnet_and_node, MetricsFetcher,
};
use ic_types::Height;

use anyhow::Result;
use futures::future::join_all;
use slog::{error, info, Logger};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const NODES_COUNT: usize = 13;
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);
const SUCCESS_THRESHOLD: f64 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_DURATION: Duration = Duration::from_secs(5 * 60);
const DKG_INTERVAL: u64 = 999;
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

const INGRESS_BYTES_COUNT_METRIC: &str = "consensus_ingress_message_bytes_delivered_count";
const INGRESS_BYTES_SUM_METRIC: &str = "consensus_ingress_message_bytes_delivered_sum";
const INGRESS_MESSAGES_SUM_METRIC: &str = "consensus_ingress_messages_delivered_sum";

// Network parameters
const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(200); // artificial added latency
const NETWORK_SIMULATION: FixedNetworkSimulation = FixedNetworkSimulation::new()
    .with_latency(LATENCY)
    .with_bandwidth(BANDWIDTH_MBITS);

fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    env.sync_with_prometheus();

    let topology_snapshot = env.topology_snapshot();
    let (app_subnet, _) = get_app_subnet_and_node(&topology_snapshot);

    app_subnet.apply_network_settings(NETWORK_SIMULATION);
}

fn test(env: TestEnv, message_size: usize, rps: f64) {
    let log = env.logger();

    let canister_count: usize = 4;

    let app_node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();

    // create the runtime that lives until this variable is dropped.
    info!(
        env.logger(),
        "Set tokio runtime: worker_threads={}, blocking_threads={}",
        MAX_RUNTIME_THREADS,
        MAX_RUNTIME_BLOCKING_THREADS
    );
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();

    info!(
        log,
        "Step 1: Install {} canisters on the subnet..", canister_count
    );
    let mut canisters = Vec::new();
    let agent = rt.block_on(app_node.build_canister_agent());

    let nodes = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .collect::<Vec<_>>();
    let agents = rt.block_on(async {
        join_all(
            nodes
                .iter()
                .cloned()
                .map(|n| async move { n.build_canister_agent().await }),
        )
        .await
    });

    for _ in 0..canister_count {
        canisters.push(
            app_node.create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, /*arg=*/ None),
        );
    }
    info!(log, "{} canisters installed successfully.", canisters.len());

    info!(log, "Step 2: Instantiate and start the workload..");
    let payload: Vec<u8> = vec![0; message_size];
    let generator = {
        let (agents, canisters, payload) = (agents.clone(), canisters.clone(), payload.clone());
        move |idx: usize| {
            let (agents, canisters, payload) = (agents.clone(), canisters.clone(), payload.clone());
            async move {
                let (agents, canisters, payload) =
                    (agents.clone(), canisters.clone(), payload.clone());
                let request_outcome = canister_requests![
                    idx,
                    1 * agents[idx%agents.len()] => GenericRequest::new(canisters[0], "write".to_string(), payload.clone(), CallMode::UpdateNoPolling),
                    1 * agents[idx%agents.len()] => GenericRequest::new(canisters[1], "write".to_string(), payload.clone(), CallMode::UpdateNoPolling),
                    1 * agents[idx%agents.len()] => GenericRequest::new(canisters[2], "write".to_string(), payload.clone(), CallMode::UpdateNoPolling),
                    1 * agents[idx%agents.len()] => GenericRequest::new(canisters[3], "write".to_string(), payload.clone(), CallMode::UpdateNoPolling),
                ];
                request_outcome.into_test_outcome()
            }
        }
    };

    let consensus_metrics_before = rt.block_on(get_consensus_metrics(&nodes));
    let now = Instant::now();

    let metrics = rt.block_on(
        generic_workload_engine::engine::Engine::new(log.clone(), generator, rps, TEST_DURATION)
            .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
            .execute_simply(log.clone()),
    );

    let duration = now.elapsed();
    let consensus_metrics_after = rt.block_on(get_consensus_metrics(&nodes));

    let test_metrics = TestMetrics::compute(
        consensus_metrics_before,
        consensus_metrics_after,
        &metrics,
        duration,
    );

    info!(log, "Reporting workload execution results ...");
    env.emit_report(format!("{}", test_metrics));

    info!(
        log,
        "Step 3: Assert expected number of success update calls on each canister.."
    );
    let requests_count = rps * TEST_DURATION.as_secs_f64();
    let min_expected_success_calls = (SUCCESS_THRESHOLD * requests_count) as usize;
    info!(
        log,
        "Minimal expected number of success calls {}", min_expected_success_calls,
    );
    info!(
        log,
        "Number of success calls {}, failure calls {}",
        metrics.success_calls(),
        metrics.failure_calls()
    );

    let min_expected_canister_counter = min_expected_success_calls / canister_count;
    info!(
        log,
        "Minimal expected counter value on canisters {}", min_expected_canister_counter
    );
    for canister in canisters.iter() {
        rt.block_on(assert_canister_counter_with_retries(
            &log,
            &agent.get(),
            canister,
            payload.clone(),
            min_expected_canister_counter,
            MAX_RETRIES,
            RETRY_WAIT,
        ));
    }

    if cfg!(feature = "upload_perf_systest_results") {
        let branch_version = read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")
            .expect("tip-of-branch IC version");

        rt.block_on(persist_metrics(
            branch_version,
            test_metrics,
            message_size,
            rps,
            &log,
        ));
    }
}

#[derive(Copy, Clone)]
struct TestMetrics {
    success_rate: f64,
    blocks_per_second: f64,
    throughput_bytes_per_second: f64,
    throughput_messages_per_second: f64,
}

impl TestMetrics {
    fn compute(
        before: ConsensusMetrics,
        after: ConsensusMetrics,
        load_metrics: &LoadTestMetrics,
        duration: Duration,
    ) -> Self {
        let metrics_difference = after - before;
        let blocks_per_second = metrics_difference.delivered_blocks as f64 / duration.as_secs_f64();
        let throughput_bytes_per_second =
            metrics_difference.delivered_ingress_messages_bytes as f64 / duration.as_secs_f64();
        let throughput_messages_per_second =
            metrics_difference.delivered_ingress_messages as f64 / duration.as_secs_f64();

        Self {
            blocks_per_second,
            success_rate: (load_metrics.success_calls() as f64)
                / (load_metrics.total_calls() as f64),
            throughput_bytes_per_second,
            throughput_messages_per_second,
        }
    }
}

impl std::fmt::Display for TestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Success rate: {:.1}%", 100. * self.success_rate)?;
        writeln!(f, "Block rate: {:.1} blocks/s", self.blocks_per_second)?;
        write!(
            f,
            "Throughput: {:.1} MiB/s, {:.1} messages/s",
            self.throughput_bytes_per_second / (1024. * 1024.),
            self.throughput_messages_per_second
        )
    }
}

#[derive(Copy, Clone, Debug)]
struct ConsensusMetrics {
    delivered_blocks: u64,
    delivered_ingress_messages: u64,
    delivered_ingress_messages_bytes: u64,
}

impl std::ops::Sub for ConsensusMetrics {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            delivered_blocks: self.delivered_blocks - other.delivered_blocks,
            delivered_ingress_messages: self.delivered_ingress_messages
                - other.delivered_ingress_messages,
            delivered_ingress_messages_bytes: self.delivered_ingress_messages_bytes
                - other.delivered_ingress_messages_bytes,
        }
    }
}

async fn get_consensus_metrics(nodes: &[IcNodeSnapshot]) -> ConsensusMetrics {
    let fetcher = MetricsFetcher::new(
        nodes.iter().cloned(),
        vec![
            INGRESS_BYTES_COUNT_METRIC.to_string(),
            INGRESS_BYTES_SUM_METRIC.to_string(),
            INGRESS_MESSAGES_SUM_METRIC.to_string(),
        ],
    );

    let metrics = fetcher
        .fetch::<u64>()
        .await
        .expect("Should be able to fetch the metrics");

    let avg_blocks = average(&metrics[INGRESS_BYTES_COUNT_METRIC]);
    let avg_ingress_messages = average(&metrics[INGRESS_MESSAGES_SUM_METRIC]);
    let avg_ingress_bytes = average(&metrics[INGRESS_BYTES_SUM_METRIC]);

    ConsensusMetrics {
        delivered_blocks: avg_blocks,
        delivered_ingress_messages: avg_ingress_messages,
        delivered_ingress_messages_bytes: avg_ingress_bytes,
    }
}

async fn persist_metrics(
    ic_version: String,
    metrics: TestMetrics,
    message_size: usize,
    rps: f64,
    log: &Logger,
) {
    // elastic search url
    const ES_URL: &str =
        "https://elasticsearch.testnet.dfinity.network/ci-consensus-performance-test/_doc";

    let timestamp =
        chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).to_rfc3339();

    let json_report = serde_json::json!(
        {
            "benchmark_name": "consensus_performance_test",
            "timestamp": timestamp,
            "ic_version": ic_version,
            "benchmark_settings": {
                "message_size": message_size,
                "rps": rps,
            },
            "benchmark_results": {
                "success_rate": metrics.success_rate,
                "blocks_per_second": metrics.blocks_per_second,
                "throughput_bytes_per_second": metrics.throughput_bytes_per_second,
                "throughput_messages_per_second": metrics.throughput_messages_per_second,
            }
        }
    );

    info!(
        log,
        "Starting to upload performance test results to {ES_URL}: {}", json_report,
    );

    let client = reqwest::Client::new();
    let result = ic_system_test_driver::retry_with_msg_async!(
        "Uploading performance test results attempt",
        log,
        Duration::from_secs(5 * 60),
        Duration::from_secs(10),
        || async {
            client
                .post(ES_URL)
                .json(&json_report)
                .send()
                .await
                .map_err(Into::into)
        }
    )
    .await;

    match result {
        Ok(response) => {
            info!(
                log,
                "Successfully uploaded performance test results: {response:?}"
            );
        }
        Err(err) => {
            error!(
                log,
                "Failed to upload performance test results. Last error: {err}"
            )
        }
    }
}

fn average(nums: &[u64]) -> u64 {
    assert!(!nums.is_empty());

    nums.iter().sum::<u64>() / (nums.len() as u64)
}

fn test_small_messages(env: TestEnv) {
    test(env, 4_000, 500.0)
}

fn test_large_messages(env: TestEnv) {
    test(env, 950_000, 4.0)
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(systest!(test_small_messages))
        .add_test(systest!(test_large_messages))
        .execute_from_args()?;
    Ok(())
}
