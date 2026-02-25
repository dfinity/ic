use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_api::{CallMode, GenericRequest};
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmResources};
use ic_system_test_driver::driver::test_env_api::{IcNodeSnapshot, get_dependency_path_from_env};
use ic_system_test_driver::driver::universal_vm::{UniversalVm, UniversalVms};
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::generic_workload_engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetrics, LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::util::{MetricsFetcher, assert_canister_counter_with_retries};
use ic_types::ReplicaVersion;

use futures::future::join_all;
use slog::{Logger, error, info};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;

const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);
const SUCCESS_THRESHOLD: f64 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_DURATION: Duration = Duration::from_secs(5 * 60);

const INGRESS_BYTES_COUNT_METRIC: &str = "consensus_ingress_message_bytes_delivered_count";
const INGRESS_BYTES_SUM_METRIC: &str = "consensus_ingress_message_bytes_delivered_sum";
const INGRESS_MESSAGES_SUM_METRIC: &str = "consensus_ingress_messages_delivered_sum";
const INGRESS_MESSAGE_E2E_LATENCY_METRICS: &str =
    "replica_http_ingress_watcher_wait_for_certification_duration_seconds";
const TIME_TO_RECEIVE_BLOCK_METRICS: &str = "consensus_time_to_receive_block";
const CONSENSUS_GET_PAYLOAD_DURATION_METRICS: &str = "consensus_get_payload_duration_seconds";
const CONSENSUS_VALIDATE_PAYLOAD_DURTION_METRICS: &str =
    "consensus_validate_payload_duration_seconds";
const BLOCK_ASSEMBLY_DURATION_METRICS: &str =
    "ic_stripped_consensus_artifact_total_block_assembly_duration";
const HISTOGRAM_METRICS: &[&str; 4] = &[
    CONSENSUS_GET_PAYLOAD_DURATION_METRICS,
    INGRESS_MESSAGE_E2E_LATENCY_METRICS,
    CONSENSUS_VALIDATE_PAYLOAD_DURTION_METRICS,
    BLOCK_ASSEMBLY_DURATION_METRICS,
];

pub fn test_with_rt_handle(
    env: TestEnv,
    message_size: usize,
    rps: f64,
    rt: Handle,
    report: bool,
) -> anyhow::Result<TestMetrics> {
    let log = env.logger();

    let canister_count: usize = 4;

    let subnet = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .ok_or(anyhow::anyhow!("Failed to find an application subnet"))?;
    let app_node = subnet
        .nodes()
        .next()
        .ok_or(anyhow::anyhow!("Subnet doesn't have any hodes"))?;

    info!(
        log,
        "Step 1: Install {} canisters on the subnet..", canister_count
    );
    let mut canisters = Vec::new();
    let agent = rt.block_on(app_node.build_canister_agent());

    let nodes = subnet.nodes().collect::<Vec<_>>();
    let agents = rt.block_on(async {
        join_all(
            nodes
                .iter()
                .map(|n| async move { n.build_canister_agent().await }),
        )
        .await
    });

    for _ in 0..canister_count {
        canisters.push(app_node.create_and_install_canister_with_arg(
            &std::env::var("COUNTER_CANISTER_WAT_PATH").unwrap(),
            /*arg=*/ None,
        ));
    }
    info!(log, "{} canisters installed successfully.", canisters.len());

    info!(log, "Sleeping for 60 seconds");
    std::thread::sleep(Duration::from_secs(60));

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
    if report {
        env.emit_report(format!("{test_metrics}"));
    } else {
        info!(log, "{}", test_metrics);
    }

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

    Ok(test_metrics)
}

#[derive(Copy, Clone)]
pub struct TestMetrics {
    success_rate: f64,
    blocks_per_second: f64,
    throughput_bytes_per_second: f64,
    throughput_messages_per_second: f64,
    average_e2e_latency: f64,
    average_time_to_receive_block: f64,
    average_payload_creation_duration_seconds: f64,
    average_payload_validation_duration_seconds: f64,
    average_block_assembly_duration_seconds: f64,
}

impl TestMetrics {
    fn compute(
        before: ConsensusMetrics,
        after: ConsensusMetrics,
        load_metrics: &LoadTestMetrics,
        duration: Duration,
    ) -> Self {
        let metrics_difference = after - before;

        Self {
            blocks_per_second: metrics_difference.delivered_blocks as f64 / duration.as_secs_f64(),
            success_rate: (load_metrics.success_calls() as f64)
                / (load_metrics.total_calls() as f64),
            throughput_bytes_per_second: metrics_difference.delivered_ingress_messages_bytes as f64
                / duration.as_secs_f64(),
            throughput_messages_per_second: metrics_difference.delivered_ingress_messages as f64
                / duration.as_secs_f64(),
            average_time_to_receive_block: metrics_difference.time_to_receive_block.average(),
            average_e2e_latency: metrics_difference.histogram_metrics
                [INGRESS_MESSAGE_E2E_LATENCY_METRICS]
                .average(),
            average_payload_creation_duration_seconds: metrics_difference.histogram_metrics
                [CONSENSUS_GET_PAYLOAD_DURATION_METRICS]
                .average(),
            average_payload_validation_duration_seconds: metrics_difference.histogram_metrics
                [CONSENSUS_VALIDATE_PAYLOAD_DURTION_METRICS]
                .average(),
            average_block_assembly_duration_seconds: metrics_difference.histogram_metrics
                [BLOCK_ASSEMBLY_DURATION_METRICS]
                .average(),
        }
    }
}

impl std::fmt::Display for TestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Success rate: {:.1}%", 100. * self.success_rate)?;
        writeln!(f, "Block rate: {:.2} blocks/s", self.blocks_per_second)?;
        writeln!(
            f,
            "Throughput: {:.1} MiB/s, {:.2} messages/s",
            self.throughput_bytes_per_second / (1024. * 1024.),
            self.throughput_messages_per_second
        )?;
        writeln!(
            f,
            "Average time to receive a rank 0 block: {:.2}s",
            self.average_time_to_receive_block
        )?;
        write!(
            f,
            "Avarage E2E ingress message latency: {:.2}s",
            self.average_e2e_latency
        )?;
        write!(
            f,
            "Avarage time to create a block payload: {:.2}s",
            self.average_payload_creation_duration_seconds
        )?;
        write!(
            f,
            "Avarage time to validate a block payload: {:.2}s",
            self.average_payload_validation_duration_seconds
        )?;
        write!(
            f,
            "Avarage time to assemble a block proposal: {:.2}s",
            self.average_block_assembly_duration_seconds,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ConsensusMetrics {
    delivered_blocks: u64,
    delivered_ingress_messages: u64,
    delivered_ingress_messages_bytes: u64,
    time_to_receive_block: HistogramMetrics,
    histogram_metrics: BTreeMap</*name=*/ &'static str, HistogramMetrics>,
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
            time_to_receive_block: self.time_to_receive_block - other.time_to_receive_block,
            histogram_metrics: self
                .histogram_metrics
                .into_iter()
                .map(|(name, metrics)| {
                    (
                        name,
                        metrics
                            - other
                                .histogram_metrics
                                .get(&name)
                                .cloned()
                                .unwrap_or_default(),
                    )
                })
                .collect(),
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
    let time_to_receive_block =
        HistogramMetrics::fetch(TIME_TO_RECEIVE_BLOCK_METRICS, Some("rank=\"0\""), nodes).await;

    let mut histogram_metrics = BTreeMap::new();

    for metric_name in HISTOGRAM_METRICS {
        let metric = HistogramMetrics::fetch(metric_name, None, nodes).await;

        histogram_metrics.insert(*metric_name, metric);
    }

    ConsensusMetrics {
        delivered_blocks: avg_blocks,
        delivered_ingress_messages: avg_ingress_messages,
        delivered_ingress_messages_bytes: avg_ingress_bytes,
        time_to_receive_block,
        histogram_metrics,
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct HistogramMetrics {
    sum: f64,
    count: f64,
}

impl HistogramMetrics {
    async fn fetch(metrics_name: &str, filter: Option<&str>, nodes: &[IcNodeSnapshot]) -> Self {
        let (metrics_sum, metrics_count) = if let Some(filter) = filter {
            (
                format!("{metrics_name}_sum{{{filter}}}"),
                format!("{metrics_name}_count{{{filter}}}"),
            )
        } else {
            (
                format!("{metrics_name}_sum"),
                format!("{metrics_name}_count"),
            )
        };

        let fetcher = MetricsFetcher::new(
            nodes.iter().cloned(),
            vec![metrics_sum.clone(), metrics_count.clone()],
        );

        let metrics = fetcher
            .fetch::<f64>()
            .await
            .expect("Should be able to fetch the metrics");

        Self {
            sum: average_f64(&metrics[&metrics_sum]),
            count: average_f64(&metrics[&metrics_count]),
        }
    }

    fn average(&self) -> f64 {
        self.sum / self.count
    }
}

impl std::ops::Sub for HistogramMetrics {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            sum: self.sum - other.sum,
            count: self.count - other.count,
        }
    }
}

pub async fn persist_metrics(
    ic_version: ReplicaVersion,
    metrics: TestMetrics,
    message_size: usize,
    rps: f64,
    latency: Duration,
    bandwidth_bits_per_seconds: u32,
    subnet_size: usize,
    max_ingress_bytes_per_block: Option<u64>, // None means the default value
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
                "latency_seconds": latency.as_secs_f64(),
                "bandwith_bits_per_second": bandwidth_bits_per_seconds,
                "subnet_size": subnet_size,
                "max_ingress_bytse_per_block": max_ingress_bytes_per_block.unwrap_or(ic_limits::MAX_INGRESS_BYTES_PER_BLOCK),
            },
            "benchmark_results": {
                "success_rate": metrics.success_rate,
                "blocks_per_second": metrics.blocks_per_second,
                "throughput_bytes_per_second": metrics.throughput_bytes_per_second,
                "throughput_messages_per_second": metrics.throughput_messages_per_second,
                "average_e2e_latency": metrics.average_e2e_latency,
                "average_time_to_receive_block": metrics.average_time_to_receive_block,
                "average_payload_creation_duration_seconds": metrics.average_payload_creation_duration_seconds,
                "average_payload_validation_duration_seconds": metrics.average_payload_validation_duration_seconds,
                "average_block_assembly_duration_seconds": metrics.average_block_assembly_duration_seconds,
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

fn average_f64(nums: &[f64]) -> f64 {
    assert!(!nums.is_empty());

    nums.iter().sum::<f64>() / (nums.len() as f64)
}

pub fn setup_jaeger_vm(env: &TestEnv) -> std::net::Ipv6Addr {
    const JAEGER_VM_NAME: &str = "jaeger-vm";

    let path = get_dependency_path_from_env("JAEGER_UVM_CONFIG_IMAGE_ZST");
    UniversalVm::new(JAEGER_VM_NAME.to_string())
        .with_required_host_features(vec![HostFeature::Performance])
        .with_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(16)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(1024)),
        })
        .with_config_img(path)
        .start(env)
        .expect("failed to setup Jaeger Universal VM");

    let deployed_jaeger_vm = env.get_deployed_universal_vm(JAEGER_VM_NAME).unwrap();
    let jaeger_vm = deployed_jaeger_vm.get_vm().unwrap();
    let jaeger_ipv6 = jaeger_vm.ipv6;

    info!(
        env.logger(),
        "Jaeger frontend available at: http://[{}]:16686", jaeger_ipv6
    );

    jaeger_ipv6
}
