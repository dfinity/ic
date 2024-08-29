use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::canister_api::{CallMode, GenericRequest};
use ic_system_test_driver::canister_requests;
use ic_system_test_driver::driver::test_env_api::IcNodeSnapshot;
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{read_dependency_from_env_to_string, HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::generic_workload_engine;
use ic_system_test_driver::generic_workload_engine::metrics::{
    LoadTestMetrics, LoadTestMetricsProvider, RequestOutcome,
};
use ic_system_test_driver::util::{assert_canister_counter_with_retries, MetricsFetcher};

use futures::future::join_all;
use slog::{error, info, Logger};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Handle, Runtime};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const MAX_RETRIES: u32 = 10;
const RETRY_WAIT: Duration = Duration::from_secs(10);
const SUCCESS_THRESHOLD: f64 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_DURATION: Duration = Duration::from_secs(5 * 60);
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

const INGRESS_BYTES_COUNT_METRIC: &str = "consensus_ingress_message_bytes_delivered_count";
const INGRESS_BYTES_SUM_METRIC: &str = "consensus_ingress_message_bytes_delivered_sum";
const INGRESS_MESSAGES_SUM_METRIC: &str = "consensus_ingress_messages_delivered_sum";

pub fn test(env: TestEnv, message_size: usize, rps: f64) {
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

    test_with_rt_handle(env, message_size, rps, rt.handle().clone(), true).unwrap();
}
pub fn test_with_rt_handle(
    env: TestEnv,
    message_size: usize,
    rps: f64,
    rt: Handle,
    report: bool,
) -> anyhow::Result<()> {
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
    if report {
        env.emit_report(format!("{}", test_metrics));
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

    if cfg!(feature = "upload_perf_systest_results") && report {
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

    Ok(())
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
