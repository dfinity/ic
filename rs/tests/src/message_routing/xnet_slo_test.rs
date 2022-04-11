/* tag::catalog[]
Title:: XNet messaging functions within SLO.

Goal:: Ensure IC routes XNet traffic in a timely manner.

Runbook::
0. Instantiate an IC with SUBNETS applications subnets containing NODES_PER_SUBNET nodes each.
1. Build and install Xnet canisters on each subnet (number of canisters is calculated dynamically).
2. Start all canisters (via update `start` call).
3. Wait RUNTIME_SEC secs for canisters to exchange messages.
4. Stop sending messages for all canisters (via update `stop` call).
5. Collect metrics from all canisters (via query `metrics` call).
6. Aggregate metrics for each subnet (over its canisters).
7. Assert error_ratio < 5%, no seq_errors, send_rate >= 0.3, responses_received > threshold (calculated dynamically).
8. Stop/delete all canisters and assert operations' success.

Success::
1. Xnet canisters are successfully installed and started on each subnet.
2. Metrics collected for subnets are within the limits.

end::catalog[] */

use std::time::Duration;

use crate::driver::ic::{InternetComputer, Subnet};
use crate::util::{assert_endpoints_reachability, block_on, runtime_from_url, EndpointsStatus};
use canister_test::{Canister, Project, Runtime, Wasm};
use dfn_candid::candid;
use ic_fondue::{ic_manager::IcHandle, pot::FondueTestFn};
use ic_registry_subnet_type::SubnetType;
use slog::info;
use std::fmt::Display;
use tokio::time::sleep;
use xnet_test::{CanisterId, Metrics};

// Constants for all xnet tests.
const PAYLOAD_SIZE_BYTES: u64 = 1024;
/// Maximum messages a canister should send every round (in order to prevent it
/// filling up its output queue). This should be estimated as:
///
/// `queue_capacity / 10 /* max_rounds roundtrip */`
const MAX_CANISTER_TO_CANISTER_RATE: usize = 30;
const SEND_RATE_THRESHOLD: f64 = 0.3;
const ERROR_PERCENTAGE_THRESHOLD: f64 = 5.0;
const TARGETED_LATENCY_SECONDS: u64 = 20;

#[derive(Debug)]
pub struct Config {
    subnets: usize,
    nodes_per_subnet: usize,
    runtime: Duration,
    payload_size_bytes: u64,
    send_rate_threshold: f64,
    error_percentage_threshold: f64,
    targeted_latency_seconds: u64,
    subnet_to_subnet_rate: usize,
    canisters_per_subnet: usize,
    canister_to_subnet_rate: usize,
}

impl Config {
    fn new(subnets: usize, nodes_per_subnet: usize, runtime: Duration, rate: usize) -> Config {
        // Subnet-to-subnet request rate: ceil(rate / subnet_connections).
        let subnet_to_subnet_rate = (rate - 1) / (subnets - 1) + 1;
        // Minimum number of subnet-to-subnet queues needed to stay under
        // `max_canister_to_canister_rate`.
        let subnet_to_subnet_queues =
            (subnet_to_subnet_rate - 1) / MAX_CANISTER_TO_CANISTER_RATE + 1;
        // Minimum number of canisters required to send `subnet_to_subnet_rate` requests
        // per round.
        let canisters_per_subnet = (subnet_to_subnet_queues as f64).sqrt().ceil() as usize;
        // A canister's outbound request rate to a given subnet.
        let canister_to_subnet_rate = (subnet_to_subnet_rate - 1) / canisters_per_subnet + 1;

        Config {
            subnets,
            nodes_per_subnet,
            runtime,
            payload_size_bytes: PAYLOAD_SIZE_BYTES,
            send_rate_threshold: SEND_RATE_THRESHOLD,
            error_percentage_threshold: ERROR_PERCENTAGE_THRESHOLD,
            targeted_latency_seconds: TARGETED_LATENCY_SECONDS,
            subnet_to_subnet_rate,
            canisters_per_subnet,
            canister_to_subnet_rate,
        }
    }

    /// Builds the IC instance.
    pub fn build(&self) -> InternetComputer {
        (0..self.subnets).fold(InternetComputer::new(), |ic, _idx| {
            ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(self.nodes_per_subnet))
        })
    }

    /// Returns a test function based on this configuration.
    pub fn test(self) -> impl FondueTestFn<IcHandle> {
        move |handle: IcHandle, ctx: &ic_fondue::pot::Context| test(handle, ctx, self)
    }
}

pub fn config_nightly_3_subnets() -> Config {
    Config::new(3, 4, Duration::from_secs(600), 10)
}

pub fn config_nightly_29_subnets() -> Config {
    Config::new(29, 1, Duration::from_secs(600), 10)
}

pub fn config_prod_slo_3_subnets() -> Config {
    Config::new(3, 4, Duration::from_secs(1200), 10)
}

pub fn config_prod_slo_29_subnets() -> Config {
    Config::new(29, 1, Duration::from_secs(1200), 10)
}

pub fn config_hotfix_slo_3_subnets() -> Config {
    Config::new(3, 4, Duration::from_secs(120), 10)
}

// Generic test
pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context, config: Config) {
    info!(ctx.logger, "Config for the test: {:?}", config);
    let mut rng = ctx.rng.clone();
    let mut endpoints = handle.as_permutation(&mut rng).collect::<Vec<_>>();
    assert_eq!(endpoints.len(), config.subnets * config.nodes_per_subnet);
    // Assert all nodes are reachable after IC setup.
    block_on(assert_endpoints_reachability(
        endpoints.as_slice(),
        EndpointsStatus::AllReachable,
    ));
    info!(
        ctx.logger,
        "IC setup succeeded, all status endpoints are reachable over http."
    );
    // Installing canisters on a subnet requires an Agent (or a Runtime wrapper around Agent).
    // We need only one endpoint per subnet for canister installation.
    endpoints.sort_by_key(|key| key.subnet_id().unwrap());
    endpoints.dedup_by_key(|key| key.subnet_id().unwrap());
    assert_eq!(
        endpoints.len(),
        config.subnets,
        "Selecting unique endpoints based on subnet_id failed."
    );
    // All elements are related to subnets with different ids.
    let endpoints_runtime = endpoints
        .iter()
        .map(|ep| runtime_from_url(ep.url.clone()))
        .collect::<Vec<_>>();
    assert_eq!(endpoints_runtime.len(), config.subnets);
    // Step 1: Build and install Xnet canisters on each subnet.
    info!(ctx.logger, "Building Xnet canister wasm...");
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "rust_canisters/xnet_test",
        "xnet-test-canister",
        &[],
    );
    info!(ctx.logger, "Installing Xnet canisters on subnets ...");
    let canisters = install_canisters(
        &endpoints_runtime,
        config.subnets,
        config.canisters_per_subnet,
        wasm,
    );
    let canisters_count = canisters.iter().map(Vec::len).sum::<usize>();
    assert_eq!(
        canisters_count,
        config.subnets * config.canisters_per_subnet
    );
    info!(
        ctx.logger,
        "All {} canisters installed successfully.", canisters_count
    );
    // Step 2: Start all canisters (via update `start` call).
    info!(ctx.logger, "Calling start() on all canisters...");
    start_all_canisters(
        &canisters,
        config.payload_size_bytes,
        config.canister_to_subnet_rate as u64,
    );
    let msgs_per_round =
        config.canister_to_subnet_rate * config.canisters_per_subnet * (config.subnets - 1);
    info!(
        ctx.logger,
        "Starting chatter: {} messages/round * {} bytes = {} bytes/round",
        msgs_per_round,
        config.payload_size_bytes,
        msgs_per_round * config.payload_size_bytes as usize
    );
    // Step 3: Wait for canisters to exchange messages.
    info!(
        ctx.logger,
        "Sending messages for {} secs...",
        config.runtime.as_secs()
    );
    block_on(async {
        sleep(Duration::from_secs(config.runtime.as_secs())).await;
    });
    // Step 4: Stop all canisters (via update `stop` call).
    info!(ctx.logger, "Stopping all canisters...");
    stop_all_canister(&canisters);
    // Step 5: Collect metrics from all canisters (via query `metrics` call).
    info!(ctx.logger, "Collecting metrics from all canisters...");
    let metrics = collect_metrics(&canisters);
    // Step 6: Aggregate metrics for each subnet (over its canisters).
    info!(ctx.logger, "Aggregating metrics for each subnet...");
    let mut aggregated_metrics = Vec::<Metrics>::new();
    for (subnet_idx, subnet_metrics) in metrics.iter().enumerate() {
        let mut merged_metric = Metrics::default();
        for (canister_idx, canister_metric) in subnet_metrics.iter().enumerate() {
            info!(
                ctx.logger,
                "Metrics for subnet {}, canister {}: {:?}",
                subnet_idx,
                canister_idx,
                canister_metric
            );
            merged_metric.merge(canister_metric);
        }
        aggregated_metrics.push(merged_metric);
        info!(
            ctx.logger,
            "Aggregated metrics for subnet {}: {:?}",
            subnet_idx,
            aggregated_metrics.last()
        );
    }
    // Step 7. Assert metric are within limits.
    info!(ctx.logger, "Asserting metrics are within limits...");
    let mut success = true;
    let mut expect =
        |cond: bool, subnet: usize, ok_msg: &str, fail_msg: &str, val: &dyn Display| {
            success &= cond;
            info!(
                ctx.logger,
                "Subnet {}: {} {}: {}",
                subnet,
                if cond { "Success:" } else { "Failure:" },
                if cond { ok_msg } else { fail_msg },
                val,
            );
        };

    for (i, m) in aggregated_metrics.iter().enumerate() {
        let attempted_calls = m.requests_sent + m.call_errors;
        if attempted_calls != 0 {
            let failed_calls = m.call_errors + m.reject_responses;
            let error_percentage = 100. * failed_calls as f64 / attempted_calls as f64;
            expect(
                error_percentage < config.error_percentage_threshold,
                i,
                format!("Error ratio below {}%", config.error_percentage_threshold).as_str(),
                "Failed calls",
                &format!(
                    "{}% ({}/{})",
                    error_percentage, failed_calls, attempted_calls
                ),
            );
        }

        expect(
            m.seq_errors == 0,
            i,
            "Sequence errors",
            "Sequence errors",
            &m.seq_errors,
        );

        let send_rate = attempted_calls as f64
            / (config.subnets - 1) as f64
            / config.runtime.as_secs() as f64
            / config.canisters_per_subnet as f64
            / config.canister_to_subnet_rate as f64;
        expect(
            send_rate >= config.send_rate_threshold,
            i,
            format!("Send rate at least {}", config.send_rate_threshold).as_str(),
            format!("Send rate below {}", config.send_rate_threshold).as_str(),
            &send_rate,
        );

        // Successful plus reject responses.
        let responses_received =
            m.latency_distribution.buckets().last().unwrap().1 + m.reject_responses;
        // All messages sent more than `targeted_latency_seconds` before the end of the
        // test should have gotten a response.
        let responses_expected = (m.requests_sent as f64
            * (config.runtime.as_secs() - config.targeted_latency_seconds) as f64
            / config.runtime.as_secs() as f64) as usize;
        // Account for requests enqueued this round (in case canister messages were
        // executed before ingress messages, i.e. the heartbeat was executed before
        // metrics collection) or uncounted responses (if ingress executed first).
        info!(
            ctx.logger,
            "responses_expected={} subnet_to_subnet_rate={}, responses_received={}",
            responses_expected,
            config.subnet_to_subnet_rate,
            responses_received
        );
        let responses_expected = responses_expected - config.subnet_to_subnet_rate;
        let actual = format!("{}/{}", responses_received, m.requests_sent);
        let msg = format!(
            "Expected requests sent more than {}s ago ({}/{}) to receive responses",
            config.targeted_latency_seconds, responses_expected, m.requests_sent
        );
        expect(
            responses_received >= responses_expected,
            i,
            &msg,
            &msg,
            &actual,
        );

        if responses_received != 0 {
            let avg_latency_millis = m.latency_distribution.sum_millis() / responses_received;
            expect(
                avg_latency_millis <= config.targeted_latency_seconds as usize * 1000,
                i,
                &format!(
                    "Mean response latency less than {}s",
                    config.targeted_latency_seconds
                ),
                &format!(
                    "Mean response latency was more than {}s",
                    config.targeted_latency_seconds
                ),
                &(avg_latency_millis as f64 * 1e-3),
            );
        }
    }
    // Step 8: Stop/delete all canisters.
    info!(ctx.logger, "Stop/delete all canisters...");
    block_on(async {
        for canister in canisters.iter().flatten() {
            canister.stop().await.expect("Stopping canister failed.");
            canister.delete().await.expect("Deleting canister failed.");
        }
    });
    assert!(success, "Test failed.");
}

pub fn start_all_canisters(
    canisters: &[Vec<Canister>],
    payload_size_bytes: u64,
    canister_to_subnet_rate: u64,
) {
    let topology: Vec<Vec<CanisterId>> = canisters
        .iter()
        .map(|x| x.iter().map(|y| y.canister_id_vec8()).collect())
        .collect();
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            let input = (&topology, canister_to_subnet_rate, payload_size_bytes);
            let _: String = canister
                .update_("start", candid, input)
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Starting canister_idx={} on subnet_idx={} failed.",
                        canister_idx, subnet_idx
                    )
                });
        }
    });
}

pub fn stop_all_canister(canisters: &[Vec<Canister>]) {
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            let _: String = canister
                .update_("stop", candid, ())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Stopping canister_idx={} on subnet_idx={} failed.",
                        canister_idx, subnet_idx
                    )
                });
        }
    });
}

pub fn collect_metrics(canisters: &[Vec<Canister>]) -> Vec<Vec<Metrics>> {
    let mut metrics: Vec<Vec<Metrics>> = Vec::new();
    block_on(async {
        for (subnet_idx, canister_idx, canister) in canisters
            .iter()
            .enumerate()
            .flat_map(|(x, v)| v.iter().enumerate().map(move |(y, v)| (x, y, v)))
        {
            if canister_idx == 0 {
                metrics.push(vec![]);
            }
            let result = canister
                .query_("metrics", candid, ())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Collecting metrics for canister_idx={} on subnet_idx={} failed.",
                        canister_idx, subnet_idx
                    )
                });
            metrics[subnet_idx].push(result);
        }
    });
    metrics
}

pub fn install_canisters(
    endpoints_runtime: &[Runtime],
    subnets: usize,
    canisters_per_subnet: usize,
    wasm: Wasm,
) -> Vec<Vec<Canister>> {
    let mut canisters: Vec<Vec<Canister>> = Vec::new();
    block_on(async {
        for subnet_idx in 0..subnets {
            canisters.push(vec![]);
            for canister_idx in 0..canisters_per_subnet {
                let canister = wasm
                    .clone()
                    .install_(&endpoints_runtime[subnet_idx], vec![])
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "Installation of the canister_idx={} on subnet_idx={} failed.",
                            canister_idx, subnet_idx
                        )
                    });
                canisters[subnet_idx].push(canister);
            }
        }
    });
    canisters
}
