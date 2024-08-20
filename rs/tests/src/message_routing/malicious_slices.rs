/* tag::catalog[]
Title:: XNet messaging rejects invalid slices.

Goal:: Ensure IC doesn't accept obviously invalid signatures on XNet streams.

Runbook::
0. Instantiate an IC with 2 application subnets containing one node each. Enable
   the malicious flag `maliciously_alter_root_hash` which should lead to slice
   validation failing and no XNet messages being inducted.
1. Install Xnet canisters on each subnet.
2. Start all canisters (via update `start` call).
3. Wait for RUNTIME_SEC secs for canisters to exchange messages.
4. Fetch metrics and verify whether there were no successful signature validation
   and there are some logged failures.

Success::
1. There is no accepted XNet slice according to the metrics
2. There are > 5 hash mismatches and > 5 signature validation failures
3. The inducted payload bytes corresponding to XNet messages is 0

end::catalog[] */

use super::common::{install_canisters, start_all_canisters};
use canister_test::Runtime;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot,
};
use ic_system_test_driver::util::{block_on, runtime_from_url, MetricsFetcher};
use ic_types::malicious_behaviour::MaliciousBehaviour;
use slog::info;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    subnets: usize,
    nodes_per_subnet: usize,
    runtime: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Config {
        Config {
            subnets: 2,
            nodes_per_subnet: 1,
            runtime: Duration::from_secs(30),
        }
    }

    /// Builds the IC instance.
    pub fn build(self) -> impl PotSetupFn {
        move |env: TestEnv| {
            setup(
                env,
                self,
                MaliciousBehaviour::new(true).set_maliciously_alter_certified_hash(),
            )
        }
    }

    /// Returns a test function based on this configuration.
    pub fn test(self) -> impl SysTestFn {
        move |env: TestEnv| test(env, self)
    }
}

// Generic setup
fn setup(env: TestEnv, config: Config, malicious_behavior: MaliciousBehaviour) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
    (0..config.subnets)
        .fold(InternetComputer::new(), |ic, _idx| {
            ic.add_subnet(
                Subnet::new(SubnetType::Application)
                    .add_malicious_nodes(config.nodes_per_subnet, malicious_behavior.clone()),
            )
        })
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    env.sync_with_prometheus();
}

pub fn test(env: TestEnv, config: Config) {
    block_on(test_async(env, config));
}

// Generic test
pub async fn test_async(env: TestEnv, config: Config) {
    let logger = env.logger();
    info!(logger, "Config for the test: {:?}", config);
    let topology = env.topology_snapshot();

    // Installing canisters on a subnet requires an Agent (or a Runtime wrapper around Agent).
    // We need only one agent (runtime) per subnet for canister installation.
    let endpoints_runtime: Vec<Runtime> = topology
        .subnets()
        .map(|s| {
            let node = s.nodes().next().unwrap();
            runtime_from_url(node.get_public_url(), node.effective_canister_id())
        })
        .collect();

    assert_eq!(endpoints_runtime.len(), config.subnets);
    // Install Xnet canisters on each subnet.
    info!(logger, "Installing Xnet canisters on subnets ...");
    let canisters = install_canisters(
        env.clone(),
        &endpoints_runtime,
        config.subnets,
        1, // Number of canisters per subnet
    )
    .await;
    let canisters_count = canisters.iter().flatten().count();
    assert_eq!(canisters_count, config.subnets);
    info!(
        logger,
        "All {} canisters installed successfully.", canisters_count
    );
    // Start all canisters (via update `start` call).
    info!(logger, "Calling start() on all canisters...");
    start_all_canisters(
        &canisters, 1024, // send messages with 1024 byte payloads
        10,   // each canister sends 10 RPS
    )
    .await;
    info!(logger, "Starting chatter: 10 messages/round * 1024 bytes",);

    info!(logger, "Sleeping {} seconds.", config.runtime.as_secs());
    tokio::time::sleep(Duration::from_secs(config.runtime.as_secs())).await;

    for (index, subnet) in env.topology_snapshot().subnets().enumerate() {
        println!("Collecting metrics for subnet {}.", index);
        fetch_metrics_and_assert(&env, subnet).await;
    }
}

async fn fetch_metrics_and_assert(env: &TestEnv, subnet: SubnetSnapshot) {
    const NUM_RETRIES: u32 = 200;
    const BACKOFF_TIME_MILLIS: u64 = 500;

    const SIG_FAIL: &str = "state_manager_decode_slice{op=\"verify\",status=\"failure\"}";
    const SIG_SUCC: &str = "state_manager_decode_slice{op=\"verify\",status=\"success\"}";
    const HASH_FAIL: &str = "state_manager_decode_slice{op=\"compare\",status=\"failure\"}";
    const HASH_SUCC: &str = "state_manager_decode_slice{op=\"compare\",status=\"success\"}";
    const MR_INDUCTED_XNET_PAYLOAD_SIZE: &str = "mr_inducted_xnet_payload_size_bytes_sum";

    let metrics = MetricsFetcher::new(
        subnet.nodes(),
        vec![
            SIG_FAIL.into(),
            SIG_SUCC.into(),
            HASH_FAIL.into(),
            HASH_SUCC.into(),
            MR_INDUCTED_XNET_PAYLOAD_SIZE.into(),
        ],
    );
    for _ in 0..NUM_RETRIES {
        match metrics.fetch::<u64>().await {
            Ok(result) => {
                if !(result.contains_key(SIG_SUCC)
                    && result.contains_key(SIG_FAIL)
                    && result.contains_key(HASH_SUCC)
                    && result.contains_key(HASH_FAIL)
                    && result.contains_key(MR_INDUCTED_XNET_PAYLOAD_SIZE))
                {
                    info!(env.logger(), "Metrics not available yet.");
                } else {
                    assert_eq!(
                        result[SIG_SUCC][0], 0,
                        "Unexpectedly saw {} accepted slice signatures.",
                        result[SIG_SUCC][0]
                    );
                    assert_eq!(
                        result[HASH_SUCC][0], 0,
                        "Unexpectedly saw {} hash matches.",
                        result[HASH_SUCC][0]
                    );
                    assert_eq!(
                        result[MR_INDUCTED_XNET_PAYLOAD_SIZE][0], 0,
                        "Unexpectedly saw {} XNet payload bytes inducted.",
                        result[MR_INDUCTED_XNET_PAYLOAD_SIZE][0]
                    );
                    if result[SIG_FAIL][0] > 5 && result[HASH_FAIL][0] > 5 {
                        info!(
                            env.logger(),
                            "{} slice signatures accepted/{} rejected.",
                            result[SIG_SUCC][0],
                            result[SIG_FAIL][0]
                        );
                        info!(
                            env.logger(),
                            "{} hash matches/{} hash mismatches.",
                            result[HASH_SUCC][0],
                            result[HASH_FAIL][0]
                        );
                        info!(
                            env.logger(),
                            "{} XNet payload bytes inducted.",
                            result[MR_INDUCTED_XNET_PAYLOAD_SIZE][0]
                        );
                        info!(env.logger(), "Success!");
                        // Success we can return.
                        return;
                    } else {
                        info!(
                            env.logger(),
                            "Not seen enough failed signature/hash checks yet. \
                            Failed signatures verifications {}. \
                            Mismatched hashes {}.",
                            result[SIG_FAIL][0],
                            result[HASH_FAIL][0]
                        );
                    }
                }
            }
            Err(e) => {
                info!(env.logger(), "Could not scrape metrics: {}.", e);
            }
        }
        std::thread::sleep(Duration::from_millis(BACKOFF_TIME_MILLIS));
    }
    panic!("Couldn't obtain metrics after 200 attempts.");
}
