/* tag::catalog[]
Title:: Subnet makes progress despite one third of the nodes being stressed.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install one counter canister on each subnet.
3. Instantiate and start one workload per subnet using a subset of 1/3 of the nodes as targets.
   Workloads send update[canister_id, "write"] requests.
   Requests are equally distributed between this subset of 1/3 nodes.
4. Stress (modify tc settings on) another disjoint subset of 1/3 of the nodes (during the workload execution).
   Stressing manifests in introducing randomness in: latency, bandwidth, packet drops percentage, stress duration.
5. Collect metrics from both workloads and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
6. Perform assertions for both counter canisters (via query `read` call)
   - Counter value on the canisters should exceed the threshold = (1 - max_failures_ratio) * total_requests_count.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsInstallationExt,
    SshSession, ADMIN, DEVICE_NAME,
};
use crate::util::{self, block_on};
use crate::workload::{CallSpec, Metrics, Request, RoundRobinPlan, Workload};
use ic_agent::{export::Principal, Agent};
use ic_base_types::NodeId;
use ic_registry_subnet_type::SubnetType;
use rand::distributions::{Distribution, Uniform};
use rand_chacha::ChaCha8Rng;
use slog::{debug, info, Logger};
use ssh2::Session;
use std::cmp::{max, min};
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const COUNTER_CANISTER_WAT: &str = "counter.wat";
const CANISTER_METHOD: &str = "write";
// Seed for random generator
const RND_SEED: u64 = 42;
// Size of the payload sent to the counter canister in update("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(5);
// Ratio of requests with duration < DURATION_THRESHOLD should exceed this parameter.
const MIN_REQUESTS_RATIO_BELOW_THRESHOLD: f64 = 0.9;
// Parameters related to nodes stressing.
const BANDWIDTH_MIN: u32 = 10;
const BANDWIDTH_MAX: u32 = 100;
const LATENCY_MIN: Duration = Duration::from_millis(10);
const LATENCY_MAX: Duration = Duration::from_millis(990);
const DROPS_PERC_MIN: u32 = 1;
const DROPS_PERC_MAX: u32 = 99;
const MIN_NODE_STRESS_TIME: Duration = Duration::from_secs(10);
const MIN_NODE_UNSTRESSED_TIME: Duration = Duration::ZERO;
const FRACTION_FROM_REMAINING_DURATION: f64 = 0.25;
// Parameters related to reading/asserting counter values of the canisters.
const MAX_CANISTER_READ_RETRIES: u32 = 4;
const CANISTER_READ_RETRY_WAIT: Duration = Duration::from_secs(10);
// Parameters related to workload creation.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(30); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::ZERO; // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Test can be run with different setup/configuration parameters.
// This config holds these parameters.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    nodes_system_subnet: usize,
    nodes_app_subnet: usize,
    runtime: Duration,
    rps: usize,
    max_failures_ratio: f64,
}

impl Config {
    /// Builds the IC instance.
    pub fn build(&self) -> impl FnOnce(TestEnv) {
        let config = *self;
        move |env: TestEnv| Config::config(env, config)
    }

    fn config(env: TestEnv, config: Config) {
        InternetComputer::new()
            .add_subnet(Subnet::new(SubnetType::System).add_nodes(config.nodes_system_subnet))
            .add_subnet(Subnet::new(SubnetType::Application).add_nodes(config.nodes_app_subnet))
            .setup_and_start(&env)
            .expect("Failed to setup IC under test.");
    }

    /// Returns a test function based on the configuration.
    pub fn test(self) -> impl Fn(TestEnv) {
        move |env: TestEnv| test(env, self)
    }
}

pub fn config_sys_4_nodes_app_4_nodes() -> Config {
    Config {
        nodes_app_subnet: 4,
        nodes_system_subnet: 4,
        rps: 100,
        runtime: Duration::from_secs(180),
        max_failures_ratio: 0.05,
    }
}

pub fn test(env: TestEnv, config: Config) {
    let log = env.logger();
    info!(
        &log,
        "Step 0: Checking readiness of all nodes after the IC setup ..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 1: Installing NNS canisters on the System subnet ..."
    );
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet. ..."
    );
    let subnet_nns = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap();
    let subnet_app = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let canister_nns = subnet_nns
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    let canister_app = subnet_app
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(&log, "Installation of counter canisters has succeeded.");
    info!(&log, "Step 3: Instantiate and start one workload per subnet using a subset of 1/3 of the nodes as targets.");
    let workload_nns_nodes_count = config.nodes_system_subnet / 3;
    let workload_app_nodes_count = config.nodes_app_subnet / 3;
    assert!(
        min(workload_nns_nodes_count, workload_app_nodes_count) > 0,
        "Workloads need at least one node on both subnets."
    );
    info!(
        &log,
        "Launching two workloads for both subnets in separate threads against {} node/s.",
        workload_nns_nodes_count
    );
    // Workload sends messages to canisters via node agents, so we create them.
    let agents_nns: Vec<_> = subnet_nns
        .nodes()
        .take(workload_nns_nodes_count)
        .map(|node| {
            debug!(
                &log,
                "Node with id={} from NNS will be used for the workload.", node.node_id
            );
            node.with_default_agent(|agent| async move { agent })
        })
        .collect();
    let agents_app: Vec<_> = subnet_app
        .nodes()
        .take(workload_app_nodes_count)
        .map(|node| {
            debug!(
                &log,
                "Node with id={} from APP will be used for the workload.", node.node_id
            );
            node.with_default_agent(|agent| async move { agent })
        })
        .collect();
    assert!(
        agents_nns.len() == workload_nns_nodes_count
            && agents_app.len() == workload_app_nodes_count,
        "Number of nodes and agents do not match."
    );
    // Spawn two workloads in separate threads, as we will need to have execution context to stress nodes.
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    let start_time = Instant::now();
    let stop_time = start_time + config.runtime;
    let handle_workload_nns = spawn_workload(
        log.clone(),
        canister_nns,
        agents_nns,
        config.rps,
        config.runtime,
        payload.clone(),
        DURATION_THRESHOLD,
    );
    let handle_workload_app = spawn_workload(
        log.clone(),
        canister_app,
        agents_app,
        config.rps,
        config.runtime,
        payload.clone(),
        DURATION_THRESHOLD,
    );
    info!(
        &log,
        "Step 4: Stress another disjoint subset of 1/3 of the nodes (during the workload execution)."
    );
    let stress_nns_nodes_count = config.nodes_system_subnet / 3;
    let stress_app_nodes_count = config.nodes_app_subnet / 3;
    assert!(
        min(stress_nns_nodes_count, stress_app_nodes_count) > 0,
        "At least one node needs to be stressed on each subnet."
    );
    // We stress (modify node's traffic) using random parameters.
    let rng: ChaCha8Rng = rand_core::SeedableRng::seed_from_u64(RND_SEED);
    // Stress function for each node is executed in a separate thread.
    let stress_nns_handles: Vec<_> = subnet_nns
        .nodes()
        .skip(workload_nns_nodes_count)
        .take(stress_nns_nodes_count)
        .map(|node| stress_node_periodically(log.clone(), rng.clone(), node, stop_time))
        .collect();
    let stress_app_handles: Vec<_> = subnet_app
        .nodes()
        .skip(workload_app_nodes_count)
        .take(stress_app_nodes_count)
        .map(|node| stress_node_periodically(log.clone(), rng.clone(), node, stop_time))
        .collect();
    for h in stress_nns_handles {
        let stress_info = h
            .join()
            .expect("Thread execution failed.")
            .unwrap_or_else(|err| {
                panic!("Node stressing failed err={}", err);
            });
        info!(&log, "{:?}", stress_info);
    }
    for h in stress_app_handles {
        let stress_info = h
            .join()
            .expect("Thread execution failed.")
            .unwrap_or_else(|err| {
                panic!("Node stressing failed err={}", err);
            });
        info!(&log, "{:?}", stress_info);
    }
    info!(
        &log,
        "Collect metrics from both workloads and perform assertions ..."
    );
    let metrics_nns = handle_workload_nns
        .join()
        .expect("Workload execution against NNS subnet failed.");
    let metrics_app = handle_workload_app
        .join()
        .expect("Workload execution against APP subnet failed.");

    let duration_bucket_nns = metrics_nns
        .find_request_duration_bucket(DURATION_THRESHOLD)
        .unwrap();
    let duration_bucket_app = metrics_app
        .find_request_duration_bucket(DURATION_THRESHOLD)
        .unwrap();
    info!(
        &log,
        "Requests below {} sec:\nRequests_count: NNS={} APP={}\nRequests_ratio: NNS={} APP={}.",
        DURATION_THRESHOLD.as_secs(),
        duration_bucket_nns.requests_count_below_threshold(),
        duration_bucket_app.requests_count_below_threshold(),
        duration_bucket_nns.requests_ratio_below_threshold(),
        duration_bucket_app.requests_ratio_below_threshold(),
    );
    assert!(
        duration_bucket_nns.requests_ratio_below_threshold() > MIN_REQUESTS_RATIO_BELOW_THRESHOLD
    );
    assert!(
        duration_bucket_app.requests_ratio_below_threshold() > MIN_REQUESTS_RATIO_BELOW_THRESHOLD
    );
    info!(
        &log,
        "Results of the workload execution for NNS {:?}", metrics_nns
    );
    info!(
        &log,
        "Results of the workload execution for APP {:?}", metrics_app
    );
    // Create agents to read results from the counter canisters.
    let agent_nns = subnet_nns
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    let agent_app = subnet_app
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    info!(
        &log,
        "Step 6: Assert min counter value on both canisters has been reached ... "
    );
    let total_requests_count = config.rps * config.runtime.as_secs() as usize;
    let min_expected_success_count =
        ((1.0 - config.max_failures_ratio) * total_requests_count as f64) as usize;
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &agent_nns,
            &canister_nns,
            payload.clone(),
            min_expected_success_count,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
    block_on(async {
        assert_canister_counter_with_retries(
            &log,
            &agent_app,
            &canister_app,
            payload.clone(),
            min_expected_success_count,
            MAX_CANISTER_READ_RETRIES,
            CANISTER_READ_RETRY_WAIT,
        )
        .await;
    });
}

#[derive(Debug)]
struct NodeStressInfo {
    _node_id: NodeId,
    stressed_times: u32,
    stressed_mode_duration: Duration,
    normal_mode_duration: Duration,
}

fn stress_node_periodically(
    log: Logger,
    mut rng: ChaCha8Rng,
    node: IcNodeSnapshot,
    stop_time: Instant,
) -> JoinHandle<Result<NodeStressInfo, io::Error>> {
    thread::spawn(move || {
        let mut stress_info = NodeStressInfo {
            _node_id: node.node_id,
            stressed_times: 0,
            normal_mode_duration: Duration::default(),
            stressed_mode_duration: Duration::default(),
        };

        let should_stop = |remaining: Duration| {
            if remaining.is_zero() {
                info!(&log, "Stressing node with id={} is finished.", node.node_id);
                true
            } else {
                false
            }
        };

        // Session is an expensive resource, so we create it once per node.
        let session = node.block_on_ssh_session(ADMIN).unwrap();

        loop {
            // First keep the node in unstressed mode.
            let remaining_duration = stop_time.saturating_duration_since(Instant::now());
            if should_stop(remaining_duration) {
                break;
            } else {
                let _ = execute_ssh_command(&session, reset_tc_ssh_command())?;
                let max_duration =
                    fraction_of_duration(remaining_duration, FRACTION_FROM_REMAINING_DURATION);
                let sleep_time = Uniform::from(
                    MIN_NODE_UNSTRESSED_TIME..=max(max_duration, MIN_NODE_UNSTRESSED_TIME),
                )
                .sample(&mut rng);
                info!(
                    &log,
                    "Node with id={} is in normal (unstressed) mode for {} sec.",
                    node.node_id,
                    sleep_time.as_secs()
                );
                thread::sleep(sleep_time);
                stress_info.normal_mode_duration =
                    stress_info.normal_mode_duration.saturating_add(sleep_time);
            }
            // Now stress the node modifying its traffic parameters.
            let remaining_duration = stop_time.saturating_duration_since(Instant::now());
            if should_stop(remaining_duration) {
                break;
            } else {
                let max_duration =
                    fraction_of_duration(remaining_duration, FRACTION_FROM_REMAINING_DURATION);
                let action_time =
                    Uniform::from(MIN_NODE_STRESS_TIME..=max(max_duration, MIN_NODE_STRESS_TIME))
                        .sample(&mut rng);
                let tc_rules =
                    execute_ssh_command(&session, limit_tc_randomly_ssh_command(&mut rng))?;
                info!(
                    &log,
                    "Node with id={} is stressed for {} sec. The applied tc rules are:\n{}",
                    node.node_id,
                    action_time.as_secs(),
                    tc_rules.as_str()
                );
                thread::sleep(action_time);
                stress_info.stressed_mode_duration = stress_info
                    .stressed_mode_duration
                    .saturating_add(action_time);
                stress_info.stressed_times += 1;
            }
        }
        Ok(stress_info)
    })
}

fn fraction_of_duration(time: Duration, fraction: f64) -> Duration {
    Duration::from_secs((time.as_secs() as f64 * fraction) as u64)
}

fn execute_ssh_command(session: &Session, ssh_command: String) -> Result<String, io::Error> {
    let mut channel = session.channel_session()?;
    channel.exec("bash")?;
    channel.write_all(ssh_command.as_bytes())?;
    channel.flush()?;
    channel.send_eof()?;
    let mut stderr = String::new();
    let mut command_output = String::new();
    channel.stderr().read_to_string(&mut stderr)?;
    channel.read_to_string(&mut command_output)?;
    if !stderr.is_empty() {
        panic!("Channel exited with an stderr=\n{}", stderr);
    }
    channel.close()?;
    channel.wait_close()?;
    let exit_code = channel.exit_status()?;
    if exit_code != 0 {
        panic!("Channel exited with an exit code {}.", exit_code);
    }
    Ok(command_output)
}

fn spawn_workload(
    log: Logger,
    canister_id: Principal,
    agents: Vec<Agent>,
    rps: usize,
    runtime: Duration,
    payload: Vec<u8>,
    duration_threshold: Duration,
) -> JoinHandle<Metrics> {
    let plan = RoundRobinPlan::new(vec![Request::Update(CallSpec::new(
        canister_id,
        CANISTER_METHOD,
        payload,
    ))]);
    thread::spawn(move || {
        block_on(async {
            let workload = Workload::new(agents, rps, runtime, plan, log)
                .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
                .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
                .with_requests_duration_bucket(duration_threshold);
            workload
                .execute()
                .await
                .expect("Execution of the workload failed.")
        })
    })
}

async fn assert_canister_counter_with_retries(
    log: &slog::Logger,
    agent: &Agent,
    canister_id: &Principal,
    payload: Vec<u8>,
    min_expected_count: usize,
    max_retries: u32,
    retry_wait: Duration,
) {
    for i in 1..=1 + max_retries {
        debug!(
            log,
            "Reading counter value from canister with id={}, attempt {}.", canister_id, i
        );
        let res = agent
            .query(canister_id, "read")
            .with_arg(&payload)
            .call()
            .await
            .unwrap();
        let counter = u32::from_le_bytes(
            res.as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        ) as usize;
        debug!(log, "Counter value is {}.", counter);
        if counter >= min_expected_count {
            debug!(
                log,
                "Counter value on canister is {}, above the minimum expectation {}.",
                counter,
                min_expected_count
            );
            return;
        } else {
            debug!(
                log,
                "Counter value on canister is {}, below the minimum expectation {}.",
                counter,
                min_expected_count
            );
            debug!(log, "Retrying in {} secs ...", retry_wait.as_secs());
            tokio::time::sleep(retry_wait).await;
        }
    }
    panic!(
        "Minimum expected counter value {} on counter canister was not observed after {} retries.",
        min_expected_count, max_retries
    );
}

fn reset_tc_ssh_command() -> String {
    format!(
        r#"set -euo pipefail
    sudo tc qdisc del dev {device} root 2> /dev/null || true
    "#,
        device = DEVICE_NAME
    )
}

fn limit_tc_randomly_ssh_command(mut rng: &mut ChaCha8Rng) -> String {
    let bandwidth_dist = Uniform::from(BANDWIDTH_MIN..=BANDWIDTH_MAX);
    let latency_dist = Uniform::from(LATENCY_MIN..=LATENCY_MAX);
    let drops_perc_dist = Uniform::from(DROPS_PERC_MIN..=DROPS_PERC_MAX);
    let cfg = util::get_config();
    let p2p_listen_port = cfg.transport.unwrap().p2p_flows.get(0).unwrap().server_port;
    // The second command deletes existing tc rules (if present).
    // The last command reads the active tc rules.
    format!(
        r#"set -euo pipefail
sudo tc qdisc del dev {device} root 2> /dev/null || true
sudo tc qdisc add dev {device} root handle 1: prio
sudo tc qdisc add dev {device} parent 1:3 handle 10: tbf rate {bandwidth_mbit}mbit latency 400ms burst 100000
sudo tc qdisc add dev {device} parent 10:1 handle 20: netem delay {latency_ms}ms 5ms drop {drops_percentage}%
sudo tc qdisc add dev {device} parent 20:1 handle 30: sfq
sudo tc filter add dev {device} protocol ipv6 parent 1:0 prio 3 u32 match ip6 dport {p2p_listen_port} 0xFFFF flowid 1:3
sudo tc qdisc show dev {device}
"#,
        device = DEVICE_NAME,
        bandwidth_mbit = bandwidth_dist.sample(&mut rng),
        latency_ms = latency_dist.sample(&mut rng).as_millis(),
        drops_percentage = drops_perc_dist.sample(&mut rng),
        p2p_listen_port = p2p_listen_port
    )
}
