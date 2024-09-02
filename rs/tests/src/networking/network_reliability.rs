/* tag::catalog[]
Title:: Subnet makes progress despite one third of the nodes being stressed.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install one counter canister on each subnet.
3. Instantiate and start workload for the APP subnet using a subset of 1/3 of the nodes as targets.
   Workload send update[canister_id, "write"] requests.
   Requests are equally distributed between this subset of 1/3 nodes.
4. Stress (modify tc settings on) another disjoint subset of 1/3 of the nodes (during the workload execution).
   Stressing manifests in introducing randomness in: latency, bandwidth, packet drops percentage, stress duration.
5. Collect metrics from the workload and assert:
   - Ratio of requests with duration below DURATION_THRESHOLD should exceed MIN_REQUESTS_RATIO_BELOW_THRESHOLD.
6. Perform assertions for both counter canisters (via query `read` call)
   - Counter value on the canisters should exceed the threshold = (1 - max_failures_ratio) * total_requests_count.

end::catalog[] */

use ic_base_types::NodeId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::canister_api::{CallMode, GenericRequest};
use ic_system_test_driver::driver::constants::DEVICE_NAME;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsInstallationBuilder,
    SshSession,
};
use ic_system_test_driver::util::{
    self, agent_observes_canister_module, assert_canister_counter_with_retries, block_on,
    spawn_round_robin_workload_engine,
};
use rand::distributions::{Distribution, Uniform};
use rand_chacha::ChaCha8Rng;
use slog::{debug, info, Logger};
use std::cmp::max;
use std::io::{self};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const CANISTER_METHOD: &str = "write";
// Seed for random generator
const RND_SEED: u64 = 42;
// Size of the payload sent to the counter canister in update("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(20);
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
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

// Test can be run with different setup/configuration parameters.
// This config holds these parameters.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub nodes_system_subnet: usize,
    pub nodes_app_subnet: usize,
    pub runtime: Duration,
    pub rps: usize,
}

pub fn setup(env: TestEnv, config: Config) {
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(8)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(50331648)), // 48GiB
        boot_image_minimal_size_gibibytes: None,
    };
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .add_nodes(config.nodes_system_subnet),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .add_nodes(config.nodes_app_subnet),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
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
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet. ..."
    );
    let subnet_app = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let canister_app = subnet_app
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(&log, "Installation of counter canisters has succeeded.");
    info!(&log, "Step 3: Instantiate and start one workload per subnet using a subset of 1/3 of the nodes as targets.");
    let workload_app_nodes_count = config.nodes_app_subnet / 3;
    info!(
        &log,
        "Launching two workloads for both subnets in separate threads against {} node/s.",
        workload_app_nodes_count
    );
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
        agents_app.len() == workload_app_nodes_count,
        "Number of nodes and agents do not match."
    );
    info!(
        &log,
        "Asserting all agents observe the installed canister ..."
    );
    block_on(async {
        for agent in agents_app.iter() {
            assert!(
                agent_observes_canister_module(agent, &canister_app).await,
                "Canister module not available"
            );
        }
    });
    info!(&log, "All agents observe the installed canister module.");
    // Spawn two workloads in separate threads, as we will need to have execution context to stress nodes.
    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];
    let start_time = Instant::now();
    let stop_time = start_time + config.runtime;
    let handle_workload_app = {
        let requests = vec![GenericRequest::new(
            canister_app,
            CANISTER_METHOD.to_string(),
            payload.clone(),
            CallMode::Update,
        )];
        spawn_round_robin_workload_engine(
            log.clone(),
            requests,
            agents_app,
            config.rps,
            config.runtime,
            REQUESTS_DISPATCH_EXTRA_TIMEOUT,
            vec![DURATION_THRESHOLD],
        )
    };
    info!(
        &log,
        "Step 4: Stress another disjoint subset of 1/3 of the nodes (during the workload execution)."
    );
    let stress_app_nodes_count = config.nodes_app_subnet / 3;
    assert!(
        stress_app_nodes_count > 0,
        "At least one node needs to be stressed on each subnet."
    );
    // We stress (modify node's traffic) using random parameters.
    let rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
    // Stress function for each node is executed in a separate thread.
    let stress_app_handles: Vec<_> = subnet_app
        .nodes()
        .skip(workload_app_nodes_count)
        .take(stress_app_nodes_count)
        .map(|node| stress_node_periodically(log.clone(), rng.clone(), node, stop_time))
        .collect();

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
        "Step 5: Collect metrics from both workloads and perform assertions ..."
    );
    let load_metrics_app = handle_workload_app
        .join()
        .expect("Workload execution against APP subnet failed.");
    info!(
        &log,
        "Workload execution results for APP: {load_metrics_app}"
    );
    let requests_count_below_threshold_app =
        load_metrics_app.requests_count_below_threshold(DURATION_THRESHOLD);
    let min_expected_success_count = config.rps * config.runtime.as_secs() as usize;
    assert_eq!(load_metrics_app.failure_calls(), 0);
    assert!(requests_count_below_threshold_app
        .iter()
        .all(|(_, count)| *count as usize == min_expected_success_count));
    let agent_app = subnet_app
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();
    info!(
        &log,
        "Step 6: Assert min counter value on both canisters has been reached ... "
    );
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
        let session = node
            .block_on_ssh_session()
            .expect("Failed to ssh into node");

        loop {
            // First keep the node in unstressed mode.
            let remaining_duration = stop_time.saturating_duration_since(Instant::now());
            if should_stop(remaining_duration) {
                break;
            } else {
                let _ = node
                    .block_on_bash_script_from_session(&session, &reset_tc_ssh_command())
                    .expect("Failed to execute bash script from session");
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
                let tc_rules = node
                    .block_on_bash_script_from_session(
                        &session,
                        &limit_tc_randomly_ssh_command(&mut rng),
                    )
                    .expect("Failed to execute bash script from session");
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
    let p2p_listen_port = cfg.transport.unwrap().listening_port;
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
