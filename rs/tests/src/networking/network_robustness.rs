/* tag::catalog[]
Title:: Effect of adverse network conditions on subnet performance.

Description::
This test analyzes how the IC performs under different network conditions
(e.g., packet loss, limited bandwidth, added delay). The test considers one
of these network conditions at a time and applies the same to all nodes in
the subnet (e.g., 30% of packet loss for all nodes). Important: the introduced
network conditions only affect the p2p port.

This test observes the effect of the network conditions on the IC performance
by checking how many update calls to the counter canister go through. All results
are written to a CSV file (e.g., loss_YYYY-MM-DD-hh-mm-ss.csv).

Before you run a test, specify what you want to test in the config below (e.g.,
test 5%, 10%, 15%, 20% packet loss).

Then, make sure to specify the GuestOS image version via IC_VERSION_ID (e.g.,
use export IC_VERSION_ID=$(ic/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master)).
In addition, you might need to increase the default timeout (50mins) when testing
many different network conditions. You can do that by setting the appropriate
time in seconds to the SYSTEM_TESTS_TIMEOUT environment variable (e.g., use
export SYSTEM_TESTS_TIMEOUT=6000 for 100minutes).

Runbook::
 0. Instantiate an IC with one System and one Application subnet.
 1. Install NNS canisters on the System subnet.
 2. Setup SSH session to all Application subnet nodes.
 3. Create agent to read results from the counter canister.
 4. Start experiment by repeating the following for each network condition value.
 5. Build and install a counter canister on the Application subnet.
    This is needed to prevent one repetition having an effect on the next one.
 6. Set network stress conditions on all nodes.
 7. Instantiate and start the workload in the Application subnet targeting all of the nodes.
    Workloads send update[canister_id, "write"] requests.
    Requests are equally distributed between all nodes in the subnet.
 8. Collect metrics from the workload.
    Wait a bit for outstanding update calls to be processed (configurable by setting
    MAX_CANISTER_READ_RETRIES and CANISTER_READ_RETRY_WAIT).
 9. Write the results (expected vs. actual counts) to the CSV file.
10. Repeat until all network condition values have been covered.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt, SshSession, ADMIN,
    DEVICE_NAME,
};
use crate::util::{self, block_on};
use crate::workload::{CallSpec, Request, RoundRobinPlan, Workload};
use chrono::Utc;
use ic_agent::{export::Principal, Agent};
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info};
use ssh2::Session;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, LineWriter, Read, Write};
use std::thread;
use std::time::Duration;

const COUNTER_CANISTER_WAT: &str = "counter.wat";
const CANISTER_METHOD: &str = "write";
// Size of the payload sent to the counter canister in update("write") call.
const PAYLOAD_SIZE_BYTES: usize = 1024;
// Duration of each request is placed into one of two categories - below or above this threshold.
const DURATION_THRESHOLD: Duration = Duration::from_secs(5);
// Parameters related to reading/asserting counter values of the canisters.
const MAX_CANISTER_READ_RETRIES: u32 = 4;
const CANISTER_READ_RETRY_WAIT: Duration = Duration::from_secs(10);
// Parameters related to workload creation.
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(30); // Responses are collected during the workload execution + this extra time, after all requests had been dispatched.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::ZERO; // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

const EXPERIMENT_GAP_WAIT: Duration = Duration::from_secs(60); // Time to wait after a run before trying to start the next one

// Test can be run with different setup/configuration parameters.
#[derive(Debug, Clone)]
enum TestParameter {
    PacketLoss,
    Bandwidth,
    Delay,
}

// This config holds these parameters.
#[derive(Debug, Clone)]
pub struct Config {
    nodes_system_subnet: usize,    // size of the System subnet
    nodes_app_subnet: usize,       // size of the Application subnet
    num_stress_nodes: usize, // number of nodes which will experience the adverse network conditions
    runtime: Duration,       // runtime of the workload generator
    rps: usize,              // number of update calls the workload generator submits
    test_parameter: TestParameter, // network condition that should be tested (e.g., packet loss)
    parameter_name: String,  // name of the test parameter (e.g., loss)
    parameter_unit: String,  // unit of the test parameter (e.g., %)
    parameter_values: Vec<f32>, // all test parameter values to be tested
}

impl Config {
    /// Builds the IC instance.
    pub fn build(&self) -> impl FnOnce(TestEnv) {
        let config = self.clone();
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
        move |env: TestEnv| test(env, self.clone())
    }
}

pub fn loss_config() -> Config {
    Config {
        nodes_app_subnet: 4,
        nodes_system_subnet: 4,
        num_stress_nodes: 4,
        rps: 100,
        runtime: Duration::from_secs(180),
        test_parameter: TestParameter::PacketLoss,
        parameter_name: "loss".to_string(),
        parameter_unit: "%".to_string(),
        parameter_values: vec![
            0.1, 0.5, 1.0, 5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0,
        ],
    }
}

pub fn bandwidth_config() -> Config {
    Config {
        nodes_app_subnet: 4,
        nodes_system_subnet: 4,
        num_stress_nodes: 4,
        rps: 100,
        runtime: Duration::from_secs(180),
        test_parameter: TestParameter::Bandwidth,
        parameter_name: "bandwidth".to_string(),
        parameter_unit: "Mbps".to_string(),
        parameter_values: vec![
            100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 40.0, 30.0, 20.0, 10.0, 5.0, 1.0, 0.5, 0.1, 0.05,
            0.01,
        ],
    }
}

pub fn delay_config() -> Config {
    Config {
        nodes_app_subnet: 4,
        nodes_system_subnet: 4,
        num_stress_nodes: 4,
        rps: 100,
        runtime: Duration::from_secs(180),
        test_parameter: TestParameter::Delay,
        parameter_name: "delay".to_string(),
        parameter_unit: "ms".to_string(),
        parameter_values: vec![
            0.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 1100.0, 1200.0, 1300.0, 1400.0,
            1500.0, 1600.0, 1800.0, 2000.0, 2100.0, 2200.0, 2300.0, 2400.0, 2500.0, 2600.0, 2800.0,
            3000.0, 3200.0, 3400.0, 3600.0, 3800.0, 4000.0, 4500.0, 5000.0,
        ],
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

    info!(&log, "Step 2: Prepare stress nodes.");

    let subnet_app = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();

    info!(&log, "Determine stress nodes and get SSH sessions.");
    let stress_app_nodes_count = config.num_stress_nodes;
    assert!(
        stress_app_nodes_count > 0,
        "At least one node needs to be stressed on each subnet."
    );

    let stress_node_sessions: Vec<_> = subnet_app
        .nodes()
        .take(stress_app_nodes_count)
        .map(|node| node.block_on_ssh_session(ADMIN).unwrap())
        .collect();

    info!(
        &log,
        "Create agent to read results from the counter canister."
    );
    let agent_app = subnet_app
        .nodes()
        .next()
        .map(|node| node.with_default_agent(|agent| async move { agent }))
        .unwrap();

    let payload: Vec<u8> = vec![0; PAYLOAD_SIZE_BYTES];

    // prepare values to be tested and some helpers for the output and logging
    info!(&log, "Prepare results file.");
    let time_string = Utc::now().format("%Y-%m-%d-%H-%M-%S");
    let file_name = format!("{}_{}.csv", config.parameter_name, time_string);
    let file = File::create(file_name).unwrap();
    let mut file = LineWriter::new(file);

    let header = format!("{},expected,actual,ratio\n", config.parameter_name);
    file.write_all(header.as_bytes()).unwrap();

    for limitation in config.parameter_values.iter() {
        info!(
            &log,
            "Build and install counter canister on the app subnet. ..."
        );
        let canister_app = subnet_app
            .nodes()
            .next()
            .unwrap()
            .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
        info!(&log, "Installation of counter canisters has succeeded.");

        info!(
            &log,
            "Set {} to {}{}.", config.parameter_name, limitation, config.parameter_unit
        );
        for session in &stress_node_sessions {
            let ssh_command = limit_tc_ssh_command(config.test_parameter.clone(), *limitation);
            let tc_rules = execute_ssh_command(session, ssh_command).unwrap_or_else(|err| {
                panic!(
                    "Failed to set adverse network conditions through tc... err={}",
                    err
                );
            });
            debug!(&log, "TC Rules: {}", tc_rules.as_str())
        }

        info!(&log, "Spawn workload for {}s.", config.runtime.as_secs());
        let plan = RoundRobinPlan::new(vec![Request::Update(CallSpec::new(
            canister_app,
            CANISTER_METHOD,
            payload.clone(),
        ))]);

        // Workload sends messages to canisters via node agents, so we create them.
        let agents_app: Vec<_> = subnet_app
            .nodes()
            .map(|node| {
                debug!(
                    &log,
                    "Node with id={} from APP will be used for the workload.", node.node_id
                );
                node.with_default_agent(|agent| async move { agent })
            })
            .collect();

        if let Ok(metrics_app) = block_on(async {
            let workload = Workload::new(agents_app, config.rps, config.runtime, plan, log.clone())
                .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
                .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
                .with_requests_duration_bucket(DURATION_THRESHOLD);
            workload.execute().await
        }) {
            info!(&log, "Collect metrics from the workload.");
            let duration_bucket_app = metrics_app
                .find_request_duration_bucket(DURATION_THRESHOLD)
                .unwrap();
            info!(
                &log,
                "Requests below {} sec:\nRequests_count: APP={}\nRequests_ratio: APP={}.",
                DURATION_THRESHOLD.as_secs(),
                duration_bucket_app.requests_count_below_threshold(),
                duration_bucket_app.requests_ratio_below_threshold(),
            );
        } else {
            info!(&log, "Workload generator panicked!");
        }

        info!(&log, "Read counter value on canister.");
        let expected_count = config.rps * config.runtime.as_secs() as usize;
        let mut actual_count = 0;

        for i in 1..=1 + MAX_CANISTER_READ_RETRIES {
            actual_count = block_on(get_canister_count(
                &log,
                &agent_app,
                &canister_app,
                payload.clone(),
            ))
            .unwrap();

            info!(
                &log,
                "Counter value: {}; Difference: {}.",
                actual_count,
                expected_count - actual_count
            );

            if actual_count == expected_count {
                break;
            }

            debug!(
                log,
                "{}/{}: Retrying in {} secs ...",
                i,
                MAX_CANISTER_READ_RETRIES,
                CANISTER_READ_RETRY_WAIT.as_secs()
            );
            thread::sleep(CANISTER_READ_RETRY_WAIT);
        }

        info!(
            &log,
            "{} at {}{}: expected {}, observed {}, difference {}.",
            config.parameter_name,
            limitation,
            config.parameter_unit,
            expected_count,
            actual_count,
            expected_count - actual_count
        );

        let line = format!(
            "{},{},{},{}\n",
            limitation,
            expected_count,
            actual_count,
            (actual_count as f32) / (expected_count as f32)
        );
        file.write_all(line.as_bytes()).unwrap();

        info!(&log, "Return to normal network conditions.");
        for session in &stress_node_sessions {
            let _ = execute_ssh_command(session, reset_tc_ssh_command()).unwrap_or_else(|err| {
                panic!("Failed to reset tc... err={}", err);
            });
        }

        // wait for the subnet to return to normal operation
        thread::sleep(EXPERIMENT_GAP_WAIT);
    }

    file.flush().unwrap();
    info!(&log, "Step X: All done!");
}

async fn get_canister_count(
    log: &slog::Logger,
    agent: &Agent,
    canister_id: &Principal,
    payload: Vec<u8>,
) -> Result<usize, io::Error> {
    debug!(
        log,
        "Reading counter value from canister with id={}.", canister_id
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

    Ok(counter)
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

fn reset_tc_ssh_command() -> String {
    format!(
        r#"set -euo pipefail
    sudo tc qdisc del dev {device} root 2> /dev/null || true
    "#,
        device = DEVICE_NAME
    )
}

fn limit_tc_ssh_command(parameter: TestParameter, value: f32) -> String {
    let cfg = util::get_config();
    let p2p_listen_port = cfg.transport.unwrap().listening_port;

    let network_limitation = match parameter {
        TestParameter::PacketLoss => format!("netem loss {}%", value),
        TestParameter::Bandwidth => format!("tbf rate {}mbit latency 400ms burst 1540", value),
        TestParameter::Delay => format!("netem delay {}ms", value),
    };

    format!(
        r#"set -euo pipefail
sudo tc qdisc del dev {device} root 2> /dev/null || true
sudo tc qdisc add dev {device} root handle 1: prio
sudo tc qdisc add dev {device} parent 1:3 handle 10: {network_limitation}
sudo tc qdisc add dev {device} parent 10:1 handle 20: sfq
sudo tc filter add dev {device} protocol ipv6 parent 1:0 prio 3 u32 match ip6 dport {p2p_listen_port} 0xFFFF flowid 1:3
sudo tc qdisc show dev {device}
"#,
        device = DEVICE_NAME,
        network_limitation = network_limitation,
        p2p_listen_port = p2p_listen_port
    )
}
