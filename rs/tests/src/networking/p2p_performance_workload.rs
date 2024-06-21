use crate::{
    canister_api::{CallMode, GenericRequest},
    driver::{
        farm::HostFeature,
        ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        test_env::TestEnv,
        test_env_api::{
            retry_async, HasDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationBuilder, SshSession, SubnetSnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    retry_with_msg_async,
    util::{agent_observes_canister_module, block_on, spawn_round_robin_workload_engine},
};

use anyhow::bail;
use ic_agent::Agent;
use ic_registry_subnet_type::SubnetType;
use slog::{debug, info, Logger};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const COUNTER_CANISTER_WAT: &str = "rs/tests/src/counter.wat";
const CANISTER_METHOD: &str = "write";
// Duration of each request is placed into one of the two categories - below or above this threshold.
const APP_DURATION_THRESHOLD: Duration = Duration::from_secs(60);
// Parameters related to workload creation.
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(2); // This param can be slightly tweaked (1-2 sec), if the workload fails to dispatch requests precisely on time.

const JAEGER_VM_NAME: &str = "jaeger-vm";

pub enum Latency {
    No,
    FromSubnetMetrics(SubnetId),
    Constant(Duration),
}

pub enum SubnetId {
    Lhg73,
    /// Canary subnet
    Io67,
}

impl SubnetId {
    fn rtt(&self) -> [(u64, u64, f64); 156] {
        match self {
            SubnetId::Lhg73 => LHG_73_RTT,
            SubnetId::Io67 => IO67_RTT,
        }
    }

    fn packet_loss(&self) -> [(u64, u64, f64); 156] {
        match self {
            SubnetId::Lhg73 => LHG73_PACKET_LOSS,
            SubnetId::Io67 => IO67_PACKET_LOSS,
        }
    }
}
// Create an IC with two subnets, with variable number of nodes.
// Install NNS canister on system subnet.
pub fn config(
    env: TestEnv,
    nodes_nns_subnet: usize,
    nodes_app_subnet: usize,
    boot_image_minimal_size_gibibytes: Option<ImageSizeGiB>,
) {
    let logger = env.logger();
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("failed to start prometheus VM");

    let path = env.get_dependency_path("rs/tests/jaeger_uvm_config_image.zst");

    UniversalVm::new(JAEGER_VM_NAME.to_string())
        .with_required_host_features(vec![HostFeature::Performance])
        .with_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(16)),
            memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        })
        .with_config_img(path)
        .start(&env)
        .expect("failed to setup Jaeger Universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(JAEGER_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let jaeger_ipv6 = universal_vm.ipv6;

    info!(
        logger,
        "Jaeger frontend available at: http://[{}]:16686", jaeger_ipv6
    );

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(16)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
        boot_image_minimal_size_gibibytes,
    };
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .with_jaeger_addr(SocketAddr::new(IpAddr::V6(jaeger_ipv6), 4317))
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .with_initial_notary_delay(Duration::from_millis(300))
                .add_nodes(nodes_nns_subnet),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .with_initial_notary_delay(Duration::from_millis(300))
                .add_nodes(nodes_app_subnet),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test.");
    env.sync_with_prometheus();
    info!(logger, "Step 1: Installing NNS canisters ...");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }
}

// Run a test with configurable number of update requests per second,
// size of the payload, duration of the test. The requests are sent
// to the replica.
pub fn test(
    env: TestEnv,
    rps: usize,
    payload_size_bytes: usize,
    duration: Duration,
    latency: Latency,
    download_prometheus_data: bool,
) {
    let log = env.logger();
    info!(
        &log,
        "Checking readiness of all nodes after the IC setup ..."
    );
    let top_snapshot = env.topology_snapshot();
    top_snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&log, "All nodes are ready, IC setup succeeded.");
    info!(
        &log,
        "Step 2: Build and install one counter canisters on each subnet ..."
    );
    let app_subnet = top_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let app_canister = app_subnet
        .nodes()
        .next()
        .unwrap()
        .create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        &log,
        "Installation of counter canisters on both subnets has succeeded."
    );

    info!(&log, "Step 3: Instantiate and start workloads.");
    // Workload sends messages to canisters via node agents, so we create them.
    let app_agents = create_agents_for_subnet(&log, &app_subnet);
    info!(
        &log,
        "Asserting all agents observe the installed canister ..."
    );
    block_on(async {
        for agent in app_agents.iter() {
            retry_with_msg_async!(
                format!("observing canister module {}", app_canister.to_string()),
                &log,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(agent, &app_canister).await {
                        true => Ok(()),
                        false => bail!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();
        }
    });
    info!(&log, "All agents observe the installed canister module.");
    match latency {
        Latency::No => {}
        Latency::FromSubnetMetrics(subnet) => {
            let tc = tc_command(
                &app_subnet
                    .nodes()
                    .map(|n| n.get_ip_addr())
                    .collect::<Vec<_>>(),
                subnet,
            );
            app_subnet.nodes().enumerate().for_each(|(idx, node)| {
                let session = node
                    .block_on_ssh_session()
                    .expect("Failed to ssh into node");
                node.block_on_bash_script_from_session(&session, &tc[idx])
                    .expect("Failed to execute bash script from session");
            });
        }
        Latency::Constant(value) => {
            app_subnet.nodes().for_each(|node| {
                let session = node
                    .block_on_ssh_session()
                    .expect("Failed to ssh into node");
                node.block_on_bash_script_from_session(&session, &limit_tc_ssh_command(value))
                    .expect("Failed to execute bash script from session");
            });
        }
    }

    info!(&log, "Step 5: Start workload.");
    // Spawn one workload per subnet against the counter canister.
    let payload: Vec<u8> = vec![0; payload_size_bytes];
    let handle_app_workload = {
        let requests = vec![GenericRequest::new(
            app_canister,
            CANISTER_METHOD.to_string(),
            payload.clone(),
            CallMode::Update,
        )];
        spawn_round_robin_workload_engine(
            log.clone(),
            requests,
            app_agents,
            rps,
            duration,
            REQUESTS_DISPATCH_EXTRA_TIMEOUT,
            vec![APP_DURATION_THRESHOLD],
        )
    };
    let load_metrics_app = handle_app_workload
        .join()
        .expect("Workload execution against Application subnet failed.");
    info!(
        &log,
        "Step 6: Collect metrics from the workloads and perform assertions ..."
    );
    info!(&log, "App subnet metrics {load_metrics_app}");
    let requests_count_below_threshold_app =
        load_metrics_app.requests_count_below_threshold(APP_DURATION_THRESHOLD);
    info!(
        &log,
        "Application subnet: requests below {} sec: requests_count={:?}\nFailure calls: {}",
        APP_DURATION_THRESHOLD.as_secs(),
        requests_count_below_threshold_app,
        load_metrics_app.failure_calls(),
    );

    // Download Prometheus data if required.
    if download_prometheus_data {
        info!(&log, "Waiting before download.");
        std::thread::sleep(Duration::from_secs(100));
        info!(&log, "Downloading p8s data");
        env.download_prometheus_data_dir_if_exists();
    }
}

fn create_agents_for_subnet(log: &Logger, subnet: &SubnetSnapshot) -> Vec<Agent> {
    subnet
        .nodes()
        .map(|node| {
            debug!(
                &log,
                "Agent for the node with id={} from the {:?} subnet will be used for the workload.",
                node.node_id,
                subnet.subnet_type()
            );
            node.build_default_agent()
        })
        .collect::<_>()
}

/**
 * 1. Delete existing tc rules (if present).
 * 2. Add a qdisc to introduce latency and increase queue size to 1_000_000.
 * 3. Read the active tc rules.
 */
fn limit_tc_ssh_command(latency: Duration) -> String {
    format!(
        r#"set -euo pipefail
        sudo tc qdisc del dev {device} root 2> /dev/null || true
        sudo tc qdisc add dev {device} root netem limit 10000000 delay {latency_ms}ms
        sudo tc qdisc show dev {device}
"#,
        device = "enp1s0",
        latency_ms = latency.as_millis(),
    )
}

fn tc_command(nodes: &[IpAddr], subnet: SubnetId) -> [String; 13] {
    assert_eq!(nodes.len(), 13);

    const ARRAY_REPEAT_VALUE: std::string::String = String::new();
    let mut tcs: [String; 13] = [ARRAY_REPEAT_VALUE; 13];

    let packet_loss = subnet.packet_loss();
    let rtt = subnet.rtt();

    for i in 0..13 {
        let mut tc = String::from("sudo tc qdisc del dev enp1s0 root 2> /dev/null || true \n");
        tc.push_str("sudo tc qdisc add dev enp1s0 root handle 1: prio \n");
        let src_ip = nodes[i];
        for j in 0..13 {
            if i == j {
                continue;
            }
            let dst_ip = nodes[j];
            tc.push_str(&format!(
                "sudo tc qdisc add dev enp1s0 parent 1:{j} handle {j}0: netem limit 10000000 loss {:.3}% delay {}ms \n",
                packet_loss[(12) * i + j].2 * 100.0,
                (rtt[(12) * i + j].2 * 1000.0 / 2.0) as u64
            ));
            tc.push_str(&format!("sudo tc filter add dev enp1s0 protocol ip parent 1:0 prio {j} u32 match ip6 src {src_ip} match ip6 dst {dst_ip} flowid 1:{j} \n"));
        }
        tcs[i] = tc;
    }
    tcs
}

/*
Small script to parse text formatted prometheus table data

peer1 peer2 value
peer1 peer3 value
peer2 peer1 value
...


import sys

"""
LATENCY

sum by (ic_node,peer) (quic_transport_quinn_path_rtt_seconds{ic_subnet="<<SUBNET_ID>>"})

PACKETLOSS

sum by (ic_node,peer) (
  rate(quic_transport_quinn_path_lost_packets{ic_subnet="<<SUBNET_ID>>"}[10m]) /
  rate(quic_transport_quinn_path_sent_packets{ic_subnet="<<SUBNET_ID>>"}[10m])
)

"""

def process_data(input_file, output_file):
    # Initialize a dictionary to hold ID to number mapping
    id_to_number = {}
    next_number = 1

    # Read data from the input file
    with open(input_file, 'r') as file:
        data = file.readlines()

    # Prepare to write to the output file
    with open(output_file, 'w') as output:
        # Process each line
        for line in data:
            # Split the line into components
            parts = line.split()
            if len(parts) < 3:
                continue

            node_id, peer_id, value = parts[0], parts[1], parts[2]

            # Assign numbers to node IDs if they haven't been assigned already
            if node_id not in id_to_number:
                id_to_number[node_id] = next_number
                next_number += 1
            if peer_id not in id_to_number:
                id_to_number[peer_id] = next_number
                next_number += 1

            # Map node and peer IDs to their respective numbers
            node_number = id_to_number[node_id]
            peer_number = id_to_number[peer_id]

            # Format the output
            output_line = f"({node_number}, {peer_number}, {value}),\n"
            output.write(output_line)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python process_data.py <input_file> <output_file>")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        process_data(input_file, output_file)
*/

const LHG_73_RTT: [(u64, u64, f64); 156] = [
    (1, 2, 0.61712),
    (1, 3, 0.16138),
    (1, 4, 0.1979),
    (1, 5, 0.31523),
    (1, 6, 0.03331),
    (1, 7, 0.0301),
    (1, 8, 0.0968),
    (1, 9, 0.1448),
    (1, 10, 0.26926),
    (1, 11, 0.04916),
    (1, 12, 0.03823),
    (1, 13, 0.31636),
    (2, 1, 0.4457),
    (2, 3, 0.21571),
    (2, 4, 0.31776),
    (2, 5, 0.31094),
    (2, 6, 0.34994),
    (2, 7, 0.24353),
    (2, 8, 0.36381),
    (2, 9, 0.05638),
    (2, 10, 0.21407),
    (2, 11, 0.33622),
    (2, 12, 0.27787),
    (2, 13, 0.03922),
    (3, 1, 0.16143),
    (3, 2, 0.21653),
    (3, 4, 0.13629),
    (3, 5, 0.1642),
    (3, 6, 0.17138),
    (3, 7, 0.13677),
    (3, 8, 0.20414),
    (3, 9, 0.24348),
    (3, 10, 0.14349),
    (3, 11, 0.15612),
    (3, 12, 0.16038),
    (3, 13, 0.16789),
    (4, 1, 0.19735),
    (4, 2, 0.32791),
    (4, 3, 0.13626),
    (4, 5, 0.24396),
    (4, 6, 0.18301),
    (4, 7, 0.16498),
    (4, 8, 0.23006),
    (4, 9, 0.28532),
    (4, 10, 0.32546),
    (4, 11, 0.17209),
    (4, 12, 0.1687),
    (4, 13, 0.3046),
    (5, 1, 0.32781),
    (5, 2, 0.31353),
    (5, 3, 0.16413),
    (5, 4, 0.24397),
    (5, 6, 0.30252),
    (5, 7, 0.28085),
    (5, 8, 0.35983),
    (5, 9, 0.25506),
    (5, 10, 0.03217),
    (5, 11, 0.2806),
    (5, 12, 0.28543),
    (5, 13, 0.39781),
    (6, 1, 0.03333),
    (6, 2, 0.35234),
    (6, 3, 0.17143),
    (6, 4, 0.18291),
    (6, 5, 0.3025),
    (6, 7, 0.02777),
    (6, 8, 0.07972),
    (6, 9, 0.1297),
    (6, 10, 0.25978),
    (6, 11, 0.02073),
    (6, 12, 0.02456),
    (6, 13, 0.33166),
    (7, 1, 0.03004),
    (7, 2, 0.24537),
    (7, 3, 0.13675),
    (7, 4, 0.16501),
    (7, 5, 0.27803),
    (7, 6, 0.02777),
    (7, 8, 0.07466),
    (7, 9, 0.13592),
    (7, 10, 0.23801),
    (7, 11, 0.01887),
    (7, 12, 0.01972),
    (7, 13, 0.29473),
    (8, 1, 0.09677),
    (8, 2, 0.34166),
    (8, 3, 0.20411),
    (8, 4, 0.23096),
    (8, 5, 0.35981),
    (8, 6, 0.0798),
    (8, 7, 0.07474),
    (8, 9, 0.17424),
    (8, 10, 0.30549),
    (8, 11, 0.08596),
    (8, 12, 0.08187),
    (8, 13, 0.27698),
    (9, 1, 0.14482),
    (9, 2, 0.05636),
    (9, 3, 0.24343),
    (9, 4, 0.28514),
    (9, 5, 0.25525),
    (9, 6, 0.12969),
    (9, 7, 0.13586),
    (9, 8, 0.17429),
    (9, 10, 0.25616),
    (9, 11, 0.10919),
    (9, 12, 0.14037),
    (9, 13, 0.23707),
    (10, 1, 0.26862),
    (10, 2, 0.19502),
    (10, 3, 0.16683),
    (10, 4, 0.29872),
    (10, 5, 0.03211),
    (10, 6, 0.25981),
    (10, 7, 0.23806),
    (10, 8, 0.30551),
    (10, 9, 0.25588),
    (10, 11, 0.2647),
    (10, 12, 0.27553),
    (10, 13, 0.05266),
    (11, 1, 0.04922),
    (11, 2, 0.32807),
    (11, 3, 0.15616),
    (11, 4, 0.17251),
    (11, 5, 0.28066),
    (11, 6, 0.02084),
    (11, 7, 0.01885),
    (11, 8, 0.08604),
    (11, 9, 0.10918),
    (11, 10, 0.26476),
    (11, 12, 0.02555),
    (11, 13, 0.2858),
    (12, 1, 0.03829),
    (12, 2, 0.27083),
    (12, 3, 0.16036),
    (12, 4, 0.16875),
    (12, 5, 0.2854),
    (12, 6, 0.02457),
    (12, 7, 0.01961),
    (12, 8, 0.08141),
    (12, 9, 0.1404),
    (12, 10, 0.27557),
    (12, 11, 0.02553),
    (12, 13, 0.30877),
    (13, 1, 0.31634),
    (13, 2, 0.03919),
    (13, 3, 0.16781),
    (13, 4, 0.31543),
    (13, 5, 0.40834),
    (13, 6, 0.32947),
    (13, 7, 0.2947),
    (13, 8, 0.27695),
    (13, 9, 0.23713),
    (13, 10, 0.05268),
    (13, 11, 0.29273),
    (13, 12, 0.30878),
];

const LHG73_PACKET_LOSS: [(u64, u64, f64); 156] = [
    (1, 2, 0.10996749729144095),
    (1, 3, 0.0),
    (1, 4, 0.00014506208657305328),
    (1, 5, 0.00017493731412910373),
    (1, 6, 0.0),
    (1, 7, 0.00021835849005104132),
    (1, 8, 0.000028244598220590316),
    (1, 9, 0.0),
    (1, 10, 0.00017437298381237467),
    (1, 11, 0.0004203211253397596),
    (1, 12, 0.00025079418157498745),
    (1, 13, 0.00017522852720422885),
    (2, 1, 0.46462264150943394),
    (2, 3, 0.0),
    (2, 4, 0.004377136649733218),
    (2, 5, 0.0),
    (2, 6, 0.0038299891540130152),
    (2, 7, 0.5499092558983666),
    (2, 8, 0.13039882959099292),
    (2, 9, 0.0),
    (2, 10, 0.00035081564637782847),
    (2, 11, 0.00006247461968575268),
    (2, 12, 0.00002988196623337816),
    (2, 13, 0.0),
    (3, 1, 0.00011286681715575621),
    (3, 2, 0.0398395352054226),
    (3, 4, 0.0),
    (3, 5, 0.0),
    (3, 6, 0.0),
    (3, 7, 0.0),
    (3, 8, 0.0008279800142755175),
    (3, 9, 0.0),
    (3, 10, 0.00046834536338090247),
    (3, 11, 0.0),
    (3, 12, 0.0),
    (3, 13, 0.0),
    (4, 1, 0.0),
    (4, 2, 0.016789015769439915),
    (4, 3, 0.0),
    (4, 5, 0.0),
    (4, 6, 0.0),
    (4, 7, 0.0),
    (4, 8, 0.000058462437883659755),
    (4, 9, 0.0),
    (4, 10, 0.0009978868278938716),
    (4, 11, 0.0),
    (4, 12, 0.0),
    (4, 13, 0.000029207313511303232),
    (5, 1, 0.0008459496514104023),
    (5, 2, 0.0),
    (5, 3, 0.0),
    (5, 4, 0.0),
    (5, 6, 0.0),
    (5, 7, 0.0),
    (5, 8, 0.0),
    (5, 9, 0.0),
    (5, 10, 0.0),
    (5, 11, 0.0),
    (5, 12, 0.000028875028875028877),
    (5, 13, 0.00707166153564788),
    (6, 1, 0.00016115602589240148),
    (6, 2, 0.022668947818648418),
    (6, 3, 0.0),
    (6, 4, 0.0),
    (6, 5, 0.0),
    (6, 7, 0.0),
    (6, 8, 0.00005460601758313766),
    (6, 9, 0.0),
    (6, 10, 0.0),
    (6, 11, 0.0),
    (6, 12, 0.0),
    (6, 13, 0.0),
    (7, 1, 0.0029997857295907438),
    (7, 2, 0.0033869115958668193),
    (7, 3, 0.0032367831355299198),
    (7, 4, 0.0033353887549750546),
    (7, 5, 0.003399915002124947),
    (7, 6, 0.0025975461478943297),
    (7, 8, 0.0030563669804176134),
    (7, 9, 0.0035285815102328866),
    (7, 10, 0.002148109388339622),
    (7, 11, 0.003549532107131333),
    (7, 12, 0.003492063492063492),
    (7, 13, 0.003373956545766557),
    (8, 1, 0.00011341404632963793),
    (8, 2, 0.021753561762753407),
    (8, 3, 0.0),
    (8, 4, 0.0),
    (8, 5, 0.00023399338968674137),
    (8, 6, 0.0),
    (8, 7, 0.0),
    (8, 9, 0.0),
    (8, 10, 0.0009087977485268681),
    (8, 11, 0.00016970725498515062),
    (8, 12, 0.0),
    (8, 13, 0.0),
    (9, 1, 0.000055850321139346556),
    (9, 2, 0.0),
    (9, 3, 0.0),
    (9, 4, 0.0),
    (9, 5, 0.0),
    (9, 6, 0.0),
    (9, 7, 0.000027785495971103084),
    (9, 8, 0.0003091190108191654),
    (9, 10, 0.0),
    (9, 11, 0.0),
    (9, 12, 0.0),
    (9, 13, 0.000029191114224829965),
    (10, 1, 0.0013883264881124544),
    (10, 2, 0.0),
    (10, 3, 0.0),
    (10, 4, 0.0),
    (10, 5, 0.0),
    (10, 6, 0.0),
    (10, 7, 0.0),
    (10, 8, 0.00002900063801403631),
    (10, 9, 0.0),
    (10, 11, 0.0),
    (10, 12, 0.00014441684478077522),
    (10, 13, 0.0),
    (11, 1, 0.0),
    (11, 2, 0.017175265040440823),
    (11, 3, 0.0),
    (11, 4, 0.0),
    (11, 5, 0.0),
    (11, 6, 0.0),
    (11, 7, 0.0),
    (11, 8, 0.000055944055944055945),
    (11, 9, 0.0),
    (11, 10, 0.0024500510427300573),
    (11, 12, 0.0),
    (11, 13, 0.20009510223490254),
    (12, 1, 0.00005495562333415767),
    (12, 2, 0.008612001832340814),
    (12, 3, 0.00005611672278338946),
    (12, 4, 0.0005651313930488839),
    (12, 5, 0.000028395377232586536),
    (12, 6, 0.00018987685129930016),
    (12, 7, 0.0001321912013536379),
    (12, 8, 0.00005529902950203224),
    (12, 9, 0.00027585445918733276),
    (12, 10, 0.0013517400057520852),
    (12, 11, 0.0),
    (12, 13, 0.00005702554744525548),
    (13, 1, 0.00008762705923589204),
    (13, 2, 0.0),
    (13, 3, 0.0),
    (13, 4, 0.0),
    (13, 5, 0.000240132072639952),
    (13, 6, 0.0),
    (13, 7, 0.0),
    (13, 8, 0.000057097179399337676),
    (13, 9, 0.0),
    (13, 10, 0.0),
    (13, 11, 0.0),
    (13, 12, 0.00002901073397156948),
];

const IO67_RTT: [(u64, u64, f64); 156] = [
    (1, 2, 0.16734),
    (1, 3, 0.27353),
    (1, 4, 0.30555),
    (1, 5, 0.23737),
    (1, 6, 0.25876),
    (1, 7, 0.19405),
    (1, 8, 0.25064),
    (1, 9, 0.18161),
    (1, 10, 0.23736),
    (1, 11, 0.05576),
    (1, 12, 0.2812),
    (1, 13, 0.11474),
    (2, 1, 0.16745),
    (2, 3, 0.12441),
    (2, 4, 0.17481),
    (2, 5, 0.10927),
    (2, 6, 0.12067),
    (2, 7, 0.24545),
    (2, 8, 0.26332),
    (2, 9, 0.04151),
    (2, 10, 0.22915),
    (2, 11, 0.22803),
    (2, 12, 0.13506),
    (2, 13, 0.09143),
    (3, 1, 0.27369),
    (3, 2, 0.12448),
    (3, 4, 0.07763),
    (3, 5, 0.02511),
    (3, 6, 0.01955),
    (3, 7, 0.33227),
    (3, 8, 0.19035),
    (3, 9, 0.10048),
    (3, 10, 0.36291),
    (3, 11, 0.32749),
    (3, 12, 0.00252),
    (3, 13, 0.16926),
    (4, 1, 0.30565),
    (4, 2, 0.17482),
    (4, 3, 0.07763),
    (4, 5, 0.07412),
    (4, 6, 0.06778),
    (4, 7, 0.31882),
    (4, 8, 0.24298),
    (4, 9, 0.14879),
    (4, 10, 0.37033),
    (4, 11, 0.37262),
    (4, 12, 0.07774),
    (4, 13, 0.20558),
    (5, 1, 0.23735),
    (5, 2, 0.10931),
    (5, 3, 0.0251),
    (5, 4, 0.07417),
    (5, 6, 0.0152),
    (5, 7, 0.20899),
    (5, 8, 0.1815),
    (5, 9, 0.08172),
    (5, 10, 0.32365),
    (5, 11, 0.32509),
    (5, 12, 0.02524),
    (5, 13, 0.1358),
    (6, 1, 0.25877),
    (6, 2, 0.1207),
    (6, 3, 0.01956),
    (6, 4, 0.06777),
    (6, 5, 0.01518),
    (6, 7, 0.26372),
    (6, 8, 0.1825),
    (6, 9, 0.09002),
    (6, 10, 0.30955),
    (6, 11, 0.31012),
    (6, 12, 0.02154),
    (6, 13, 0.14768),
    (7, 1, 0.19406),
    (7, 2, 0.24547),
    (7, 3, 0.33227),
    (7, 4, 0.31866),
    (7, 5, 0.20844),
    (7, 6, 0.26364),
    (7, 8, 0.28578),
    (7, 9, 0.33597),
    (7, 10, 0.11232),
    (7, 11, 0.03261),
    (7, 12, 0.33047),
    (7, 13, 0.20231),
    (8, 1, 0.25065),
    (8, 2, 0.26337),
    (8, 3, 0.1903),
    (8, 4, 0.24296),
    (8, 5, 0.18148),
    (8, 6, 0.18248),
    (8, 7, 0.28589),
    (8, 9, 0.25825),
    (8, 10, 0.32082),
    (8, 11, 0.42551),
    (8, 12, 0.1919),
    (8, 13, 0.30328),
    (9, 1, 0.18172),
    (9, 2, 0.04157),
    (9, 3, 0.10048),
    (9, 4, 0.14877),
    (9, 5, 0.08173),
    (9, 6, 0.08999),
    (9, 7, 0.33593),
    (9, 8, 0.25829),
    (9, 10, 0.3733),
    (9, 11, 0.21682),
    (9, 12, 0.10349),
    (9, 13, 0.06968),
    (10, 1, 0.23699),
    (10, 2, 0.22907),
    (10, 3, 0.36289),
    (10, 4, 0.37027),
    (10, 5, 0.32357),
    (10, 6, 0.30947),
    (10, 7, 0.11226),
    (10, 8, 0.32078),
    (10, 9, 0.37328),
    (10, 11, 0.12819),
    (10, 12, 0.36405),
    (10, 13, 0.1937),
    (11, 1, 0.05577),
    (11, 2, 0.22817),
    (11, 3, 0.32739),
    (11, 4, 0.37252),
    (11, 5, 0.32532),
    (11, 6, 0.31036),
    (11, 7, 0.03266),
    (11, 8, 0.42551),
    (11, 9, 0.21658),
    (11, 10, 0.12826),
    (11, 12, 0.33359),
    (11, 13, 0.16365),
    (12, 1, 0.28104),
    (12, 2, 0.13512),
    (12, 3, 0.00253),
    (12, 4, 0.07771),
    (12, 5, 0.02525),
    (12, 6, 0.02147),
    (12, 7, 0.33049),
    (12, 8, 0.1919),
    (12, 9, 0.10349),
    (12, 10, 0.36412),
    (12, 11, 0.33376),
    (12, 13, 0.16952),
    (13, 1, 0.11449),
    (13, 2, 0.09144),
    (13, 3, 0.1693),
    (13, 4, 0.20561),
    (13, 5, 0.13581),
    (13, 6, 0.14766),
    (13, 7, 0.20231),
    (13, 8, 0.3031),
    (13, 9, 0.06971),
    (13, 10, 0.1938),
    (13, 11, 0.16366),
    (13, 12, 0.1695),
];

/// Query for the metric:
/// https://victoria.ch1-obs1.dfinity.network/select/0/vmui/#/?g0.expr=sum+by+%28ic_node%2Cpeer%29+%28%0A++rate%28quic_transport_quinn_path_lost_packets%7Bic_subnet%3D%22io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe%22%7D%5B7d%5D%29+%2F%0A++rate%28quic_transport_quinn_path_sent_packets%7Bic_subnet%3D%22io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe%22%7D%5B7d%5D%29%0A%29&g0.range_input=10d2h52m42s818ms&g0.end_input=2024-05-12T13%3A19%3A31&g0.tab=1&g0.relative_time=none&g0.tenantID=0
const IO67_PACKET_LOSS: [(u64, u64, f64); 156] = [
    (1, 2, 0.0000025116739926176536),
    (1, 3, 0.0004579456767444065),
    (1, 4, 0.001850035700864664),
    (1, 5, 0.000995202969108691),
    (1, 6, 0.00001909138613960752),
    (1, 7, 0.00019945655637087513),
    (1, 8, 0.00020795407398626622),
    (1, 9, 0.000026004830460787808),
    (1, 10, 0.00006330761514513749),
    (1, 11, 0.00009654861405968816),
    (1, 12, 0.0004536072375606995),
    (1, 13, 0.0009260210590594368),
    (2, 1, 0.000026576950863990973),
    (2, 3, 0.0004114995052709546),
    (2, 4, 0.0018229081737066288),
    (2, 5, 0.0000005933958768819974),
    (2, 6, 0.00013024455288572292),
    (2, 7, 0.020455982007400803),
    (2, 8, 0.000031435626028901895),
    (2, 9, 0.000023947440365412273),
    (2, 10, 0.00006601200235208804),
    (2, 11, 0.0006411684186170226),
    (2, 12, 0.00041909322428773237),
    (2, 13, 0.00007295633111814528),
    (3, 1, 0.010389597449360232),
    (3, 2, 0.000005401243077713142),
    (3, 4, 0.0021555313839978565),
    (3, 5, 0.000006727880551439605),
    (3, 6, 0.0011608136729818863),
    (3, 7, 0.0005629997811317654),
    (3, 8, 0.00001949232259855781),
    (3, 9, 0.00101600480987657),
    (3, 10, 0.00005065854264858888),
    (3, 11, 0.005021689441758273),
    (3, 12, 0.0000032934530928022075),
    (3, 13, 0.0000023184022386039645),
    (4, 1, 0.0018678684335336694),
    (4, 2, 0.000031416668268300735),
    (4, 3, 0.0005144044320281668),
    (4, 5, 0.0001028766894281342),
    (4, 6, 0.00019102556100341472),
    (4, 7, 0.0004362537524155629),
    (4, 8, 0.000056674819121417206),
    (4, 9, 0.00015202853894404224),
    (4, 10, 0.0003617712393357278),
    (4, 11, 0.003004178416230635),
    (4, 12, 0.0005811423720677048),
    (4, 13, 0.000051074816581858724),
    (5, 1, 0.0010432149107949453),
    (5, 2, 0.0009475517681796154),
    (5, 3, 0.0022883193286215905),
    (5, 4, 0.002610988212034662),
    (5, 6, 0.001153250918564546),
    (5, 7, 0.0021525973193944293),
    (5, 8, 0.0010767507701540298),
    (5, 9, 0.00043418753932369356),
    (5, 10, 0.001272768969006755),
    (5, 11, 0.010749916709952487),
    (5, 12, 0.0019574384042711),
    (5, 13, 0.0009673222429462834),
    (6, 1, 0.0067117374811837705),
    (6, 2, 0.00006556061456508818),
    (6, 3, 0.0007314081054916355),
    (6, 4, 0.0018472198140076258),
    (6, 5, 0.000006429619908156391),
    (6, 7, 0.0012561006357616922),
    (6, 8, 0.00003722154298823348),
    (6, 9, 0.001102775770117787),
    (6, 10, 0.00003790317704034539),
    (6, 11, 0.00433350243550568),
    (6, 12, 0.0004261915770601068),
    (6, 13, 0.00005815573915253811),
    (7, 1, 0.006823172227417568),
    (7, 2, 0.00008792702682246431),
    (7, 3, 0.001476173624351456),
    (7, 4, 0.030076349208947972),
    (7, 5, 0.037095492354744415),
    (7, 6, 0.030038303242105942),
    (7, 8, 0.0002786281336062296),
    (7, 9, 0.000021040752994576822),
    (7, 10, 0.000001095917541365759),
    (7, 11, 0.00004952133633027111),
    (7, 12, 0.0024578454093489278),
    (7, 13, 0.000016841824481378308),
    (8, 1, 0.00005370160093649248),
    (8, 2, 0.000017874223930090313),
    (8, 3, 0.00006836185034737848),
    (8, 4, 0.0013723956396028574),
    (8, 5, 0.000015717180752751758),
    (8, 6, 0.000017518158418853967),
    (8, 7, 0.00008481692748439206),
    (8, 9, 0.0025713202866593163),
    (8, 10, 0.00004845256158888936),
    (8, 11, 0.00597232779894635),
    (8, 12, 0.000019538842338310524),
    (8, 13, 0.000019167036921761375),
    (9, 1, 0.000017309396411480213),
    (9, 2, 0.000027680298114631145),
    (9, 3, 0.0005667623474787441),
    (9, 4, 0.002033220199129239),
    (9, 5, 0.000004030380786458279),
    (9, 6, 0.00008071943646350249),
    (9, 7, 0.00443521094808668),
    (9, 8, 0.00008616131904608202),
    (9, 10, 0.000029517833129548022),
    (9, 11, 0.000762494536565196),
    (9, 12, 0.00003346306762915821),
    (9, 13, 0.00007681578987797783),
    (10, 1, 0.009322270880568405),
    (10, 2, 0.000020254746844599795),
    (10, 3, 0.00023500601357271062),
    (10, 4, 0.0013617773363115001),
    (10, 5, 0.000009083328382446275),
    (10, 6, 0.00001840239989943796),
    (10, 7, 0.000010781540651193795),
    (10, 8, 0.00002671767220453463),
    (10, 9, 0.000030520812178630785),
    (10, 11, 0.000031855778722983164),
    (10, 12, 0.0004215135278290673),
    (10, 13, 0.00006244122959858073),
    (11, 1, 0.00003363942481658124),
    (11, 2, 0.0000286721370679327),
    (11, 3, 0.0004917590531146349),
    (11, 4, 0.0018349257726532338),
    (11, 5, 0.000024763148915756672),
    (11, 6, 0.00010442346671132577),
    (11, 7, 0.000047054745823687904),
    (11, 8, 0.00038678542449209344),
    (11, 9, 0.00008411905126516441),
    (11, 10, 0.000026530805634556678),
    (11, 12, 0.00048041545797093287),
    (11, 13, 0.0010165654083166037),
    (12, 1, 0.012252953478055162),
    (12, 2, 0.000005131745225463936),
    (12, 3, 0.000008923671744409786),
    (12, 4, 0.0021122113111040983),
    (12, 5, 0.0000015164146296872908),
    (12, 6, 0.0008193443890555587),
    (12, 7, 0.0005300908848447211),
    (12, 8, 0.00012318614018410142),
    (12, 9, 0.001026882749503089),
    (12, 10, 0.000050966344544268),
    (12, 11, 0.004995221578124113),
    (12, 13, 0.000001358177454882406),
    (13, 1, 0.0006337791868513416),
    (13, 2, 0.0000009519790678842553),
    (13, 3, 0.000003302281817464143),
    (13, 4, 0.00148074982778491),
    (13, 5, 0.0000014964488140247861),
    (13, 6, 0.000005996316225352878),
    (13, 7, 0.0011227127562902584),
    (13, 8, 0.00018202700190020091),
    (13, 9, 0.000006003484178758085),
    (13, 10, 0.000007740675111283463),
    (13, 11, 0.0007356809260771047),
    (13, 12, 0.000005987140187701364),
];
