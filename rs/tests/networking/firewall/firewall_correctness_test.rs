/* tag::catalog[]
Title:: Firewall Correctness

Goal:: Verifies the whitelisted/all port split in the firewall configuration: some
       ports are reachable from all IC nodes (in `all_nodes_tcp_ports_whitelist`),
       while other ports are reachable only from whitelisted IC nodes (they are in
       `whitelisted_nodes_tcp_ports_whitelist`) depending on the node's reward type.

Runbook::
1. Set up an IC with a system subnet an application subnet, a cloud engine, and an API BN.
2. For each pair of nodes in the network (excluding API BNs), and for each port in the
   firewall config (whitelisted-only, all-nodes, and closed):
   * From the source node, attempt to establish a TCP connection to the destination
     node on the given port.
   * Assert that the connection can be established if and only if it should be allowed
     according to the firewall rules:
     * Ports in `whitelisted_nodes_tcp_ports_whitelist` should only be reachable from
       whitelisted nodes.
     * Ports in `all_nodes_tcp_ports_whitelist` should be reachable from all IC nodes.
     * Ports not in either whitelist should not be reachable from any node.

Note:: UDP connectivity is not tested in this test, as it is harder to reliably test UDP
       connectivity by design of the protocol.

Success::
All connectivity assertions pass as described above.

end::catalog[] */

use anyhow::Result;
use ic_consensus_system_test_utils::{
    node::await_subnet_firewall_registry_version_with_retries_async,
    rw_message::install_nns_and_check_progress,
};
use ic_firewall_system_test_utils::execute_add_firewall_rules_proposal;
use ic_protobuf::registry::{
    firewall::v1::{FirewallAction, FirewallRule, FirewallRuleDirection},
    node::v1::NodeRewardType,
};
use ic_registry_keys::FirewallRulesScope;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    systest,
    util::{block_on, get_config},
};
use slog::Logger;
use std::{sync::LazyLock, time::Duration};

/// Ports opened only to whitelisted IC nodes.
static TCP_PORTS_WHITELISTED_ONLY: LazyLock<Vec<u32>> = LazyLock::new(|| {
    get_config()
        .firewall
        .unwrap()
        .whitelisted_nodes_tcp_ports_whitelist
        .clone()
        .into_iter()
        // We exceptionally exclude port 22 (SSH) from the list such that the test driver can still
        // SSH into the nodes and actually perform the test.
        // This test thus does not test whether nodes correctly open resp. restrict their SSH port.
        .filter(|port| *port != 22)
        .collect()
});
/// Ports opened to all IC nodes.
static TCP_PORTS_ALL_NODES: LazyLock<Vec<u32>> = LazyLock::new(|| {
    get_config()
        .firewall
        .unwrap()
        .all_nodes_tcp_ports_whitelist
        .clone()
});
/// Ports closed to everyone, only a few are tested here.
const TCP_PORTS_CLOSED: &[u32] = &[23, 24, 25];

const CLOUD_ENGINE_NODE_REWARD_TYPES: &[NodeRewardType] = &[
    NodeRewardType::Type4,
    NodeRewardType::Type4dot1,
    NodeRewardType::Type4dot2,
    NodeRewardType::Type4dot3,
    NodeRewardType::Type4dot4,
    NodeRewardType::Type4dot5,
];

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_subnet(Subnet::fast(SubnetType::System, 1))
        .add_subnet(Subnet::fast(SubnetType::Application, 2))
        .add_subnet(Subnet::fast(SubnetType::CloudEngine, 2))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn firewall_correctness_test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();

    let mut join_handles = vec![];
    let all_nodes = topology_snapshot
        .subnets()
        .flat_map(|s| s.nodes())
        .collect::<Vec<_>>();
    block_on(async {
        // Add a firewall rule to the registry to make sure that nodes do not add the default rules
        // found in their config file, which whitelists prefixes found in the test environment
        // (which would make nodes accept connections from all other nodes, regardless of their
        // reward types).
        // The rule allows necessary ports (SSH and the metrics ports) to be open to everyone, such
        // that the test driver can still connect to the nodes and perform the test
        add_necessary_ports_registry_rule(
            &topology_snapshot.root_subnet().nodes().next().unwrap(),
            &logger,
        )
        .await;

        // Wait for a while to make sure that all nodes have updated their firewall rules according
        // to the new registry configuration.
        for subnet in topology_snapshot.subnets() {
            await_subnet_firewall_registry_version_with_retries_async(
                &subnet,
                topology_snapshot.get_registry_version().increment(),
                &logger,
                Duration::from_secs(60),
                Duration::from_secs(10),
            )
            .await;
        }

        for node_src in &all_nodes {
            for node_dst in &all_nodes {
                for &port in TCP_PORTS_WHITELISTED_ONLY
                    .iter()
                    .chain(TCP_PORTS_ALL_NODES.iter())
                    .chain(TCP_PORTS_CLOSED.iter())
                {
                    // Spawn all connectivity checks in parallel to speed up the test
                    let node_src = node_src.clone();
                    let node_dst = node_dst.clone();
                    join_handles.push(tokio::spawn(async move {
                        let can_connect = node_can_tcp_connect(&node_src, &node_dst, port).await;
                        let should_connect = should_be_able_to_connect(&node_src, &node_dst, port);

                        assert_eq!(
                            can_connect, should_connect,
                            "TCP connectivity from node {} to node {} on port {} did not match the \
                            expected firewall rules: should be able to connect: {}, but connection \
                            attempt returned {}",
                            node_src.node_id, node_dst.node_id, port, should_connect, can_connect
                        );
                    }));
                }
            }
        }

        for handle in join_handles {
            handle.await.expect("task panicked");
        }
    });
}

async fn add_necessary_ports_registry_rule(nns_node: &IcNodeSnapshot, log: &Logger) {
    let ipv6_prefixes = get_config().firewall.unwrap().default_rules[0]
        .ipv6_prefixes
        .clone();
    let rule = FirewallRule {
        ipv4_prefixes: vec![],
        ipv6_prefixes,
        ports: vec![22, 9090, 9091],
        action: FirewallAction::Allow as i32,
        comment: "Test rule".to_string(),
        user: None,
        direction: Some(FirewallRuleDirection::Inbound as i32),
    };
    execute_add_firewall_rules_proposal(
        log,
        nns_node,
        FirewallRulesScope::Global,
        vec![rule],
        vec![0],
        vec![],
    )
    .await;
}

/// Returns whether a TCP connection should be established from `node_src` to `node_dst:port`
/// according to their subnet types.
fn should_be_able_to_connect(
    node_src: &IcNodeSnapshot,
    node_dst: &IcNodeSnapshot,
    port: u32,
) -> bool {
    if TCP_PORTS_CLOSED.contains(&port) {
        // This port is closed to everyone, so we should NOT be able to connect.
        return false;
    }

    if TCP_PORTS_ALL_NODES.contains(&port) {
        // This port is open to all IC nodes, so we should be able to connect.
        return true;
    }

    assert!(
        TCP_PORTS_WHITELISTED_ONLY.contains(&port),
        "Port {port} is not in any of the tested port lists, so the test does \
        not specify whether it should be open or closed."
    );

    if CLOUD_ENGINE_NODE_REWARD_TYPES.contains(&node_dst.node_reward_type()) {
        // Cloud engine nodes accept incoming connections from everyone
        return true;
    }

    if CLOUD_ENGINE_NODE_REWARD_TYPES.contains(&node_src.node_reward_type()) {
        // Non-cloud engine nodes do not accept incoming connections from cloud engine nodes on
        // whitelisted-only ports.
        return false;
    }

    // If we are here, the connection is between two non-cloud engine nodes, which are whitelisted
    // between each other.
    true
}

/// Via an SSH session to `node_src`, runs a `nc` probe to `node_dst:port`
/// and returns `true` when a TCP connection could be established.
async fn node_can_tcp_connect(
    node_src: &IcNodeSnapshot,
    node_dst: &IcNodeSnapshot,
    port: u32,
) -> bool {
    let script = format!(
        "nc -z -w 5 {} {} && echo success || echo failure",
        node_dst.get_ip_addr(),
        port
    );
    node_src
        .block_on_bash_script_async(&script)
        .await
        .is_ok_and(|output| output.contains("success"))
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(firewall_correctness_test))
        .execute_from_args()?;
    Ok(())
}
