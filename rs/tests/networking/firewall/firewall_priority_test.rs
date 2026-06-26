/* tag::catalog[]
Title:: Firewall Priority

Goal:: Checks the precedence levels of the firewall configurations

Runbook::
. set up the testnet and startup firewall configuration of replica_nodes
. get the existing rule that allows access at a port
. add a firewall rule that's a copy of above fetched rule
. verify that ports are still reachable
. add another rule that is a copy of the above, but denies access to port 9090, with higher priority
. verify the port is unreachable with the new rule
. add another rule to position 0, but now allowing access to port 9090
. verify the port is now reachable again
. remove that last added rule
. verify that the port is unreachable
. update the other existing rule to block port 9091 instead of 9090
. verify that port 9091 is unreachable, and 9090 is reachable
. update the same rule to block port 8080
. verify that port 8080 is unreachable (from the test machine)
. verify that port 8080 is still reachable from replica nodes

Success::
. all connectivity tests succeed as expected

end::catalog[] */

use anyhow::Result;
use ic_firewall_system_test_utils::{
    BACKOFF_DELAY, execute_add_firewall_rules_proposal, execute_remove_firewall_rules_proposal,
    execute_update_firewall_rules_proposal,
};
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule, FirewallRuleDirection};
use ic_registry_keys::FirewallRulesScope;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            NnsInstallationBuilder, SshSession,
        },
        test_setup::SystemTestBackend,
    },
    systest,
    util::{self, block_on},
};
use slog::{Logger, info};
use std::time::Duration;
use url::Url;

const INITIAL_WAIT: Duration = Duration::from_secs(10);
const MAX_WAIT: Duration = Duration::from_secs(120);

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System, 1))
        .add_subnet(Subnet::fast(SubnetType::Application, 2))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn override_firewall_rules_with_priority(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    let toggle_endpoint = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    info!(log, "Installing NNS canisters on the root subnet...");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(&log, "NNS canisters installed successfully.");

    let mut toggle_metrics_url = toggle_endpoint.get_public_url();
    toggle_metrics_url.set_port(Some(9090)).unwrap();
    let mut toggle_9091_url = toggle_endpoint.get_public_url();
    toggle_9091_url.set_port(Some(9091)).unwrap();
    let mut toggle_xnet_url = toggle_endpoint.get_public_url();
    toggle_xnet_url.set_port(Some(2497)).unwrap();

    info!(log, "Firewall priority test is starting");

    // assert before a new rule is added, port 9090 is available
    assert!(get_request_succeeds(&toggle_metrics_url));
    // assert port 8080 is available
    assert!(get_request_succeeds(&toggle_endpoint.get_public_url()));

    info!(
        log,
        "Firewall priority test is ready. Setting default rules in the registry..."
    );

    // Set the default rules in the registry for the first time
    block_on(set_default_registry_rules(&log, &nns_node));

    info!(
        log,
        "Default rules set. Testing connectivity with backoff..."
    );

    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert that ports 9090 and 8080 are still available
            get_request_succeeds(&toggle_metrics_url)
                && get_request_succeeds(&toggle_endpoint.get_public_url())
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    info!(
        log,
        "Succeeded. Adding a rule to deny port 9090 on node {}...", toggle_endpoint.node_id
    );

    // add a firewall rule that disables 9090 on the first node
    let firewall_config = util::get_config().firewall.unwrap();

    let deny_port = FirewallAction::Deny;
    let mut deny_prefixes = firewall_config.default_rules[0].ipv6_prefixes.clone();
    // On the Local backend the driver reaches the nodes from a per-group
    // management address that lives *outside* the node `/64` (so the GuestOS
    // firewall's built-in accept for the node's own prefix does not shadow the
    // rules under test). That source is in the ULA range `fd00::/8`, which the
    // Farm `default_rules` prefixes do not cover, so add it explicitly here;
    // otherwise the deny rule would never match the driver and the port would
    // stay reachable. Node-to-node traffic on 8080 is unaffected: it is allowed
    // at higher priority by the orchestrator's automatic node whitelisting.
    if SystemTestBackend::read_attribute(&env) == SystemTestBackend::Local {
        deny_prefixes.push("fd00::/8".to_string());
    }
    let mut node_rules = vec![FirewallRule {
        ipv4_prefixes: vec![],
        ipv6_prefixes: deny_prefixes,
        ports: vec![9090],
        action: deny_port.into(),
        comment: "Test rule".to_string(),
        user: None,
        direction: Some(FirewallRuleDirection::Inbound as i32),
    }];
    block_on(execute_add_firewall_rules_proposal(
        &log,
        &nns_node,
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        node_rules.clone(),
        vec![0],
        vec![],
    ));

    info!(log, "New rule is set. Testing connectivity with backoff...");
    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 9090 is now turned off
            !get_request_succeeds(&toggle_metrics_url)
                && get_request_succeeds(&toggle_endpoint.get_public_url())
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    info!(
        log,
        "Succeeded. Adding a higher priority rule to allow port 9090 on node {}...",
        toggle_endpoint.node_id
    );
    // add a firewall rule that re-enables port 9090
    let allow_port = FirewallAction::Allow;
    let mut new_rule = node_rules[0].clone();
    new_rule.action = allow_port.into();
    block_on(execute_add_firewall_rules_proposal(
        &log,
        &nns_node,
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![new_rule.clone()],
        vec![0],
        node_rules.clone(),
    ));
    node_rules = vec![new_rule, node_rules[0].clone()];

    info!(log, "New rule is set. Testing connectivity with backoff...");
    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 9090 is now restored
            get_request_succeeds(&toggle_metrics_url)
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    info!(
        log,
        "Succeeded. Removing the higher priority rule for node {}...", toggle_endpoint.node_id
    );

    // Remove the last rule we added
    block_on(execute_remove_firewall_rules_proposal(
        &log,
        &nns_node,
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![0],
        node_rules.clone(),
    ));
    node_rules = vec![node_rules[1].clone()];

    info!(log, "Rule is removed. Testing connectivity with backoff...");
    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 9090 is now turned off
            !get_request_succeeds(&toggle_metrics_url)
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    info!(
        log,
        "Succeeded. Updating the existing rule for node {} to block port 9091...",
        toggle_endpoint.node_id
    );

    // Update the other existing node-specific rule to block port 9091
    let mut updated_rule = node_rules[0].clone();
    updated_rule.ports = vec![9091];
    block_on(execute_update_firewall_rules_proposal(
        &log,
        &nns_node,
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![updated_rule.clone()],
        vec![0],
        node_rules,
    ));
    node_rules = vec![updated_rule];

    info!(log, "Rule is updated. Testing connectivity with backoff...");
    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 9091 is now turned off and port 9090 is now turned on
            !get_request_succeeds(&toggle_9091_url) && get_request_succeeds(&toggle_metrics_url)
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    info!(
        log,
        "Succeeded. Updating the existing rule for node {} to block http port...",
        toggle_endpoint.node_id
    );

    // Update the existing node-specific rule to block port {http}
    let mut updated_rule = node_rules[0].clone();
    updated_rule.ports = vec![toggle_endpoint.get_public_url().port().unwrap().into()];
    block_on(execute_update_firewall_rules_proposal(
        &log,
        &nns_node,
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![updated_rule],
        vec![0],
        node_rules,
    ));

    info!(log, "Rule is updated. Testing connectivity with backoff...");

    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 8080 is now turned off
            !get_request_succeeds(&toggle_endpoint.get_public_url())
        },
        INITIAL_WAIT,
        BACKOFF_DELAY,
        MAX_WAIT
    ));

    // Verify that port {xnet} is reachable on this node from other nodes
    let node = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
        .nodes()
        .next()
        .unwrap();

    let session = node.block_on_ssh_session().unwrap();
    info!(
        log,
        "Calling curl {} from node {}",
        toggle_endpoint.get_public_url(),
        node.node_id
    );

    let res = node.block_on_bash_script_from_session(
        &session,
        &format!("timeout 10s curl {}", toggle_endpoint.get_public_url()),
    );
    assert!(res.is_ok());

    info!(log, "Firewall priority tests has succeeded.")
}

async fn set_default_registry_rules(log: &Logger, nns_node: &IcNodeSnapshot) {
    let firewall_config = util::get_config().firewall.unwrap();
    let default_rules = firewall_config.default_rules;
    execute_add_firewall_rules_proposal(
        log,
        nns_node,
        FirewallRulesScope::ReplicaNodes,
        default_rules.clone(),
        (0..default_rules.len()).map(|u| u as i32).collect(),
        vec![],
    )
    .await
}

fn get_request_succeeds(url: &Url) -> bool {
    let http_client = reqwest::blocking::ClientBuilder::new()
        .timeout(BACKOFF_DELAY)
        .build()
        .expect("Could not build reqwest client.");

    http_client.get(url.clone()).send().is_ok()
}

fn await_rule_execution_with_backoff(
    log: &Logger,
    test: &dyn Fn() -> bool,
    initial_wait: Duration,
    linear_backoff: Duration,
    max_wait: Duration,
) -> bool {
    let mut total_duration = initial_wait;
    std::thread::sleep(initial_wait);
    if test() {
        info!(
            log,
            "(Waited {} seconds, succeeded)",
            total_duration.as_secs()
        );
        return true;
    }
    while total_duration < max_wait {
        std::thread::sleep(linear_backoff);
        total_duration += linear_backoff;
        if test() {
            info!(
                log,
                "(Waited {} seconds, succeeded)",
                total_duration.as_secs()
            );
            return true;
        }
    }
    info!(log, "(Waited {} seconds, failed)", total_duration.as_secs());
    false
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(override_firewall_rules_with_priority))
        .execute_from_args()?;

    Ok(())
}
