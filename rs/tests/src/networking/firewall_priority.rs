/* tag::catalog[]
Title:: Firewall

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

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, SshSession, ADMIN};
use crate::nns::{
    await_proposal_execution, submit_external_proposal_with_test_id,
    vote_execute_proposal_assert_executed, NnsExt,
};
use crate::util::{self, block_on, get_random_nns_node_endpoint};
use candid::CandidType;
use ic_fondue::ic_manager::IcEndpoint;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule};
use ic_registry_keys::FirewallRulesScope;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::firewall::{
    compute_firewall_ruleset_hash, AddFirewallRulesPayload, RemoveFirewallRulesPayload,
    UpdateFirewallRulesPayload,
};
use slog::info;
use ssh2::Session;
use std::io::{self, Read, Write};
use std::time::Duration;
use url::Url;

const INITIAL_WAIT: Duration = Duration::from_secs(10);
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const BACKOFF_DELAY: Duration = Duration::from_secs(5);
const MAX_WAIT: Duration = Duration::from_secs(120);

enum Proposal<T: CandidType> {
    Add(T, NnsFunction),
    Remove(T, NnsFunction),
    Update(T, NnsFunction),
}

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System, 1))
        .add_subnet(Subnet::fast(SubnetType::Application, 2))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn override_firewall_rules_with_priority(env: TestEnv) {
    let (handle, ref ctx) = get_ic_handle_and_ctx(env.clone());

    let log = ctx.logger.clone();
    let mut rng = ctx.rng.clone();

    ctx.install_nns_canisters(&handle, true);
    let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let app_endpoints: Vec<_> = handle
        .as_permutation(&mut rng)
        .filter(|e| e.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::Application))
        .collect();

    let toggle_endpoint = app_endpoints[0];
    let mut toggle_metrics_url = toggle_endpoint.url.clone();
    toggle_metrics_url.set_port(Some(9090)).unwrap();
    let mut toggle_9091_url = toggle_endpoint.url.clone();
    toggle_9091_url.set_port(Some(9091)).unwrap();
    let mut toggle_xnet_url = toggle_endpoint.url.clone();
    toggle_xnet_url.set_port(Some(2497)).unwrap();

    info!(log, "Firewall priority test is starting");

    // await for app node to be ready
    block_on(toggle_endpoint.assert_ready(ctx));

    // assert before a new rule is added, port 9090 is available
    assert!(get_request_succeeds(&toggle_metrics_url));
    // assert port 8080 is available
    assert!(get_request_succeeds(&toggle_endpoint.url));

    info!(
        log,
        "Firewall priority test is ready. Setting default rules in the registry..."
    );

    // Set the default rules in the registry for the first time
    block_on(set_default_registry_rules(ctx, nns_endpoint));

    info!(
        log,
        "Default rules set. Testing connectivity with backoff..."
    );

    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert that ports 9090 and 8080 are still available
            get_request_succeeds(&toggle_metrics_url) && get_request_succeeds(&toggle_endpoint.url)
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
    let mut node_rules = vec![FirewallRule {
        ipv4_prefixes: vec![],
        ipv6_prefixes: firewall_config.default_rules[0].ipv6_prefixes.clone(),
        ports: vec![9090],
        action: deny_port.into(),
        comment: "Test rule".to_string(),
    }];
    let proposal = prepare_add_rules_proposal(
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        node_rules.clone(),
        vec![0],
        vec![],
    );
    block_on(execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Add(proposal, NnsFunction::AddFirewallRules),
    ));

    info!(log, "New rule is set. Testing connectivity with backoff...");
    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 9090 is now turned off
            !get_request_succeeds(&toggle_metrics_url) && get_request_succeeds(&toggle_endpoint.url)
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
    let proposal = prepare_add_rules_proposal(
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![new_rule.clone()],
        vec![0],
        node_rules.clone(),
    );
    node_rules = vec![new_rule, node_rules[0].clone()];
    block_on(execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Add(proposal, NnsFunction::AddFirewallRules),
    ));

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
    let proposal = prepare_remove_rules_proposal(
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![0],
        node_rules.clone(),
    );
    node_rules = vec![node_rules[1].clone()];
    block_on(execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Remove(proposal, NnsFunction::RemoveFirewallRules),
    ));

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
    let proposal = prepare_update_rules_proposal(
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![updated_rule.clone()],
        vec![0],
        node_rules,
    );
    node_rules = vec![updated_rule];
    block_on(execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Update(proposal, NnsFunction::UpdateFirewallRules),
    ));

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
    updated_rule.ports = vec![toggle_endpoint.url.port().unwrap().into()];
    let proposal = prepare_update_rules_proposal(
        FirewallRulesScope::Node(toggle_endpoint.node_id),
        vec![updated_rule],
        vec![0],
        node_rules,
    );
    block_on(execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Update(proposal, NnsFunction::UpdateFirewallRules),
    ));

    info!(log, "Rule is updated. Testing connectivity with backoff...");

    assert!(await_rule_execution_with_backoff(
        &log,
        &|| {
            // assert port 8080 is now turned off
            !get_request_succeeds(&toggle_endpoint.url)
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

    let session = node.block_on_ssh_session(ADMIN).unwrap();
    info!(
        log,
        "Calling curl {} from node {}", toggle_endpoint.url, node.node_id
    );
    let res = execute_ssh_command(
        &session,
        format!("timeout 10s curl {}", toggle_endpoint.url),
    );
    assert_eq!(res.unwrap(), 0);

    info!(log, "Firewall priority tests has succeeded.")
}

fn execute_ssh_command(session: &Session, ssh_command: String) -> Result<i32, io::Error> {
    let mut channel = session.channel_session()?;
    channel.exec("bash")?;
    channel.write_all(ssh_command.as_bytes())?;
    channel.flush()?;
    channel.send_eof()?;
    let mut stderr = String::new();
    let mut command_output = String::new();
    channel.stderr().read_to_string(&mut stderr)?;
    channel.read_to_string(&mut command_output)?;
    channel.close()?;
    channel.wait_close()?;
    Ok(channel.exit_status()?)
}

async fn set_default_registry_rules(ctx: &ic_fondue::pot::Context, nns_endpoint: &IcEndpoint) {
    let firewall_config = util::get_config().firewall.unwrap();
    let default_rules = firewall_config.default_rules.clone();
    let proposal = prepare_add_rules_proposal(
        FirewallRulesScope::ReplicaNodes,
        default_rules.clone(),
        (0..default_rules.len()).map(|u| u as i32).collect(),
        vec![],
    );
    execute_proposal(
        ctx,
        nns_endpoint,
        Proposal::Add(proposal, NnsFunction::AddFirewallRules),
    )
    .await;
}

async fn execute_proposal<T: Clone + CandidType>(
    ctx: &ic_fondue::pot::Context,
    nns_endpoint: &IcEndpoint,
    proposal: Proposal<T>,
) {
    let (proposal_payload, function) = match proposal {
        Proposal::Add(payload, func) => (payload, func),
        Proposal::Remove(payload, func) => (payload, func),
        Proposal::Update(payload, func) => (payload, func),
    };
    let nns = util::runtime_from_url(nns_endpoint.url.clone());
    let governance = crate::nns::get_governance_canister(&nns);
    let proposal_id =
        submit_external_proposal_with_test_id(&governance, function, proposal_payload.clone())
            .await;
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    // wait until proposal is executed
    await_proposal_execution(ctx, &governance, proposal_id, BACKOFF_DELAY, WAIT_TIMEOUT).await;
}

fn get_request_succeeds(url: &Url) -> bool {
    let http_client = reqwest::blocking::ClientBuilder::new()
        .timeout(BACKOFF_DELAY)
        .build()
        .expect("Could not build reqwest client.");

    http_client.get(url.clone()).send().is_ok()
}

fn prepare_add_rules_proposal(
    scope: FirewallRulesScope,
    new_rules: Vec<FirewallRule>,
    positions_sorted: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) -> AddFirewallRulesPayload {
    let mut all_rules = previous_rules;
    for (rule, pos) in new_rules.iter().zip(positions_sorted.clone()) {
        all_rules.insert(pos as usize, rule.clone());
    }
    AddFirewallRulesPayload {
        scope,
        rules: new_rules,
        positions: positions_sorted,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    }
}

fn prepare_remove_rules_proposal(
    scope: FirewallRulesScope,
    positions: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) -> RemoveFirewallRulesPayload {
    let mut all_rules = previous_rules;
    let mut positions_sorted = positions.clone();
    positions_sorted.sort_unstable();
    positions_sorted.reverse();
    for pos in positions_sorted {
        all_rules.remove(pos as usize);
    }
    RemoveFirewallRulesPayload {
        scope,
        positions,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    }
}

fn prepare_update_rules_proposal(
    scope: FirewallRulesScope,
    new_rules: Vec<FirewallRule>,
    positions_sorted: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) -> UpdateFirewallRulesPayload {
    let mut all_rules = previous_rules;
    for (rule, pos) in new_rules.iter().zip(positions_sorted.clone()) {
        all_rules[pos as usize] = rule.clone();
    }
    UpdateFirewallRulesPayload {
        scope,
        rules: new_rules,
        positions: positions_sorted,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    }
}

fn await_rule_execution_with_backoff(
    log: &slog::Logger,
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
