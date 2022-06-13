/* tag::catalog[]
Title:: Firewall

Goal:: Checks the precedence levels of the firewall configurations

Runbook::
. set up the testnet and startup firewall configuration of replica_nodes
. get a existing rule that allows access at a port
. add a firewall that's a copy of above fetcehd rule, but denies access of the port
. verify the port is unreachable with the new rule
. add another rule to position 0, but now allowing access to the port
. verify the port is now reachable again

Success::
. the port is denied with first new rule created
. the port is allowed access with second new rule created

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::nns::{
    await_proposal_execution, submit_external_proposal_with_test_id,
    vote_execute_proposal_assert_executed, NnsExt,
};
use crate::util::{self, block_on, get_random_nns_node_endpoint};
use ic_fondue::ic_manager::{IcEndpoint, IcHandle};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule};
use ic_registry_keys::FirewallRulesScope;
use ic_registry_subnet_type::SubnetType;
use registry_canister::mutations::firewall::{
    compute_firewall_ruleset_hash, AddFirewallRulesPayload,
};
use reqwest::blocking::Client;
use slog::info;
use std::time::{Duration, Instant};
use url::Url;

const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const BACKOFF_DELAY: Duration = Duration::from_secs(5);

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::System, 1))
        .add_subnet(Subnet::fast(SubnetType::Application, 2))
}

pub fn override_firewall_rules_with_priority(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let log = ctx.logger.clone();
    let mut rng = ctx.rng.clone();
    let http_client = reqwest::blocking::ClientBuilder::new()
        .timeout(BACKOFF_DELAY)
        .build()
        .expect("Could not build reqwest client.");

    ctx.install_nns_canisters(&handle, true);
    let nns_endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let app_endpoints: Vec<_> = handle
        .as_permutation(&mut rng)
        .filter(|e| e.subnet.as_ref().map(|s| s.type_of) == Some(SubnetType::Application))
        .collect();

    let toggle_endpoint = app_endpoints[0];
    let mut toggle_metrics_url = toggle_endpoint.url.clone();
    toggle_metrics_url.set_port(Some(9090)).unwrap();

    // await for app node to be ready
    block_on(toggle_endpoint.assert_ready(ctx));

    // assert before a new rule is added, port 9090 is available
    assert!(get_request_succeeds(
        &log,
        &http_client,
        &toggle_metrics_url
    ));
    // assert port 8080 is available
    assert!(get_request_succeeds(
        &log,
        &http_client,
        &toggle_endpoint.url
    ));

    // add a firewall rule that disables 9090 on the first node
    let deny_port = FirewallAction::Deny;
    block_on(set_default_registry_rules(nns_endpoint));
    let previous_rules = block_on(create_allow_or_deny_rule_for_node_port(
        ctx,
        nns_endpoint,
        toggle_endpoint,
        deny_port,
        vec![],
    ));
    await_rule_takes_effect(&log, &http_client, &toggle_metrics_url, deny_port);

    // assert port 9090 is now turned off
    assert!(!get_request_succeeds(
        &log,
        &http_client,
        &toggle_metrics_url
    ));
    assert!(get_request_succeeds(
        &log,
        &http_client,
        &toggle_endpoint.url
    ));

    // add a firewall rule that re-enables port 9090
    let allow_port = FirewallAction::Allow;
    block_on(create_allow_or_deny_rule_for_node_port(
        ctx,
        nns_endpoint,
        toggle_endpoint,
        allow_port,
        previous_rules,
    ));
    await_rule_takes_effect(&log, &http_client, &toggle_metrics_url, allow_port);

    // assert that 9090 is now restored
    assert!(get_request_succeeds(
        &log,
        &http_client,
        &toggle_metrics_url
    ));
}

async fn set_default_registry_rules(nns_endpoint: &IcEndpoint) {
    let firewall_config = util::get_config().firewall.unwrap();
    let default_rule = firewall_config.default_rules[0].clone();
    let default_rules = vec![default_rule];
    let proposal = AddFirewallRulesPayload {
        scope: FirewallRulesScope::ReplicaNodes,
        rules: default_rules.clone(),
        positions: vec![0],
        expected_hash: compute_firewall_ruleset_hash(&default_rules),
    };
    let nns = util::runtime_from_url(nns_endpoint.url.clone());
    let governance = crate::nns::get_governance_canister(&nns);
    let proposal_id =
        submit_external_proposal_with_test_id(&governance, NnsFunction::AddFirewallRules, proposal)
            .await;
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;
}

async fn create_allow_or_deny_rule_for_node_port(
    ctx: &ic_fondue::pot::Context,
    nns_endpoint: &IcEndpoint,
    node_endpoint: &IcEndpoint,
    new_state: FirewallAction,
    previous_rules: Vec<FirewallRule>,
) -> Vec<FirewallRule> {
    let proposal = prepare_proposal_payload(node_endpoint, new_state, previous_rules);
    let nns = util::runtime_from_url(nns_endpoint.url.clone());
    let governance = crate::nns::get_governance_canister(&nns);
    let proposal_id = submit_external_proposal_with_test_id(
        &governance,
        NnsFunction::AddFirewallRules,
        proposal.clone(),
    )
    .await;
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    // wait until 9090 is closed
    await_proposal_execution(ctx, &governance, proposal_id, BACKOFF_DELAY, WAIT_TIMEOUT).await;

    proposal.rules
}

fn await_rule_takes_effect(
    log: &slog::Logger,
    http_client: &Client,
    url: &Url,
    new_state: FirewallAction,
) {
    let allowed_or_denied = if new_state == FirewallAction::Allow {
        "allowed"
    } else {
        "denied"
    };
    while get_request_succeeds(log, http_client, url) != (new_state == FirewallAction::Allow) {
        let start = Instant::now();
        if start.elapsed() > WAIT_TIMEOUT {
            panic!(
                "Waiting timed out for URL {} to be {}!",
                url, allowed_or_denied
            );
        }
        std::thread::sleep(BACKOFF_DELAY);
    }
    info!(log, "Url {} is now {}", url, allowed_or_denied);
}

fn get_request_succeeds(log: &slog::Logger, c: &Client, url: &Url) -> bool {
    match c.get(url.clone()).send() {
        Ok(_) => {
            info!(log, "Get request succeeded ({}).", url);
            true
        }
        Err(e) => {
            info!(log, "Get request failed ({}) failed: {:?}", url, e);
            false
        }
    }
}

fn prepare_proposal_payload(
    node_endpoint: &IcEndpoint,
    new_state: FirewallAction,
    previous_rules: Vec<FirewallRule>,
) -> AddFirewallRulesPayload {
    // get the default firewall rule ipv6 ranges
    let firewall_config = util::get_config().firewall.unwrap();
    let default_rule = firewall_config.default_rules[0].clone();

    let new_rule = FirewallRule {
        ipv6_prefixes: default_rule.ipv6_prefixes,
        ports: vec![9090],
        action: new_state as i32,
        ipv4_prefixes: vec![],
        comment: format!(
            "Adding a rule to {} port 9090 on node {}",
            if new_state == FirewallAction::Allow {
                "allow"
            } else {
                "deny"
            },
            node_endpoint.node_id
        ),
    };

    let mut all_rules = previous_rules;
    all_rules.insert(0, new_rule.clone());
    AddFirewallRulesPayload {
        scope: FirewallRulesScope::Node(node_endpoint.node_id),
        rules: vec![new_rule],
        positions: vec![0],
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    }
}
