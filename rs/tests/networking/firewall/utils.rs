use candid::CandidType;
use ic_nns_governance_api::NnsFunction;
use ic_protobuf::registry::firewall::v1::FirewallRule;
use ic_registry_keys::FirewallRulesScope;
use ic_system_test_driver::{
    driver::test_env_api::{HasPublicApiUrl, IcNodeSnapshot},
    nns::{
        await_proposal_execution, get_governance_canister, submit_external_proposal_with_test_id,
        vote_execute_proposal_assert_executed,
    },
    util,
};
use registry_canister::mutations::firewall::{
    AddFirewallRulesPayload, RemoveFirewallRulesPayload, UpdateFirewallRulesPayload,
    compute_firewall_ruleset_hash,
};
use slog::Logger;
use std::time::Duration;

pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

async fn execute_firewall_proposal<T: CandidType>(
    log: &Logger,
    nns_node: &IcNodeSnapshot,
    function: NnsFunction,
    proposal_payload: T,
) {
    let nns = util::runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns);
    let proposal_id =
        submit_external_proposal_with_test_id(&governance, function, proposal_payload).await;
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;
    await_proposal_execution(log, &governance, proposal_id, BACKOFF_DELAY, WAIT_TIMEOUT).await;
}

pub async fn execute_add_firewall_rules_proposal(
    log: &Logger,
    nns_node: &IcNodeSnapshot,
    scope: FirewallRulesScope,
    new_rules: Vec<FirewallRule>,
    positions_sorted: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) {
    let mut all_rules = previous_rules;
    for (rule, pos) in new_rules.iter().zip(positions_sorted.clone()) {
        all_rules.insert(pos as usize, rule.clone());
    }
    let payload = AddFirewallRulesPayload {
        scope,
        rules: new_rules,
        positions: positions_sorted,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    };
    let function = NnsFunction::AddFirewallRules;

    execute_firewall_proposal(log, nns_node, function, payload).await
}

pub async fn execute_remove_firewall_rules_proposal(
    log: &Logger,
    nns_node: &IcNodeSnapshot,
    scope: FirewallRulesScope,
    positions: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) {
    let mut all_rules = previous_rules;
    let mut positions_sorted = positions.clone();
    positions_sorted.sort_unstable();
    positions_sorted.reverse();
    for pos in positions_sorted {
        all_rules.remove(pos as usize);
    }
    let payload = RemoveFirewallRulesPayload {
        scope,
        positions,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    };
    let function = NnsFunction::RemoveFirewallRules;

    execute_firewall_proposal(log, nns_node, function, payload).await
}

pub async fn execute_update_firewall_rules_proposal(
    log: &Logger,
    nns_node: &IcNodeSnapshot,
    scope: FirewallRulesScope,
    new_rules: Vec<FirewallRule>,
    positions_sorted: Vec<i32>,
    previous_rules: Vec<FirewallRule>,
) {
    let mut all_rules = previous_rules;
    for (rule, pos) in new_rules.iter().zip(positions_sorted.clone()) {
        all_rules[pos as usize] = rule.clone();
    }
    let payload = UpdateFirewallRulesPayload {
        scope,
        rules: new_rules,
        positions: positions_sorted,
        expected_hash: compute_firewall_ruleset_hash(&all_rules),
    };
    let function = NnsFunction::UpdateFirewallRules;

    execute_firewall_proposal(log, nns_node, function, payload).await
}
