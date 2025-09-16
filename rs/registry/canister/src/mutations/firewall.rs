use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_crypto_sha2::Sha256;
use ic_protobuf::registry::firewall::v1::{FirewallRule, FirewallRuleSet};
use ic_registry_keys::{FirewallRulesScope, make_firewall_rules_record_key};
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue, registry_mutation};
use prost::Message;
use std::fmt::Write;

impl Registry {
    /// Set firewall rules for a given scope.
    fn do_set_firewall_rules(
        &mut self,
        scope: &FirewallRulesScope,
        rules: Vec<FirewallRule>,
        expected_hash: String,
    ) {
        println!(
            "{LOG_PREFIX}do_set_firewall_rules: scope: {scope:?}, rules: {rules:?}, expected_hash: {expected_hash:?}"
        );

        // Compare hash
        let result_hash = compute_firewall_ruleset_hash(&rules);
        if result_hash != expected_hash {
            panic!(
                "{LOG_PREFIX}Provided expected hash for new firewall ruleset does not match. Expected hash: {expected_hash:?}, actual hash: {result_hash:?}."
            );
        }

        // Do the registry mutation
        let ruleset = FirewallRuleSet { entries: rules };

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_firewall_rules_record_key(scope).into_bytes(),
            value: ruleset.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    fn fetch_current_ruleset(&mut self, scope: &FirewallRulesScope) -> Vec<FirewallRule> {
        // Fetch current rules for scope
        let key = make_firewall_rules_record_key(scope).into_bytes();

        let default_registry_value = RegistryValue {
            value: FirewallRuleSet { entries: vec![] }.encode_to_vec(),
            version: 0,
            deletion_marker: false,
            timestamp_nanoseconds: 0,
        };

        let RegistryValue {
            value: current_ruleset_vec,
            version: _,
            deletion_marker: _,
            timestamp_nanoseconds: _,
        } = self
            .get(&key, self.latest_version())
            .unwrap_or(default_registry_value);

        let current_ruleset = FirewallRuleSet::decode(current_ruleset_vec.as_slice()).unwrap();
        current_ruleset.entries
    }

    /// Add firewall rules for a given scope.
    /// The given rules are added at the given positions. If multiple rules are added at the
    /// same position, the order is maintained.
    ///
    /// This method is called by the governance canister.
    pub fn do_add_firewall_rules(&mut self, payload: AddFirewallRulesPayload) {
        println!(
            "{}do_add_firewall_rules: scope: {:?}, rules: {:?}, positions: {:?}, expected_hash: {:?}",
            LOG_PREFIX, payload.scope, payload.rules, payload.positions, payload.expected_hash
        );

        let mut entries = self.fetch_current_ruleset(&payload.scope);
        add_firewall_rules_compute_entries(&mut entries, &payload);

        self.do_set_firewall_rules(&payload.scope, entries, payload.expected_hash);
    }

    /// Remove firewall rules for a given scope.
    /// Removes the rules at the given positions.
    ///
    /// This method is called by the governance canister.
    pub fn do_remove_firewall_rules(&mut self, payload: RemoveFirewallRulesPayload) {
        println!(
            "{}do_remove_firewall_rules: scope: {:?}, positions: {:?}, expected_hash: {:?}",
            LOG_PREFIX, payload.scope, payload.positions, payload.expected_hash
        );

        let mut entries = self.fetch_current_ruleset(&payload.scope);
        remove_firewall_rules_compute_entries(&mut entries, &payload);

        self.do_set_firewall_rules(&payload.scope, entries, payload.expected_hash);
    }

    /// Update firewall rules for a given scope.
    /// Replaces the existing rules at the given positions with the given rules.
    ///
    /// This method is called by the governance canister.
    pub fn do_update_firewall_rules(&mut self, payload: UpdateFirewallRulesPayload) {
        println!(
            "{}do_update_firewall_rules: scope: {:?}, rules: {:?}, positions: {:?}, expected_hash: {:?}",
            LOG_PREFIX, payload.scope, payload.rules, payload.positions, payload.expected_hash
        );

        let mut entries = self.fetch_current_ruleset(&payload.scope);
        update_firewall_rules_compute_entries(&mut entries, &payload);

        self.do_set_firewall_rules(&payload.scope, entries, payload.expected_hash);
    }
}

/// Computes a hash of a given set of firewall rules. This is used to verify that
/// a mutation to this ruleset results with the expected rules.
pub fn compute_firewall_ruleset_hash(rules: &[FirewallRule]) -> String {
    let mut hasher = Sha256::new();
    for rule in rules {
        hasher.write(&rule.encode_to_vec());
    }
    let bytes = &hasher.finish();
    let mut result_hash = String::new();
    for b in bytes {
        let _ = write!(result_hash, "{b:02X}");
    }
    result_hash
}

/// Adds firewall rules. Rules are added to the ruleset given in the payload,
/// at the provided positions.
/// This function can be used both by the mutation code as well as by any testing code and
/// utilities such as ic-admin.
pub fn add_firewall_rules_compute_entries(
    current_entries: &mut Vec<FirewallRule>,
    payload: &AddFirewallRulesPayload,
) {
    if payload.positions.len() != payload.rules.len() {
        panic!(
            "{}Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
            LOG_PREFIX, payload.positions, payload.rules
        );
    }

    let mut tuples: Vec<(i32, FirewallRule)> = payload
        .positions
        .iter()
        .cloned()
        .zip(payload.rules.iter().cloned())
        .collect();

    // Add entries from the front to back (sorting with stable sort)
    tuples.sort_by(|a, b| a.0.cmp(&b.0));

    for (already_inserted_above, (mut pos, rule)) in tuples.into_iter().enumerate() {
        // For every new entry we push the position down by the number of already-inserted entries.
        // This way we preserve the position requested by the caller.
        // Multiple entries with the same position will be inserted one after the other, in the original order.
        pos += already_inserted_above as i32;
        if pos > current_entries.len() as i32 {
            panic!(
                "{}Provided position does not match the size of the existing ruleset. Position: {:?}, ruleset size: {:?}.",
                LOG_PREFIX,
                pos,
                current_entries.len()
            );
        }
        current_entries.insert(pos as usize, rule);
    }
}

/// Removes firewall rules. Rules are removed from the ruleset given in the payload,
/// from the provided positions.
/// This function can be used both by the mutation code as well as by any testing code and
/// utilities such as ic-admin.
pub fn remove_firewall_rules_compute_entries(
    current_entries: &mut Vec<FirewallRule>,
    payload: &RemoveFirewallRulesPayload,
) {
    // Remove entries from the back to front to preserve positions
    let mut positions = payload.positions.clone();
    positions.sort_unstable();
    positions.reverse();
    for i in positions {
        current_entries.remove(i as usize);
    }
}

/// Performs a firewall rules update. A rules update replaces existing rules in the given
/// ruleset in the payload, at the specified positions, with new given rules.
/// This function can be used both by the mutation code as well as by any testing code and
/// utilities such as ic-admin.
pub fn update_firewall_rules_compute_entries(
    current_entries: &mut [FirewallRule],
    payload: &UpdateFirewallRulesPayload,
) {
    if payload.positions.len() != payload.rules.len() {
        panic!(
            "{}Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
            LOG_PREFIX, payload.positions, payload.rules
        );
    }

    // Update the entries
    for (rule_idx, pos) in payload.positions.clone().into_iter().enumerate() {
        if pos < 0 || pos >= current_entries.len() as i32 {
            panic!(
                "{}Provided position is out of bounds for the existing ruleset. Position: {:?}, ruleset size: {:?}.",
                LOG_PREFIX,
                pos,
                current_entries.len()
            );
        }
        current_entries[pos as usize] = payload.rules[rule_idx].clone();
    }
}

/// The payload of a proposal to add firewall rules
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct AddFirewallRulesPayload {
    /// Scope of application (with node/subnet prefix as applicable)
    pub scope: FirewallRulesScope,
    /// List of rules
    pub rules: Vec<FirewallRule>,
    /// Positions to add the rules at
    pub positions: Vec<i32>,
    /// SHA-256 hash of the expected result ruleset
    pub expected_hash: String,
}

/// The payload of a proposal to remove firewall rules
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct RemoveFirewallRulesPayload {
    /// Scope of application (with node/subnet prefix as applicable)
    pub scope: FirewallRulesScope,
    /// Positions to remove the rules from
    pub positions: Vec<i32>,
    /// SHA-256 hash of the expected result ruleset
    pub expected_hash: String,
}

/// The payload of a proposal to update firewall rules
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(Clone, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateFirewallRulesPayload {
    /// Scope of application (with node/subnet prefix as applicable)
    pub scope: FirewallRulesScope,
    /// List of rules
    pub rules: Vec<FirewallRule>,
    /// Positions to update the rules at
    pub positions: Vec<i32>,
    /// SHA-256 hash of the expected result ruleset
    pub expected_hash: String,
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::firewall::compute_firewall_ruleset_hash;
    use crate::mutations::firewall::{
        AddFirewallRulesPayload, RemoveFirewallRulesPayload, UpdateFirewallRulesPayload,
    };
    use crate::registry::Registry;
    use ic_base_types::{NodeId, PrincipalId, SubnetId};
    use ic_protobuf::registry::firewall::v1::{
        FirewallAction, FirewallRule, FirewallRuleDirection, FirewallRuleSet,
    };
    use ic_registry_keys::{FirewallRulesScope, make_firewall_rules_record_key};
    use prost::Message;

    const MUTATION_ID: u8 = 0;

    fn firewall_mutations_test(scope: FirewallRulesScope, registry: &mut Registry) {
        // Add initial rules
        let mut expected_result = FirewallRuleSet {
            entries: Vec::<FirewallRule>::new(),
        };

        let new_rules = vec![
            FirewallRule {
                ipv4_prefixes: vec!["10.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 1".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["12.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 2".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
        ];

        expected_result.entries.append(&mut new_rules.clone());

        let payload = AddFirewallRulesPayload {
            scope: scope.clone(),
            rules: new_rules,
            positions: vec![0, 0],
            expected_hash: compute_firewall_ruleset_hash(&expected_result.entries),
        };

        registry.do_add_firewall_rules(payload);

        let result_ruleset = FirewallRuleSet::decode(
            registry
                .get(
                    &make_firewall_rules_record_key(&scope).into_bytes(),
                    registry.latest_version(),
                )
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        assert_eq!(expected_result, result_ruleset);

        // Add more rules in between existing ones
        let new_rules = vec![
            FirewallRule {
                ipv4_prefixes: vec!["11.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 3".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["13.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 4".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
        ];

        expected_result.entries = vec![
            expected_result.entries[0].clone(),
            new_rules[0].clone(),
            expected_result.entries[1].clone(),
            new_rules[1].clone(),
        ];

        let payload = AddFirewallRulesPayload {
            scope: scope.clone(),
            rules: new_rules,
            positions: vec![1, 2],
            expected_hash: compute_firewall_ruleset_hash(&expected_result.entries),
        };

        registry.do_add_firewall_rules(payload);

        let result_ruleset = FirewallRuleSet::decode(
            registry
                .get(
                    &make_firewall_rules_record_key(&scope).into_bytes(),
                    registry.latest_version(),
                )
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        assert_eq!(expected_result, result_ruleset);

        // Update some rules

        let update_rules = vec![
            FirewallRule {
                ipv4_prefixes: vec!["10.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080, 9090],
                action: FirewallAction::Allow as i32,
                comment: "test comment 1".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["12.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080, 9090],
                action: FirewallAction::Allow as i32,
                comment: "test comment 2".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
        ];

        expected_result.entries = vec![
            update_rules[0].clone(),
            expected_result.entries[1].clone(),
            update_rules[1].clone(),
            expected_result.entries[3].clone(),
        ];

        let payload = UpdateFirewallRulesPayload {
            scope: scope.clone(),
            rules: update_rules,
            positions: vec![0, 2],
            expected_hash: compute_firewall_ruleset_hash(&expected_result.entries),
        };

        registry.do_update_firewall_rules(payload);

        let result_ruleset = FirewallRuleSet::decode(
            registry
                .get(
                    &make_firewall_rules_record_key(&scope).into_bytes(),
                    registry.latest_version(),
                )
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        assert_eq!(expected_result, result_ruleset);

        // Remove some rules

        expected_result.entries = vec![
            expected_result.entries[1].clone(),
            expected_result.entries[3].clone(),
        ];

        let payload = RemoveFirewallRulesPayload {
            scope: scope.clone(),
            positions: vec![0, 2],
            expected_hash: compute_firewall_ruleset_hash(&expected_result.entries),
        };

        registry.do_remove_firewall_rules(payload);

        let result_ruleset = FirewallRuleSet::decode(
            registry
                .get(
                    &make_firewall_rules_record_key(&scope).into_bytes(),
                    registry.latest_version(),
                )
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        assert_eq!(expected_result, result_ruleset);

        // Add multiple rules at the beginning and at the end
        let new_rules_head = vec![
            FirewallRule {
                ipv4_prefixes: vec!["15.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 15".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["16.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 16".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["17.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 17".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["18.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 18".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
        ];
        let new_rules_tail = vec![
            FirewallRule {
                ipv4_prefixes: vec!["20.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 20".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["21.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 21".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["22.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 22".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
            FirewallRule {
                ipv4_prefixes: vec!["23.0.0.0/8".to_string()],
                ipv6_prefixes: vec![],
                ports: vec![80, 8080],
                action: FirewallAction::Allow as i32,
                comment: "test comment 23".to_string(),
                user: None,
                direction: Some(FirewallRuleDirection::Inbound as i32),
            },
        ];

        let old_entries = expected_result.entries;
        expected_result.entries = Vec::new();
        expected_result.entries.extend(new_rules_head.clone());
        expected_result
            .entries
            .extend(vec![old_entries[0].clone(), old_entries[1].clone()]);
        expected_result.entries.extend(new_rules_tail.clone());

        let mut new_rules: Vec<FirewallRule> = Vec::new();
        new_rules.extend(new_rules_head);
        new_rules.extend(new_rules_tail);

        let payload = AddFirewallRulesPayload {
            scope: scope.clone(),
            rules: new_rules,
            positions: vec![0, 0, 0, 0, 2, 2, 2, 2],
            expected_hash: compute_firewall_ruleset_hash(&expected_result.entries),
        };

        registry.do_add_firewall_rules(payload);

        let result_ruleset = FirewallRuleSet::decode(
            registry
                .get(
                    &make_firewall_rules_record_key(&scope).into_bytes(),
                    registry.latest_version(),
                )
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        assert_eq!(expected_result, result_ruleset);
    }

    #[test]
    fn firewall_mutations_all_scope_types() {
        let mut registry = invariant_compliant_registry(MUTATION_ID);
        firewall_mutations_test(FirewallRulesScope::Global, &mut registry);
        let mut registry = invariant_compliant_registry(MUTATION_ID);
        firewall_mutations_test(FirewallRulesScope::ReplicaNodes, &mut registry);
        let mut registry = invariant_compliant_registry(MUTATION_ID);
        firewall_mutations_test(FirewallRulesScope::ApiBoundaryNodes, &mut registry);

        let mut registry = invariant_compliant_registry(MUTATION_ID);
        let subnet_id: SubnetId =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets[0].clone())
                .unwrap()
                .into();
        firewall_mutations_test(FirewallRulesScope::Subnet(subnet_id), &mut registry);

        let mut registry = invariant_compliant_registry(MUTATION_ID);
        let subnet_id: SubnetId =
            PrincipalId::try_from(registry.get_subnet_list_record().subnets[0].clone())
                .unwrap()
                .into();
        let node_id: NodeId =
            PrincipalId::try_from(registry.get_subnet_or_panic(subnet_id).membership[0].clone())
                .unwrap()
                .into();
        firewall_mutations_test(FirewallRulesScope::Node(node_id), &mut registry);
    }
}
