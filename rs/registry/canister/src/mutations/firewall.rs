use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use crate::mutations::common::{decode_registry_value, encode_or_panic};
use ic_crypto_sha::Sha256;
use ic_protobuf::registry::firewall::v1::{FirewallRule, FirewallRuleSet};
use ic_registry_keys::make_firewall_rules_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};
use std::fmt::Write;

impl Registry {
    /// Set firewall rules for a given scope.
    fn do_set_firewall_rules(
        &mut self,
        scope: String,
        rules: Vec<FirewallRule>,
        expected_hash: String,
    ) {
        println!(
            "{}do_set_firewall_rules: scope: {:?}, rules: {:?}, expected_hash: {:?}",
            LOG_PREFIX, scope, rules, expected_hash
        );

        // Compare hash
        let mut hasher = Sha256::new();
        for rule in &rules {
            hasher.write(&encode_or_panic(rule));
        }
        let result_hash = Self::to_hex_string(&hasher.finish());

        if result_hash != expected_hash {
            panic!(
                "{}Provided expected hash for new firewall ruleset does not match. Expected hash: {:?}, actual hash: {:?}.",
                LOG_PREFIX, expected_hash, result_hash
            );
        }

        // Do the registry mutation
        let ruleset = FirewallRuleSet { entries: rules };

        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Upsert as i32,
            key: make_firewall_rules_record_key(&scope).into_bytes(),
            value: encode_or_panic(&ruleset),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    fn to_hex_string(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    fn fetch_current_ruleset(&mut self, scope: &str) -> Vec<FirewallRule> {
        // Fetch current rules for scope
        let key = make_firewall_rules_record_key(scope).into_bytes();

        let default_registry_value = RegistryValue {
            value: encode_or_panic(&FirewallRuleSet { entries: vec![] }),
            version: 0,
            deletion_marker: false,
        };

        let RegistryValue {
            value: current_ruleset_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(&key, self.latest_version())
            .unwrap_or(&default_registry_value);

        let current_ruleset = decode_registry_value::<FirewallRuleSet>(current_ruleset_vec.clone());
        current_ruleset.entries
    }

    /// Add firewall rules for a given scope.
    ///
    /// This method is called by the proposals canister.
    pub fn do_add_firewall_rules(&mut self, payload: AddFirewallRulesPayload) {
        println!("{}do_add_firewall_rules: scope: {:?}, rules: {:?}, positions: {:?}, expected_hash: {:?}", LOG_PREFIX, "", payload.rules, payload.positions, payload.expected_hash);

        let mut entries = self.fetch_current_ruleset(""); //&payload.scope);

        if payload.positions.len() != payload.rules.len() {
            panic!(
                "{}Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
                LOG_PREFIX, payload.positions, payload.rules
            );
        }

        // Add entries from the back to front to preserve positions
        let mut positions = payload.positions.clone();
        positions.sort_unstable();
        positions.reverse();
        for (rule_idx, mut pos) in positions.into_iter().enumerate() {
            if pos < 0 {
                pos = entries.len() as i32;
            }
            if pos > entries.len() as i32 {
                panic!(
                    "{}Provided position does not match the size of the existing ruleset. Position: {:?}, ruleset size: {:?}.",
                    LOG_PREFIX, pos, entries.len()
                );
            }
            entries.insert(pos as usize, payload.rules[rule_idx].clone());
        }

        self.do_set_firewall_rules("".to_string(), entries, payload.expected_hash);
    }

    /// Remove firewall rules for a given scope.
    ///
    /// This method is called by the proposals canister.
    pub fn do_remove_firewall_rules(&mut self, payload: RemoveFirewallRulesPayload) {
        println!(
            "{}do_remove_firewall_rules: scope: {:?}, positions: {:?}, expected_hash: {:?}",
            LOG_PREFIX, "", payload.positions, payload.expected_hash
        );

        let mut entries = self.fetch_current_ruleset(""); //&payload.scope);

        // Remove entries from the back to front to preserve positions
        let mut positions = payload.positions.clone();
        positions.sort_unstable();
        positions.reverse();
        for i in positions {
            entries.remove(i as usize);
        }

        self.do_set_firewall_rules("".to_string(), entries, payload.expected_hash);
    }

    /// Update firewall rules for a given scope.
    ///
    /// This method is called by the proposals canister.
    pub fn do_update_firewall_rules(&mut self, payload: UpdateFirewallRulesPayload) {
        println!("{}do_update_firewall_rules: scope: {:?}, rules: {:?}, positions: {:?}, expected_hash: {:?}", LOG_PREFIX, "", payload.rules, payload.positions, payload.expected_hash);

        let mut entries = self.fetch_current_ruleset(""); //&payload.scope);

        if payload.positions.len() != payload.rules.len() {
            panic!(
                "{}Number of provided positions differs from number of provided rules. Positions: {:?}, Rules: {:?}.",
                LOG_PREFIX, payload.positions, payload.rules
            );
        }

        // Update the entries
        for (rule_idx, pos) in payload.positions.into_iter().enumerate() {
            if pos < 0 || pos >= entries.len() as i32 {
                panic!(
                    "{}Provided position is out of bounds for the existing ruleset. Position: {:?}, ruleset size: {:?}.",
                    LOG_PREFIX, pos, entries.len()
                );
            }
            entries[pos as usize] = payload.rules[rule_idx].clone();
        }

        self.do_set_firewall_rules("".to_string(), entries, payload.expected_hash);
    }
}

/// The payload of a proposal to add firewall rules
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AddFirewallRulesPayload {
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
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RemoveFirewallRulesPayload {
    /// Positions to remove the rules from
    pub positions: Vec<i32>,
    /// SHA-256 hash of the expected result ruleset
    pub expected_hash: String,
}

/// The payload of a proposal to update firewall rules
///
/// See /rs/protobuf/def/registry/firewall/v1/firewall.proto
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct UpdateFirewallRulesPayload {
    /// List of rules
    pub rules: Vec<FirewallRule>,
    /// Positions to update the rules at
    pub positions: Vec<i32>,
    /// SHA-256 hash of the expected result ruleset
    pub expected_hash: String,
}
