use candid::Principal;
use mockall::automock;
use std::collections::HashSet;

use crate::{
    add_config::{INIT_JSON_SCHEMA_VERSION, INIT_VERSION},
    storage::{
        API_BOUNDARY_NODE_PRINCIPALS, AUTHORIZED_PRINCIPAL, CONFIGS, INCIDENTS, LocalRef, RULES,
        StableMap, StorableConfig, StorableIncident, StorableIncidentId, StorablePrincipal,
        StorableRule, StorableRuleId, StorableVersion,
    },
    types::{IncidentId, InputConfig, InputRule, RuleId, Timestamp, Version},
};

#[automock]
pub trait CanisterApi {
    fn get_authorized_principal(&self) -> Option<StorablePrincipal>;
    fn set_authorized_principal(&self, principal: Principal);
    fn get_version(&self) -> Option<StorableVersion>;
    fn get_full_config(&self, version: Version) -> Option<InputConfig>;
    fn get_config(&self, version: Version) -> Option<StorableConfig>;
    fn get_rule(&self, rule_id: &RuleId) -> Option<StorableRule>;
    fn get_incident(&self, incident_id: &IncidentId) -> Option<StorableIncident>;
    fn add_config(&self, version: Version, config: StorableConfig);
    fn upsert_rule(&self, rule_id: RuleId, rule: StorableRule);
    fn upsert_incident(&self, incident_id: IncidentId, rule_ids: StorableIncident);
    fn is_api_boundary_node_principal(&self, principal: &Principal) -> bool;
    fn set_api_boundary_nodes_principals(&self, principals: Vec<Principal>);
    fn api_boundary_nodes_count(&self) -> u64;
    fn incidents_count(&self) -> u64;
    fn active_rules_count(&self) -> u64;
    fn configs_count(&self) -> u64;
}

#[derive(Clone)]
pub struct CanisterState {
    configs: LocalRef<StableMap<StorableVersion, StorableConfig>>,
    rules: LocalRef<StableMap<StorableRuleId, StorableRule>>,
    incidents: LocalRef<StableMap<StorableIncidentId, StorableIncident>>,
    authorized_principal: LocalRef<StableMap<(), StorablePrincipal>>,
    api_boundary_node_principals: LocalRef<HashSet<Principal>>,
}

impl CanisterState {
    pub fn from_static() -> Self {
        Self {
            configs: &CONFIGS,
            rules: &RULES,
            incidents: &INCIDENTS,
            authorized_principal: &AUTHORIZED_PRINCIPAL,
            api_boundary_node_principals: &API_BOUNDARY_NODE_PRINCIPALS,
        }
    }
}

impl CanisterApi for CanisterState {
    fn get_authorized_principal(&self) -> Option<StorablePrincipal> {
        self.authorized_principal
            .with(|cell| cell.borrow().get(&()))
    }

    fn set_authorized_principal(&self, principal: Principal) {
        self.authorized_principal
            .with(|cell| cell.borrow_mut().insert((), principal));
    }

    fn get_version(&self) -> Option<StorableVersion> {
        self.configs.with(|cell| {
            let configs = cell.borrow();
            configs.last_key_value().map(|(key, _)| Some(key))?
        })
    }

    fn get_config(&self, version: Version) -> Option<StorableConfig> {
        self.configs.with(|cell| cell.borrow().get(&version))
    }

    fn get_full_config(&self, version: Version) -> Option<InputConfig> {
        let config = self.get_config(version)?;

        let mut rules = vec![];

        for rule_id in config.rule_ids.iter() {
            let rule = self.get_rule(rule_id)?;
            rules.push(InputRule {
                incident_id: rule.incident_id,
                rule_raw: rule.rule_raw,
                description: rule.description,
            })
        }

        Some(InputConfig {
            schema_version: config.schema_version,
            rules,
        })
    }

    fn get_rule(&self, rule_id: &RuleId) -> Option<StorableRule> {
        self.rules
            .with(|cell| cell.borrow().get(&StorableRuleId(rule_id.0)))
    }

    fn get_incident(&self, incident_id: &IncidentId) -> Option<StorableIncident> {
        self.incidents
            .with(|cell| cell.borrow().get(&StorableIncidentId(incident_id.0)))
    }

    fn add_config(&self, version: Version, config: StorableConfig) {
        self.configs
            .with(|cell| cell.borrow_mut().insert(version, config));
    }

    fn upsert_rule(&self, rule_id: RuleId, rule: StorableRule) {
        self.rules
            .with(|cell| cell.borrow_mut().insert(StorableRuleId(rule_id.0), rule));
    }

    fn upsert_incident(&self, incident_id: IncidentId, rule_ids: StorableIncident) {
        self.incidents.with(|cell| {
            cell.borrow_mut()
                .insert(StorableIncidentId(incident_id.0), rule_ids)
        });
    }

    fn is_api_boundary_node_principal(&self, principal: &Principal) -> bool {
        self.api_boundary_node_principals
            .with(|cell| cell.borrow().contains(principal))
    }

    fn set_api_boundary_nodes_principals(&self, principals: Vec<Principal>) {
        API_BOUNDARY_NODE_PRINCIPALS
            .with(|cell| *cell.borrow_mut() = HashSet::from_iter(principals));
    }

    fn api_boundary_nodes_count(&self) -> u64 {
        API_BOUNDARY_NODE_PRINCIPALS.with(|cell| cell.borrow().len()) as u64
    }

    fn incidents_count(&self) -> u64 {
        self.incidents.with(|cell| cell.borrow().len())
    }

    fn active_rules_count(&self) -> u64 {
        self.configs.with(|cell| {
            let configs = cell.borrow();
            configs
                .last_key_value()
                .map_or(0, |(_, value)| value.rule_ids.len() as u64)
        })
    }

    fn configs_count(&self) -> u64 {
        self.configs.with(|cell| cell.borrow().len())
    }
}

pub fn init_version_and_config(time: Timestamp, canister_api: impl CanisterApi) {
    // Initialize config with an empty vector of rules
    let config = StorableConfig {
        schema_version: INIT_JSON_SCHEMA_VERSION,
        active_since: time,
        rule_ids: vec![],
    };
    canister_api.add_config(INIT_VERSION, config);
}

pub fn with_canister_state<R>(f: impl FnOnce(CanisterState) -> R) -> R {
    let state = CanisterState::from_static();
    f(state)
}
