use candid::Principal;
use mockall::automock;
use rate_limits_api::IncidentId;

use crate::{
    add_config::{
        INIT_SCHEMA_VERSION,
        INIT_VERSION,
    },
    storage::{
        LocalRef,
        StableMap,
        StorableConfig,
        StorableIncidentId,
        StorableIncidentMetadata,
        StorablePrincipal,
        StorableRuleId,
        StorableRuleMetadata,
        StorableVersion,
        AUTHORIZED_PRINCIPAL,
        CONFIGS,
        INCIDENTS,
        RULES,
    },
    types::{
        InputConfig,
        InputRule,
        RuleId,
        Timestamp,
        Version,
    },
};

#[automock]
pub trait CanisterApi {
    fn get_authorized_principal(&self) -> Option<StorablePrincipal>;
    fn set_authorized_principal(&self, principal: Principal);
    fn get_version(&self) -> Option<StorableVersion>;
    fn get_full_config(&self, version: Version) -> Option<InputConfig>;
    fn get_config(&self, version: Version) -> Option<StorableConfig>;
    fn get_rule(&self, rule_id: &RuleId) -> Option<StorableRuleMetadata>;
    fn get_incident(&self, incident_id: &IncidentId) -> Option<StorableIncidentMetadata>;
    fn add_config(&self, version: Version, config: StorableConfig) -> bool;
    fn add_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool;
    fn add_incident(&self, incident_id: IncidentId, rule_ids: StorableIncidentMetadata) -> bool;
    fn update_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool;
    fn update_incident(&self, incident_id: IncidentId, rule_ids: StorableIncidentMetadata) -> bool;
}

#[derive(Clone)]
pub struct CanisterState {
    configs: LocalRef<StableMap<StorableVersion, StorableConfig>>,
    rules: LocalRef<StableMap<StorableRuleId, StorableRuleMetadata>>,
    incidents: LocalRef<StableMap<StorableIncidentId, StorableIncidentMetadata>>,
    authorized_principal: LocalRef<StableMap<(), StorablePrincipal>>,
}

impl CanisterState {
    pub fn from_static() -> Self {
        Self {
            configs: &CONFIGS,
            rules: &RULES,
            incidents: &INCIDENTS,
            authorized_principal: &AUTHORIZED_PRINCIPAL,
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
            .with(|cell| cell.borrow_mut().insert((), StorablePrincipal(principal)));
    }

    fn get_version(&self) -> Option<StorableVersion> {
        self.configs.with(|cell| {
            let configs = cell.borrow();
            configs.last_key_value().map(|(key, _)| Some(key))?
        })
    }

    fn get_config(&self, version: Version) -> Option<StorableConfig> {
        self.configs
            .with(|cell| cell.borrow().get(&StorableVersion(version)))
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

    fn get_rule(&self, rule_id: &RuleId) -> Option<StorableRuleMetadata> {
        self.rules
            .with(|cell| cell.borrow().get(&StorableRuleId(rule_id.clone())))
    }

    fn get_incident(&self, incident_id: &IncidentId) -> Option<StorableIncidentMetadata> {
        self.incidents
            .with(|cell| cell.borrow().get(&StorableIncidentId(incident_id.clone())))
    }

    fn add_config(&self, version: Version, config: StorableConfig) -> bool {
        self.get_config(version).map_or_else(
            || {
                self.configs.with(|cell| {
                    let mut configs = cell.borrow_mut();
                    configs.insert(StorableVersion(version), config);
                });
                true // Successfully inserted
            },
            |_| false, // Already exists, return false
        )
    }

    fn add_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool {
        self.get_rule(&rule_id).map_or_else(
            || {
                self.rules.with(|cell| {
                    let mut rules = cell.borrow_mut();
                    rules.insert(StorableRuleId(rule_id), rule);
                });
                true // Successfully inserted
            },
            |_| false, // Already exists, return false
        )
    }

    fn add_incident(&self, incident_id: IncidentId, rule_ids: StorableIncidentMetadata) -> bool {
        self.get_incident(&incident_id).map_or_else(
            || {
                self.incidents.with(|cell| {
                    let mut incidents = cell.borrow_mut();
                    incidents.insert(StorableIncidentId(incident_id), rule_ids);
                });
                true // Successfully inserted
            },
            |_| false, // Already exists, return false
        )
    }

    fn update_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool {
        self.get_rule(&rule_id).map_or_else(
            || false, // Rule doesn't exist, return false
            |_| {
                self.rules.with(|cell| {
                    let mut rules = cell.borrow_mut();
                    rules.insert(StorableRuleId(rule_id), rule);
                });
                true // Successfully updated
            },
        )
    }

    fn update_incident(&self, incident_id: IncidentId, incident: StorableIncidentMetadata) -> bool {
        self.get_incident(&incident_id).map_or_else(
            || false, // Incident doesn't exist, return false
            |_| {
                self.incidents.with(|cell| {
                    let mut incidents = cell.borrow_mut();
                    incidents.insert(StorableIncidentId(incident_id), incident);
                });
                true // Successfully updated
            },
        )
    }
}

pub fn init_version_and_config(time: Timestamp, canister_api: impl CanisterApi) {
    // Initialize config with an empty vector of rules
    let config = StorableConfig {
        schema_version: INIT_SCHEMA_VERSION,
        active_since: time,
        rule_ids: vec![],
    };
    assert!(
        canister_api.add_config(INIT_VERSION, config),
        "Config for version={INIT_VERSION} already exists!"
    );
}

pub fn with_canister_state<R>(f: impl FnOnce(CanisterState) -> R) -> R {
    let state = CanisterState::from_static();
    f(state)
}
