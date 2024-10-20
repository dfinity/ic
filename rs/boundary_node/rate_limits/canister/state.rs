use ic_cdk::api::time;
use rate_limits_api::IncidentId;

use crate::{
    add_config::INIT_VERSION,
    storage::{
        LocalRef, StableMap, StorableConfig, StorableIncidentId, StorableIncidentMetadata,
        StorableRuleId, StorableRuleMetadata, StorableVersion, CONFIGS, INCIDENTS, RULES,
    },
    types::{RuleId, Version},
};

pub trait Repository {
    fn get_version(&self) -> Option<StorableVersion>;
    fn get_config(&self, version: Version) -> Option<StorableConfig>;
    fn get_rule(&self, rule_id: &RuleId) -> Option<StorableRuleMetadata>;
    fn get_incident(&self, incident_id: &IncidentId) -> Option<StorableIncidentMetadata>;
    fn add_config(&self, version: Version, config: StorableConfig) -> bool;
    fn add_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool;
    fn add_incident(&self, incident_id: IncidentId, rule_ids: StorableIncidentMetadata) -> bool;
    fn update_rule(&self, rule_id: RuleId, rule: StorableRuleMetadata) -> bool;
    fn update_incident(&self, incident_id: IncidentId, rule_ids: StorableIncidentMetadata) -> bool;
}

pub struct State {
    configs: LocalRef<StableMap<StorableVersion, StorableConfig>>,
    rules: LocalRef<StableMap<StorableRuleId, StorableRuleMetadata>>,
    incidents: LocalRef<StableMap<StorableIncidentId, StorableIncidentMetadata>>,
}

impl State {
    pub fn from_static() -> Self {
        Self {
            configs: &CONFIGS,
            rules: &RULES,
            incidents: &INCIDENTS,
        }
    }
}

impl Repository for State {
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

pub fn init_version_and_config(version: Version) {
    with_state(|state| {
        let config = StorableConfig {
            schema_version: 1,
            active_since: time(),
            rule_ids: vec![],
        };
        assert!(
            state.add_config(INIT_VERSION, config),
            "Config for version={version} already exists!"
        );
    })
}

pub fn with_state<R>(f: impl FnOnce(State) -> R) -> R {
    let state = State::from_static();
    f(state)
}
