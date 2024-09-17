use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chrono::Utc;

type Version = u64;
type Timestamp = u64;
type Config = Vec<RuleWithMetadata>;

/// Privacy policy of the rate limiting rule.
#[derive(Clone, Debug, PartialEq, Default)]
enum Policy {
    #[default]
    Public,
    Private,
}

/// Version of the rate limiting config and its metadata.
#[derive(Clone, Default, Debug)]
struct VersionMetadata {
    version: Version,
    active_since: Timestamp,
    active_till: Option<Timestamp>,
}

/// Raw rule to be serialized into json/yml and consumed by ic-boundary.
#[derive(Clone, Default, Debug, Hash, Serialize, Deserialize)]
struct RuleRaw { /* json_str */
    canister_id: Option<String>,
    subnet_id: Option<String>,
    methods: Vec<String>,
    request_type: Option<String>,
    limit: Option<String>,
}

/// Rate limiting rule with metadata.
#[derive(Clone, Default, Debug)]
struct RuleWithMetadata {
    rule: RuleRaw,
    rule_hash: String,
    policy: Policy,
}

/// Rule representation for response.
/// Allows to optionally reveal/hide the rule itself, depending on the privacy policy.
#[derive(Clone, Default, Debug)]
struct Rule {
    rule: Option<RuleRaw>,
    rule_hash: String,
    policy: Policy,
}

#[derive(Clone, Default)]
struct Canister {
    configs: Vec<(VersionMetadata, Config)>,
}

#[derive(Debug)]
struct GetConfigResponse {
    version: VersionMetadata,
    config: Vec<Rule>,
}

#[derive(Debug)]
struct GetLatestVersionResponse {
    version: VersionMetadata,
}

#[derive(Debug)]
struct GetNLatestVersionsResponse {
    versions: Vec<VersionMetadata>,
}

impl Canister {
    fn new() -> Self {
        let version = VersionMetadata {
            version: 1,
            active_since: Utc::now().timestamp() as Timestamp,
            active_till: None,
        };
        Self {
            configs: vec![(version, vec![])],
        }
    }

    /// Method for auditability/inspection
    fn get_latest_version(&self) -> GetLatestVersionResponse {
        GetLatestVersionResponse {
            version: self.configs.last().unwrap().clone().0,
        }
    }

    /// Method for auditability/inspection
    fn get_n_last_versions(&self, n: usize) -> GetNLatestVersionsResponse {
        let versions: Vec<VersionMetadata> = self.configs.iter().map(|rule| rule.0.clone()).collect();
        let start = if n > versions.len() {
            0
        } else {
            versions.len() - n
        };
        GetNLatestVersionsResponse {
            versions: versions[start..].to_vec(),
        }
    }

    /// Private method for imposing new rate-limiting config
    /// Set the new rules and bumps the version.
    fn overwrite_config(&mut self, config: Vec<(RuleRaw, Policy)>) {
        let time_now = Utc::now().timestamp() as u64;
        let (version, _) = self.configs.last_mut().unwrap();
        version.active_till = Some(time_now);

        let new_config = config
            .into_iter()
            .map(|rule| {
                let mut hasher = Sha256::new();
                let serialized =
                    serde_json::to_string(&rule.0).expect("Failed to serialize struct");
                hasher.update(serialized.as_bytes());
                let hash_value = hasher.finalize();
                // Get the resulting hash value
                RuleWithMetadata {
                    rule: rule.0,
                    rule_hash: hex::encode(hash_value),
                    policy: rule.1,
                }
            })
            .collect();

        let new_version = VersionMetadata {
            version: version.version + 1,
            active_since: time_now,
            active_till: None,
        };

        self.configs.push((new_version, new_config));
    }

    /// Method used by:
    ///  - API boundary nodes for reading the latest rules, serializing them to .yml for ic-boundary
    ///  - all IC users for auditability/inspection
    /// Depending on the caller principal and privacy policy returns full or truncated view of the rules.
    fn get_latest_config(&self, user: &str) -> GetConfigResponse {
        let (version, rules) = self.configs.last().unwrap();

        let rules: Vec<Rule> = rules
            .iter()
            .map(|rule| {
                let display_rule = if rule.policy == Policy::Private && user != "admin" {
                    None
                } else {
                    Some(rule.rule.clone())
                };
                Rule {
                    rule_hash: rule.rule_hash.clone(),
                    policy: rule.policy.clone(),
                    rule: display_rule,
                }
            })
            .collect();

        GetConfigResponse {
            version: version.clone(),
            config: rules,
        }
    }

    fn get_config_for_version(&self, version: Version) -> GetConfigResponse {
        let idx = version as usize;
        let (version, rule) = self.configs[idx - 1].clone();

        let rules: Vec<Rule> = rule
            .iter()
            .map(|rule| {
                let display_rule = if rule.policy == Policy::Private {
                    None
                } else {
                    Some(rule.rule.clone())
                };
                Rule {
                    rule_hash: rule.rule_hash.clone(),
                    policy: rule.policy.clone(),
                    rule: display_rule,
                }
            })
            .collect();

        GetConfigResponse { version, config: rules }
    }
}

fn main() {
    // Initialize canister
    println!("Initializing canister with the first version");
    let mut canister = Canister::new();

    let version = canister.get_latest_version();

    println!("latest config version {:?}", version);

    let config = canister.get_latest_config("admin");
    println!("latest config {:?}", config);

    // Add a config with two rules (overwrite config and bump version, can be json_str)
    let config = vec![
        (
            RuleRaw {
                canister_id: Some("1".to_string()),
                limit: Some("1req/s".to_string()),
                request_type: None,
                subnet_id: None,
                methods: vec![],
            },
            Policy::Private,
        ),
        (
            RuleRaw {
                canister_id: Some("2".to_string()),
                limit: Some("1req/s".to_string()),
                request_type: None,
                subnet_id: None,
                methods: vec![],
            },
            Policy::Public,
        ),
    ];

    println!("overwriting config ...");
    canister.overwrite_config(config);

    // Check new version and new rules
    let version = canister.get_latest_version();
    println!("latest version {:?}", version);
    let versions = canister.get_n_last_versions(5);
    println!("last n versions {:#?}", versions);
    let config = canister.get_latest_config("admin");
    println!("latest config seen by authorized principal: {:#?}", config);
    let result = canister.get_latest_config("non_admin");
    println!("latest config seen by unauthorized principal: {:#?}", result);

    // Overwrite rules
    let rules = vec![
        (
            RuleRaw {
                canister_id: Some("1".to_string()),
                limit: Some("1req/s".to_string()),
                request_type: None,
                subnet_id: None,
                methods: vec![],
            },
            Policy::Public, // changed from Private to Public
        ),
        (
            RuleRaw {
                canister_id: Some("2".to_string()),
                limit: Some("1req/s".to_string()),
                request_type: None,
                subnet_id: None,
                methods: vec![],
            },
            Policy::Public, // unchanged
        ),
        (
            RuleRaw {
                canister_id: Some("3".to_string()),
                limit: Some("1req/s".to_string()),
                request_type: None,
                subnet_id: None,
                methods: vec![],
            },
            Policy::Private, // added new private rule
        ),
    ];

    println!("setting new config");
    canister.overwrite_config(rules);

    // Check new version and rules
    let version = canister.get_latest_version();
    println!("latest version {:?}", version);
    let versions = canister.get_n_last_versions(5);
    println!("last n versions {:#?}", versions);
    let config = canister.get_latest_config("admin");
    println!("latest rules seen by authorized principal are {:#?}", config);
    let config = canister.get_latest_config("non_admin");
    println!("latest rules seen by unauthorized principal are {:#?}", config);
    let config = canister.get_config_for_version(1);
    println!("config rules for version 1: {:#?}", config);
    let config = canister.get_config_for_version(2);
    println!("config rules for version 2: {:#?}", config);
    let config = canister.get_config_for_version(3);
    println!("config rules for version 3: {:#?}", config);
}

// config = [
//     {
//         "rule": {
//             "canister_id": "abcd-1234",
//             "subnet_id": null,
//             "methods": null,
//             "request_type": "call",
//             "limit": "1req/s"
//         },
//         "policy": "Public"
//     },
//     {
//         "rule": {
//             "canister_id": null,
//             "subnet_id": "subnet-5678",
//             "methods": null,
//             "request_type": "query",
//             "limit": null
//         },
//         "policy": "Private"
//     }
// ]