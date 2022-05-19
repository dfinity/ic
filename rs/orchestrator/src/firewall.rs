use crate::registry_helper::RegistryHelper;
use crate::{
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
};
use ic_config::firewall::{Config as FirewallConfig, FIREWALL_FILE_DEFAULT_PATH};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule};
use ic_registry_keys::FirewallRulesScope;
use ic_types::NodeId;
use ic_types::RegistryVersion;
use ic_utils::fs::write_string_using_tmp_file;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

pub const FEATURE_ACTIVATED: bool = false;

#[derive(Clone, Debug, PartialEq, Eq)]
enum DataSource {
    Config,
    Registry,
}

/// Provides function to continuously check the Registry to determine if there
/// has been a change in the firewall config, and if so, updates the node's
/// firewall rules file accordingly.
pub(crate) struct Firewall {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    logger: ReplicaLogger,
    configuration: FirewallConfig,
    source: DataSource,
    compiled_config: String,
    last_check_version: Option<RegistryVersion>,
    // If true, write the file content even if no change was detected in registry, i.e. first time
    must_write: bool,
    // If false, do not update the firewall rules (test mode)
    enabled: bool,
    node_id: NodeId,
}

impl Firewall {
    pub(crate) fn new(
        node_id: NodeId,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        firewall_config: FirewallConfig,
        logger: ReplicaLogger,
    ) -> Self {
        let config = firewall_config;

        // Disable if the config is the default one (e.g if we're in a test)
        let enabled = FEATURE_ACTIVATED
            && config
                .config_file
                .ne(&PathBuf::from(FIREWALL_FILE_DEFAULT_PATH));

        if !enabled && FEATURE_ACTIVATED {
            warn!(
                logger,
                "Firewall configuration not found. Orchestrator does not update firewall rules."
            );
        }

        Self {
            registry,
            metrics,
            configuration: config,
            source: DataSource::Config,
            logger,
            compiled_config: Default::default(),
            last_check_version: None,
            must_write: true,
            enabled,
            node_id,
        }
    }

    fn fetch_from_registry(
        &self,
        registry_version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> Vec<FirewallRule> {
        self.registry
            .get_firewall_rules(registry_version, scope)
            .map(|firewall_ruleset| firewall_ruleset.entries)
            .unwrap_or_default()
    }

    /// Checks for the firewall configuration that applies to this node
    fn check_for_firewall_config(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        if self.last_check_version == Some(registry_version) {
            // No update in the registry, so no need to re-check
            return Ok(());
        }

        // Get the subnet ID of this node, if exists
        let subnet_id_opt = self
            .registry
            .get_subnet_id_from_node_id(self.node_id, registry_version)
            .unwrap_or(None);

        // This is the eventual list of rules fetched from the registry. It is build in the order of the priority:
        // Node > Subnet > Replica Nodes > Global
        let mut rules = Vec::<FirewallRule>::new();

        // First, we fetch the rules that are specific for this node
        rules.append(
            &mut self
                .fetch_from_registry(registry_version, &FirewallRulesScope::Node(self.node_id)),
        );

        // Then we fetch the rules that are specific for the subnet, if one is assigned
        if let Some(subnet_id) = subnet_id_opt {
            rules.append(
                &mut self
                    .fetch_from_registry(registry_version, &FirewallRulesScope::Subnet(subnet_id)),
            );
        }

        // Then the rules that apply to all replica nodes
        rules.append(
            &mut self.fetch_from_registry(registry_version, &FirewallRulesScope::ReplicaNodes),
        );

        // Lastly, rules that apply globally to any type of node
        rules.append(&mut self.fetch_from_registry(registry_version, &FirewallRulesScope::Global));

        if !rules.is_empty() {
            // We found some rules in the registry, so we will not use the default rules in the config file
            self.source = DataSource::Registry;
        } else {
            // We fetched no ruled from the registry, so we will use the default rules in the config file
            warn!(
                every_n_seconds => 300,
                self.logger,
                "Firewall configuration was not found in registry. Using config file instead. This warning should be ignored when firewall config is not expected to appear in the registry (e.g., on testnets)."
            );
            self.source = DataSource::Config;
            rules.append(&mut self.configuration.default_rules.clone());
        }

        // Whitelisting for node IPs
        // In addition to any explicit firewall rules we might apply, we also ALWAYS whitelist all nodes in the registry
        // on the ports used by the protocol

        // First, get all node IPs (v4 and v6)
        let node_ips: Vec<IpAddr> = self
            .registry
            .get_all_nodes_ip_addresses(self.registry.get_latest_version())
            .unwrap_or_default();
        // Then split it to v4 and v6 separately
        let node_ipv4s: Vec<String> = node_ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
            .collect();
        let node_ipv6s: Vec<String> = node_ips
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| ip.to_string())
            .collect();
        info!(
            self.logger,
            "Whitelisting {} node IP addresses ({} v4 and {} v6) on the firewall",
            node_ips.len(),
            node_ipv4s.len(),
            node_ipv6s.len()
        );

        // Build a single rule to whitelist all v4 and v6 IP addresses of nodes
        let node_whitelisting_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s,
            ipv6_prefixes: node_ipv6s,
            ports: self.configuration.ports_for_node_whitelist.clone(),
            action: FirewallAction::Allow as i32,
            comment: "Automatic node whitelisting".to_string(),
        };

        // Insert the whitelisting rule at the top of the list (highest priority)
        rules.insert(0, node_whitelisting_rule);

        // Generate the firewall file content
        let content = Self::generate_firewall_file_content_full(&self.configuration, rules);

        let changed = content.ne(&self.compiled_config);
        if changed {
            // Firewall config is different - update it
            info!(
                self.logger,
                "New firewall configuration found (source: {:?}). Updating local firewall.",
                self.source
            );
        }

        let mut update_version_metric = false;
        if changed || self.must_write {
            if content.is_empty() {
                warn!(
                    self.logger,
                    "No firewall configuration found. Orchestrator will not write any config to a file."
                );
            } else {
                self.write_firewall_file(&content)?;

                self.compiled_config = content;
                update_version_metric = true;
            }
            self.must_write = false;
        }

        if update_version_metric {
            // Update registry version metric, even if there was no change, but only if not rolled back
            self.metrics
                .firewall_registry_version
                .set(i64::try_from(registry_version.get()).unwrap_or(-1));
        }
        self.last_check_version = Some(registry_version);

        Ok(())
    }

    fn write_firewall_file(&self, content: &str) -> OrchestratorResult<()> {
        let f = &self.configuration.config_file;
        write_string_using_tmp_file(f, content)
            .map_err(|e| OrchestratorError::file_write_error(f, e))?;
        Ok(())
    }

    /// Generates a string with the content for the firewall rules file
    fn generate_firewall_file_content_full(
        config: &FirewallConfig,
        rules: Vec<FirewallRule>,
    ) -> String {
        config
            .file_template
            .replace(
                "<<IPv4_RULES>>",
                &Self::compile_rules(&config.ipv4_rule_template, &rules),
            )
            .replace(
                "<<IPv6_RULES>>",
                &Self::compile_rules(&config.ipv6_rule_template, &rules),
            )
    }

    /// Converts a protobuf action for nftables-specific syntax action
    fn action_to_nftables_action(action: Option<FirewallAction>) -> String {
        let default = "drop".to_string();
        if let Some(real_action) = action {
            match real_action {
                FirewallAction::Allow => "accept".to_string(),
                _ => default,
            }
        } else {
            default
        }
    }

    /// Compiles the entire list of rules using the templates
    fn compile_rules(template: &str, rules: &[FirewallRule]) -> String {
        rules
            .iter()
            .filter_map(|rule| -> Option<String> {
                if (!template.contains("<<IPv4_PREFIXES>>") || rule.ipv4_prefixes.is_empty())
                    && (!template.contains("<<IPv6_PREFIXES>>") || rule.ipv6_prefixes.is_empty())
                {
                    // Do not produce rules with empty prefix list
                    return None;
                }
                Some(
                    template
                        .replace("<<IPv4_PREFIXES>>", rule.ipv4_prefixes.join(",").as_str())
                        .replace("<<IPv6_PREFIXES>>", rule.ipv6_prefixes.join(",").as_str())
                        .replace(
                            "<<PORTS>>",
                            rule.ports
                                .iter()
                                .map(|port| port.to_string())
                                .collect::<Vec<String>>()
                                .join(",")
                                .as_str(),
                        )
                        .replace(
                            "<<ACTION>>",
                            &Self::action_to_nftables_action(FirewallAction::from_i32(rule.action)),
                        )
                        .replace("<<COMMENT>>", &rule.comment),
                )
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Checks for new firewall config, and if found, update local firewall
    /// rules
    pub fn check_and_update(&mut self) {
        if !self.enabled {
            return;
        }
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking for firewall config registry version: {}", registry_version
        );

        match self.check_for_firewall_config(registry_version) {
            Ok(()) => self
                .metrics
                .datacenter_registry_version
                .set(registry_version.get() as i64),
            Err(e) => info!(
                self.logger,
                "Failed to check for firewall config at version {}: {}", registry_version, e
            ),
        };
    }
}

#[test]
fn test_firewall_rule_compilation() {
    let ipv4_rule_template = format!(
        "{} {} {} {}",
        "<<IPv4_PREFIXES>>", "<<PORTS>>", "<<ACTION>>", "<<COMMENT>>"
    );
    let ipv6_rule_template = format!(
        "{} {} {} {}",
        "<<IPv6_PREFIXES>>", "<<PORTS>>", "<<ACTION>>", "<<COMMENT>>"
    );
    let file_template = format!("{} {}", "<<IPv4_RULES>>", "<<IPv6_RULES>>");

    let rules = vec![
        FirewallRule {
            ipv4_prefixes: vec!["test_ipv4_1".to_string()],
            ipv6_prefixes: vec!["test_ipv6_1".to_string()],
            ports: vec![1, 2, 3],
            action: 1,
            comment: "comment1".to_string(),
        },
        FirewallRule {
            ipv4_prefixes: vec!["test_ipv4_2".to_string()],
            ipv6_prefixes: vec![],
            ports: vec![4, 5, 6],
            action: 2,
            comment: "comment2".to_string(),
        },
        FirewallRule {
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec!["test_ipv6_3".to_string()],
            ports: vec![7, 8, 9],
            action: 2,
            comment: "comment3".to_string(),
        },
        FirewallRule {
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec![],
            ports: vec![10, 11, 12],
            action: 1,
            comment: "comment4".to_string(),
        },
    ];

    let expected_rules_compiled_v4 = vec![
        format!("{} {} {} {}", "test_ipv4_1", "1,2,3", "accept", "comment1"),
        format!("{} {} {} {}", "test_ipv4_2", "4,5,6", "drop", "comment2"),
    ];
    let expected_rules_compiled_v6 = vec![
        format!("{} {} {} {}", "test_ipv6_1", "1,2,3", "accept", "comment1"),
        format!("{} {} {} {}", "test_ipv6_3", "7,8,9", "drop", "comment3"),
    ];
    let expected_file_content = format!(
        "{} {}",
        expected_rules_compiled_v4.join("\n"),
        expected_rules_compiled_v6.join("\n")
    );

    let config = FirewallConfig {
        config_file: PathBuf::default(),
        firewall_config: "".to_string(),
        ipv4_prefixes: vec![],
        ipv6_prefixes: vec![],
        file_template,
        ipv4_rule_template,
        ipv6_rule_template,
        default_rules: vec![],
        ports_for_node_whitelist: vec![],
    };

    assert_eq!(
        expected_file_content,
        Firewall::generate_firewall_file_content_full(&config, rules)
    );
}
