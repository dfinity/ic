use crate::{
    catch_up_package_provider::CatchUpPackageProvider,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    registry_helper::RegistryHelper,
};

use ic_config::firewall::{Config as FirewallConfig, FIREWALL_FILE_DEFAULT_PATH};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule, FirewallRuleDirection};
use ic_registry_keys::FirewallRulesScope;
use ic_sys::fs::write_string_using_tmp_file;
use ic_types::NodeId;
use ic_types::RegistryVersion;
use std::{
    cmp::{max, min},
    collections::BTreeSet,
    convert::TryFrom,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;

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
    catchup_package_provider: Arc<CatchUpPackageProvider>,
    logger: ReplicaLogger,
    configuration: FirewallConfig,
    source: DataSource,
    compiled_config: String,
    last_applied_version: Arc<RwLock<RegistryVersion>>,
    /// If true, write the file content even if no change was detected in registry, i.e. first time
    must_write: bool,
    /// If false, do not update the firewall rules (test mode)
    enabled: bool,
    node_id: NodeId,
}

impl Firewall {
    pub(crate) fn new(
        node_id: NodeId,
        registry: Arc<RegistryHelper>,
        metrics: Arc<OrchestratorMetrics>,
        firewall_config: FirewallConfig,
        catchup_package_provider: Arc<CatchUpPackageProvider>,
        logger: ReplicaLogger,
    ) -> Self {
        let config = firewall_config;

        // Disable if the config is the default one (e.g if we're in a test)
        let enabled = config
            .config_file
            .ne(&PathBuf::from(FIREWALL_FILE_DEFAULT_PATH));

        if !enabled {
            warn!(
                logger,
                "Firewall configuration not found. Orchestrator does not update firewall rules."
            );
        }

        Self {
            registry,
            metrics,
            catchup_package_provider,
            configuration: config,
            source: DataSource::Config,
            logger,
            compiled_config: Default::default(),
            last_applied_version: Default::default(),
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
    async fn check_for_firewall_config(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        if *self.last_applied_version.read().await == registry_version {
            // No update in the registry, so no need to re-check
            return Ok(());
        }

        // Get the subnet ID of this node, if exists
        let subnet_id = self
            .registry
            .get_subnet_id_from_node_id(self.node_id, registry_version)
            .unwrap_or(None);

        // This is the eventual list of rules fetched from the registry. It is built in the order of the priority:
        // Node > Subnet > Replica Nodes > Global
        let mut tcp_rules = Vec::<FirewallRule>::new();
        let mut udp_rules = Vec::<FirewallRule>::new();

        // First, we fetch the rules that are specific for this node
        tcp_rules.append(
            &mut self
                .fetch_from_registry(registry_version, &FirewallRulesScope::Node(self.node_id)),
        );

        // Then we fetch the rules that are specific for the subnet, if one is assigned
        if let Some(subnet_id) = subnet_id {
            tcp_rules.append(
                &mut self
                    .fetch_from_registry(registry_version, &FirewallRulesScope::Subnet(subnet_id)),
            );
        }

        // Then the rules that apply to all replica nodes
        tcp_rules.append(
            &mut self.fetch_from_registry(registry_version, &FirewallRulesScope::ReplicaNodes),
        );

        // Lastly, rules that apply globally to any type of node
        tcp_rules
            .append(&mut self.fetch_from_registry(registry_version, &FirewallRulesScope::Global));

        if !tcp_rules.is_empty() {
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
            tcp_rules.append(&mut self.configuration.default_rules.clone());
        }

        // Whitelisting for node IPs
        // In addition to any explicit firewall rules we might apply, we also ALWAYS whitelist all nodes in the registry
        // on the ports used by the protocol

        // First, get all the registry versions between the latest CUP and the latest version in the registry inclusive.
        let registry_versions: Vec<RegistryVersion> = self
            .catchup_package_provider
            .get_local_cup()
            .map(|latest_cup| {
                let cup_registry_version = latest_cup.get_oldest_registry_version_in_use();

                // Iterate:
                // - from   min(cup_registry_version, registry_version)
                // - to     max(cup_registry_version, registry_version).
                // The `cup_registry_version` is extracted from the latest seen catchup package.
                // The `registry_version` is the latest registry version known to this node.
                // In almost any case `registry_version >= cup_registry_version` but there may exist cases where this condition does not hold.
                // In that case we should at least include our latest local view of the subnet.

                let min_registry_version = min(cup_registry_version, registry_version);
                let max_registry_version = max(cup_registry_version, registry_version);
                let registry_version_range =
                    min_registry_version.get()..=max_registry_version.get();

                registry_version_range.map(RegistryVersion::from).collect()
            })
            .unwrap_or_else(|| vec![registry_version]);

        // Get the union of all the node IP addresses from the registry
        let node_whitelist_ips: BTreeSet<IpAddr> = registry_versions
            .into_iter()
            .flat_map(|registry_version| {
                self.registry
                    .get_all_nodes_ip_addresses(registry_version)
                    .unwrap_or_default()
            })
            .collect();

        // Then split it to v4 and v6 separately
        let node_ipv4s: Vec<String> = node_whitelist_ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
            .collect();
        let node_ipv6s: Vec<String> = node_whitelist_ips
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| ip.to_string())
            .collect();
        info!(
            self.logger,
            "Whitelisting {} node IP addresses ({} v4 and {} v6) on the firewall",
            node_whitelist_ips.len(),
            node_ipv4s.len(),
            node_ipv6s.len()
        );

        // Build a UDP and TCP rule to whitelist all v4 and v6 IP addresses of nodes.
        let tcp_node_whitelisting_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s.clone(),
            ipv6_prefixes: node_ipv6s.clone(),
            ports: self.configuration.tcp_ports_for_node_whitelist.clone(),
            action: FirewallAction::Allow as i32,
            comment: "Automatic node whitelisting".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        };

        let udp_node_whitelisting_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s.clone(),
            ipv6_prefixes: node_ipv6s.clone(),
            ports: self.configuration.udp_ports_for_node_whitelist.clone(),
            action: FirewallAction::Allow as i32,
            comment: "Automatic node whitelisting".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        };

        // Insert the whitelisting rules at the top of the list (highest priority)
        tcp_rules.insert(0, tcp_node_whitelisting_rule);
        udp_rules.insert(0, udp_node_whitelisting_rule);

        // Blacklisting for Canister HTTP requests
        // In addition to any explicit firewall rules we might apply, we also ALWAYS blacklist the ic-http-adapter used from accessing
        // all nodes in the registry on specific ports defined in the config file.
        // (Currently, this code does not support ranges so we cannot have 1-19999 blocked nicely)

        // Build a single rule to blacklist v4 and v6 IP addresses
        // that are not supposed to be used by ic-http-adapter.
        let ic_http_adapter_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s,
            ipv6_prefixes: node_ipv6s,
            ports: self.configuration.ports_for_http_adapter_blacklist.clone(),
            action: FirewallAction::Reject as i32,
            comment: "Automatic blacklisting for ic-http-adapter".to_string(),
            user: Some("ic-http-adapter".to_string()),
            direction: Some(FirewallRuleDirection::Outbound as i32),
        };

        // Insert the ic-http-adapter rule at the top of the list (highest priority)
        tcp_rules.insert(0, ic_http_adapter_rule);

        // Generate the firewall file content
        let content =
            Self::generate_firewall_file_content_full(&self.configuration, tcp_rules, udp_rules);

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
        *self.last_applied_version.write().await = registry_version;

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
        tcp_rules: Vec<FirewallRule>,
        udp_rules: Vec<FirewallRule>,
    ) -> String {
        config
            .file_template
            .replace(
                "<<IPv4_TCP_RULES>>",
                &Self::compile_rules(
                    &config.ipv4_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv4_UDP_RULES>>",
                &Self::compile_rules(
                    &config.ipv4_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_TCP_RULES>>",
                &Self::compile_rules(
                    &config.ipv6_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_UDP_RULES>>",
                &Self::compile_rules(
                    &config.ipv6_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv4_OUTBOUND_RULES>>",
                &Self::compile_rules(
                    &config.ipv4_user_output_rule_template,
                    &tcp_rules,
                    vec![FirewallRuleDirection::Outbound],
                ),
            )
            .replace(
                "<<IPv6_OUTBOUND_RULES>>",
                &Self::compile_rules(
                    &config.ipv6_user_output_rule_template,
                    &tcp_rules,
                    vec![FirewallRuleDirection::Outbound],
                ),
            )
            .replace(
                "<<MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS>>",
                &config
                    .max_simultaneous_connections_per_ip_address
                    .to_string(),
            )
    }

    /// Converts a protobuf action for nftables-specific syntax action
    fn action_to_nftables_action(action: Option<FirewallAction>) -> String {
        let default = "drop".to_string();
        if let Some(real_action) = action {
            match real_action {
                FirewallAction::Allow => "accept".to_string(),
                FirewallAction::Reject => "reject".to_string(),
                _ => default,
            }
        } else {
            default
        }
    }

    /// Compiles the entire list of rules using the templates
    fn compile_rules(
        template: &str,
        rules: &[FirewallRule],
        directions: Vec<FirewallRuleDirection>,
    ) -> String {
        rules
            .iter()
            .filter_map(|rule| -> Option<String> {
                let rule_direction = rule
                    .direction
                    .map(|v| {
                        FirewallRuleDirection::try_from(v)
                            .unwrap_or(FirewallRuleDirection::Unspecified)
                    })
                    .unwrap_or(FirewallRuleDirection::Unspecified);
                if !directions.contains(&rule_direction) {
                    // Only produce rules with the requested direction
                    return None;
                }
                if (!template.contains("<<IPv4_PREFIXES>>") || rule.ipv4_prefixes.is_empty())
                    && (!template.contains("<<IPv6_PREFIXES>>") || rule.ipv6_prefixes.is_empty())
                {
                    // Do not produce rules with empty prefix list
                    return None;
                }
                if template.contains("<<USER>>")
                    && (rule.user.is_none() || rule.user.as_ref().unwrap().is_empty())
                {
                    // Do not produce rules with empty user
                    return None;
                }
                Some(
                    template
                        .replace(
                            "<<USER>>",
                            rule.user.as_ref().unwrap_or(&"".to_string()).as_str(),
                        )
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
                            &Self::action_to_nftables_action(
                                FirewallAction::try_from(rule.action).ok(),
                            ),
                        )
                        .replace("<<COMMENT>>", &rule.comment),
                )
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Checks for new firewall config, and if found, update local firewall
    /// rules
    pub async fn check_and_update(&mut self) {
        if !self.enabled {
            return;
        }
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking for firewall config registry version: {}", registry_version
        );

        if let Err(e) = self.check_for_firewall_config(registry_version).await {
            info!(
                self.logger,
                "Failed to check for firewall config at version {}: {}", registry_version, e
            )
        }
    }

    pub fn get_last_applied_version(&self) -> Arc<RwLock<RegistryVersion>> {
        Arc::clone(&self.last_applied_version)
    }
}

#[test]
fn test_firewall_rule_compilation() {
    let max_simultaneous_connections_per_ip_address: u32 = 5;
    let ipv4_rule_template = format!(
        "{} {} {} {}",
        "<<IPv4_PREFIXES>>", "<<PORTS>>", "<<ACTION>>", "<<COMMENT>>"
    );
    let ipv6_rule_template = format!(
        "{} {} {} {}",
        "<<IPv6_PREFIXES>>", "<<PORTS>>", "<<ACTION>>", "<<COMMENT>>"
    );
    let file_template = format!(
        "{} {} {} {} {}",
        "<<MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS>>",
        "<<IPv4_TCP_RULES>>",
        "<<IPv4_UDP_RULES>>",
        "<<IPv6_TCP_RULES>>",
        "<<IPv6_UDP_RULES>>",
    );

    let tcp_rules = vec![
        FirewallRule {
            ipv4_prefixes: vec!["test_ipv4_1".to_string()],
            ipv6_prefixes: vec!["test_ipv6_1".to_string()],
            ports: vec![1, 2, 3],
            action: 1,
            comment: "comment1".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        },
        FirewallRule {
            ipv4_prefixes: vec!["test_ipv4_2".to_string()],
            ipv6_prefixes: vec![],
            ports: vec![4, 5, 6],
            action: 2,
            comment: "comment2".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        },
        FirewallRule {
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec!["test_ipv6_3".to_string()],
            ports: vec![7, 8, 9],
            action: 2,
            comment: "comment3".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        },
        FirewallRule {
            ipv4_prefixes: vec![],
            ipv6_prefixes: vec![],
            ports: vec![10, 11, 12],
            action: 1,
            comment: "comment4".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        },
    ];

    let udp_rules = vec![FirewallRule {
        ipv4_prefixes: vec!["test_ipv4_5_udp".to_string()],
        ipv6_prefixes: vec!["test_ipv6_5_udp".to_string()],
        ports: vec![13, 14, 15],
        action: 1,
        comment: "comment5".to_string(),
        user: None,
        direction: Some(FirewallRuleDirection::Inbound as i32),
    }];

    let expected_tcp_rules_compiled_v4 = [
        format!("{} {} {} {}", "test_ipv4_1", "1,2,3", "accept", "comment1"),
        format!("{} {} {} {}", "test_ipv4_2", "4,5,6", "drop", "comment2"),
    ];

    let expected_udp_rules_compiled_v4 = [format!(
        "{} {} {} {}",
        "test_ipv4_5_udp", "13,14,15", "accept", "comment5"
    )];

    let expected_tcp_rules_compiled_v6 = [
        format!("{} {} {} {}", "test_ipv6_1", "1,2,3", "accept", "comment1"),
        format!("{} {} {} {}", "test_ipv6_3", "7,8,9", "drop", "comment3"),
    ];

    let expected_udp_rules_compiled_v6 = [format!(
        "{} {} {} {}",
        "test_ipv6_5_udp", "13,14,15", "accept", "comment5"
    )];

    let expected_file_content = format!(
        "{} {} {} {} {}",
        max_simultaneous_connections_per_ip_address,
        expected_tcp_rules_compiled_v4.join("\n"),
        expected_udp_rules_compiled_v4.join("\n"),
        expected_tcp_rules_compiled_v6.join("\n"),
        expected_udp_rules_compiled_v6.join("\n"),
    );

    let config = FirewallConfig {
        config_file: PathBuf::default(),
        file_template,

        ipv4_tcp_rule_template: ipv4_rule_template.clone(),
        ipv4_udp_rule_template: ipv4_rule_template,

        ipv6_tcp_rule_template: ipv6_rule_template.clone(),
        ipv6_udp_rule_template: ipv6_rule_template,

        ipv4_user_output_rule_template: "".to_string(),
        ipv6_user_output_rule_template: "".to_string(),
        default_rules: vec![],
        tcp_ports_for_node_whitelist: vec![],
        udp_ports_for_node_whitelist: vec![],
        ports_for_http_adapter_blacklist: vec![],
        max_simultaneous_connections_per_ip_address,
    };

    assert_eq!(
        expected_file_content,
        Firewall::generate_firewall_file_content_full(&config, tcp_rules, udp_rules)
    );
}
