use crate::{
    catch_up_package_provider::CatchUpPackageProvider,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    registry_helper::RegistryHelper,
};
use ic_config::firewall::{
    BoundaryNodeConfig as BoundaryNodeFirewallConfig, FIREWALL_FILE_DEFAULT_PATH,
    ReplicaConfig as ReplicaFirewallConfig,
};
use ic_logger::{ReplicaLogger, debug, info, warn};
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule, FirewallRuleDirection};
use ic_registry_keys::FirewallRulesScope;
use ic_sys::fs::write_string_using_tmp_file;
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::{
    cmp::{max, min},
    collections::BTreeSet,
    convert::TryFrom,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

#[derive(Clone, Eq, PartialEq, Debug)]
enum DataSource {
    Config,
    Registry,
}

/// The role of the node in the IC, i.e., whether it's acting as a replica or a boundary node.
enum Role {
    AssignedReplica(SubnetId),
    UnassignedReplica,
    BoundaryNode,
}

const SOCKS_PROXY_PORT: u16 = 1080;

/// Provides function to continuously check the Registry to determine if there
/// has been a change in the firewall config, and if so, updates the node's
/// firewall rules file accordingly.
pub(crate) struct Firewall {
    registry: Arc<RegistryHelper>,
    metrics: Arc<OrchestratorMetrics>,
    catchup_package_provider: Arc<CatchUpPackageProvider>,
    logger: ReplicaLogger,
    replica_config: ReplicaFirewallConfig,
    boundary_node_config: BoundaryNodeFirewallConfig,
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
        replica_config: ReplicaFirewallConfig,
        boundary_node_config: BoundaryNodeFirewallConfig,
        catchup_package_provider: Arc<CatchUpPackageProvider>,
        logger: ReplicaLogger,
    ) -> Self {
        // Disable if the config is the default one (e.g if we're in a test)
        let enabled = replica_config
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
            replica_config,
            boundary_node_config,
            logger,
            compiled_config: Default::default(),
            last_applied_version: Default::default(),
            must_write: true,
            enabled,
            node_id,
        }
    }

    fn fetch_firewall_rules_from_registry(
        &self,
        registry_version: RegistryVersion,
        scope: &FirewallRulesScope,
        logger: &ReplicaLogger,
    ) -> Vec<FirewallRule> {
        self.registry
            .get_firewall_rules(registry_version, scope)
            .inspect_err(|err| {
                warn!(
                    every_n_seconds => 30,
                    logger,
                    "Failed to get firewall rules for scope {:?} at registry version {}: {}",
                    scope,
                    registry_version,
                    err
                )
            })
            .unwrap_or_default()
            .map(|firewall_ruleset| firewall_ruleset.entries)
            .unwrap_or_default()
    }

    fn get_role(&self, registry_version: RegistryVersion) -> OrchestratorResult<Role> {
        let maybe_boundary_node_record = self
            .registry
            .get_api_boundary_node_record(self.node_id, registry_version);
        let maybe_subnet_id = self
            .registry
            .get_subnet_id_from_node_id(self.node_id, registry_version);
        match (maybe_boundary_node_record, maybe_subnet_id) {
            (_, Ok(Some(subnet_id))) => Ok(Role::AssignedReplica(subnet_id)),
            (Err(OrchestratorError::ApiBoundaryNodeMissingError(_, _)), Ok(None)) => {
                Ok(Role::UnassignedReplica)
            }
            (Ok(_), _) => Ok(Role::BoundaryNode),
            (Err(err), Ok(None)) => Err(OrchestratorError::RoleError(
                format!(
                    "The node is not assigned to any subnet \
                    but we failed to retrieve the `boundary_node_record` from the registry: {err}"
                ),
                registry_version,
            )),
            (Err(err_1), Err(err_2)) => Err(OrchestratorError::RoleError(
                format!(
                    "Failed to retrieve both the `boundary_node_record` \
                    and the `subnet_id` from the registry: \n{err_1}\n{err_2}"
                ),
                registry_version,
            )),
        }
    }

    // Get all the registry versions between the latest CUP and the latest version in the registry (inclusive)
    fn get_registry_versions(&mut self, registry_version: RegistryVersion) -> Vec<RegistryVersion> {
        self.catchup_package_provider
            .get_local_cup()
            .map(|latest_cup| {
                let cup_registry_version = latest_cup.get_oldest_registry_version_in_use();

                // Iterate:
                // - from   min(cup_registry_version, registry_version)
                // - to     max(cup_registry_version, registry_version).
                // The `cup_registry_version` is extracted from the latest seen catchup package.
                // The `registry_version` is the latest registry version known to this node.
                // In almost any case `registry_version >= cup_registry_version` but there may
                // exist cases where this condition does not hold.
                // In that case we should at least include our latest local view of the subnet.

                let min_registry_version = min(cup_registry_version, registry_version);
                let max_registry_version = max(cup_registry_version, registry_version);
                let registry_version_range =
                    min_registry_version.get()..=max_registry_version.get();

                registry_version_range.map(RegistryVersion::from).collect()
            })
            .unwrap_or_else(|| vec![registry_version])
    }

    fn get_node_whitelisting_rules(
        &mut self,
        registry_version: RegistryVersion,
    ) -> (FirewallRule, FirewallRule, FirewallRule) {
        // First, get all the registry versions between the latest CUP and the latest version
        // in the registry inclusive.
        let registry_versions = self.get_registry_versions(registry_version);

        // Get the union of all the node IP addresses from the registry
        let node_whitelist_ips: BTreeSet<IpAddr> = registry_versions
            .into_iter()
            .flat_map(|registry_version| {
                self.registry
                    .get_all_nodes_ip_addresses(registry_version)
                    .inspect_err(|err| {
                        warn!(
                            every_n_seconds => 30,
                            self.logger,
                            "Failed to get the IPs of all nodes in the registry: {}", err
                        )
                    })
                    .unwrap_or_default()
            })
            .collect();

        // Then split it to v4 and v6 separately
        let (node_ipv4s, node_ipv6s) = split_ips_by_address_family(&node_whitelist_ips);

        info!(
            self.logger,
            "Whitelisting node IP addresses ({} v4 and {} v6) on the firewall",
            node_ipv4s.len(),
            node_ipv6s.len()
        );

        // Build a UDP and TCP rule to whitelist all v4 and v6 IP addresses of nodes.
        let tcp_node_whitelisting_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s.clone(),
            ipv6_prefixes: node_ipv6s.clone(),
            ports: self.replica_config.tcp_ports_for_node_whitelist.clone(),
            action: FirewallAction::Allow as i32,
            comment: "Automatic node whitelisting".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        };

        let udp_node_whitelisting_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s.clone(),
            ipv6_prefixes: node_ipv6s.clone(),
            ports: self.replica_config.udp_ports_for_node_whitelist.clone(),
            action: FirewallAction::Allow as i32,
            comment: "Automatic node whitelisting".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        };

        // Blacklisting for Canister HTTP requests
        // In addition to any explicit firewall rules we might apply, we also ALWAYS blacklist the
        // ic-http-adapter used from accessing
        // all nodes in the registry on specific ports defined in the config file.
        // (Currently, this code does not support ranges so we cannot have 1-19999 blocked nicely)

        // Build a single rule to blacklist v4 and v6 IP addresses
        // that are not supposed to be used by ic-http-adapter.
        let ic_http_adapter_rule = FirewallRule {
            ipv4_prefixes: node_ipv4s,
            ipv6_prefixes: node_ipv6s,
            ports: self.replica_config.ports_for_http_adapter_blacklist.clone(),
            action: FirewallAction::Reject as i32,
            comment: "Automatic blacklisting for ic-http-adapter".to_string(),
            user: Some("ic-http-adapter".to_string()),
            direction: Some(FirewallRuleDirection::Outbound as i32),
        };

        (
            tcp_node_whitelisting_rule,
            udp_node_whitelisting_rule,
            ic_http_adapter_rule,
        )
    }

    fn get_socks_proxy_whitelisting_rules(
        &mut self,
        registry_version: RegistryVersion,
    ) -> FirewallRule {
        // First, get all the registry versions between the latest CUP and the latest version
        // in the registry inclusive.
        let registry_versions = self.get_registry_versions(registry_version);

        // Depending on whether the node is a system or app API boundary node, get the IPs of all
        // system subnet or application subnet nodes
        let node_ips: BTreeSet<IpAddr> = match self
            .registry
            .is_system_api_boundary_node(self.node_id, registry_version)
        {
            Ok(true) => registry_versions
                .into_iter()
                .flat_map(|registry_version| {
                    self.registry
                        .get_system_subnet_nodes_ip_addresses(registry_version)
                        .inspect_err(|err| {
                            warn!(
                                every_n_seconds => 30,
                                self.logger,
                                "Failed to get the IPs of system subnet nodes in the registry: {}", err
                            )
                        })
                        .unwrap_or_default()
                })
                .collect(),
            Ok(false) => registry_versions
                .into_iter()
                .flat_map(|registry_version| {
                    self.registry
                        .get_app_subnet_nodes_ip_addresses(registry_version)
                        .inspect_err(|err| {
                            warn!(
                                every_n_seconds => 30,
                                self.logger,
                                "Failed to get the IPs of app subnet nodes in the registry: {}", err
                            )
                        })
                        .unwrap_or_default()
                })
                .collect(),
            Err(err) => {
                warn!(
                    every_n_seconds => 30,
                    self.logger,
                    "Failed to determine if node is a system or app API boundary node: {}", err);
                BTreeSet::new()
            }
        };

        // Then split it to v4 and v6 separately
        let (node_ipv4s, node_ipv6s) = split_ips_by_address_family(&node_ips);
        info!(
            self.logger,
            "Whitelisting node IP addresses ({} v4 and {} v6) for the SOCKS proxy on the firewall",
            node_ipv4s.len(),
            node_ipv6s.len()
        );

        FirewallRule {
            ipv4_prefixes: node_ipv4s,
            ipv6_prefixes: node_ipv6s,
            ports: vec![SOCKS_PROXY_PORT.into()],
            action: FirewallAction::Allow as i32,
            comment: "nodes for SOCKS proxy".to_string(),
            user: None,
            direction: Some(FirewallRuleDirection::Inbound as i32),
        }
    }

    /// Checks for the firewall configuration that applies to this node
    fn check_for_firewall_config(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        if *self.last_applied_version.read().unwrap() == registry_version {
            // No update in the registry, so no need to re-check
            return Ok(());
        }

        let role = self.get_role(registry_version)?;

        // This is the eventual list of rules fetched from the registry.
        // It is built in the order of the priority:
        // Node > Subnet > Replica Nodes > Global
        let mut tcp_rules = Vec::<FirewallRule>::new();
        let mut udp_rules = Vec::<FirewallRule>::new();

        let firewall_scopes_to_fetch = match role {
            Role::AssignedReplica(subnet_id) => vec![
                FirewallRulesScope::Node(self.node_id),
                FirewallRulesScope::Subnet(subnet_id),
                FirewallRulesScope::ReplicaNodes,
                FirewallRulesScope::Global,
            ],
            Role::UnassignedReplica => vec![
                FirewallRulesScope::Node(self.node_id),
                FirewallRulesScope::ReplicaNodes,
                FirewallRulesScope::Global,
            ],
            Role::BoundaryNode => vec![
                FirewallRulesScope::Node(self.node_id),
                FirewallRulesScope::ApiBoundaryNodes,
                FirewallRulesScope::Global,
            ],
        };

        tcp_rules.extend(firewall_scopes_to_fetch.iter().flat_map(|scope| {
            self.fetch_firewall_rules_from_registry(registry_version, scope, &self.logger)
        }));

        let source = if !tcp_rules.is_empty() {
            // We found some rules in the registry, so we will *not* use the default rules
            // in the config file
            DataSource::Registry
        } else {
            // We fetched no rules from the registry, so we will use the default rules
            // in the config file
            warn!(
                every_n_seconds => 300,
                self.logger,
                "Firewall configuration was not found in registry. \
                Using config file instead. This warning should be ignored when firewall config \
                is not expected to appear in the registry (e.g., on testnets)."
            );

            match role {
                Role::AssignedReplica(_) | Role::UnassignedReplica => {
                    tcp_rules.append(&mut self.replica_config.default_rules.clone());
                }
                Role::BoundaryNode => {
                    tcp_rules.append(&mut self.boundary_node_config.default_rules.clone());
                }
            }

            DataSource::Config
        };

        let content = match role {
            // Whitelisting for node IPs
            // In addition to any explicit firewall rules we might apply, we also ALWAYS whitelist
            // all nodes in the registry on the ports used by the protocol
            Role::AssignedReplica(_) | Role::UnassignedReplica => {
                let (tcp_node_whitelisting_rule, udp_node_whitelisting_rule, ic_http_adapter_rule) =
                    self.get_node_whitelisting_rules(registry_version);
                // Insert the whitelisting rules at the top of the list (highest priority)
                tcp_rules.insert(0, tcp_node_whitelisting_rule);
                udp_rules.insert(0, udp_node_whitelisting_rule);
                // Insert the ic-http-adapter rule at the top of the list (highest priority)
                tcp_rules.insert(0, ic_http_adapter_rule);

                self.replica_config.insert_rules(tcp_rules, udp_rules)
            }
            Role::BoundaryNode => {
                let socks_proxy_whitelisting_rules =
                    self.get_socks_proxy_whitelisting_rules(registry_version);
                // Insert the whitelisting rules at the top of the list (highest priority)
                tcp_rules.insert(0, socks_proxy_whitelisting_rules);
                self.boundary_node_config.insert_rules(tcp_rules, udp_rules)
            }
        };

        let changed = content.ne(&self.compiled_config);
        if changed {
            // Firewall config is different - update it
            info!(
                self.logger,
                "New firewall configuration found (source: {:?}). Updating local firewall.", source
            );
        }

        let mut update_version_metric = false;
        if changed || self.must_write {
            if content.is_empty() {
                warn!(
                    self.logger,
                    "No firewall configuration found. \
                    Orchestrator will not write any config to a file."
                );
            } else {
                self.write_firewall_file(&content, role)?;

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
        *self.last_applied_version.write().unwrap() = registry_version;

        Ok(())
    }

    fn write_firewall_file(&self, content: &str, role: Role) -> OrchestratorResult<()> {
        let f = match role {
            Role::AssignedReplica(_) | Role::UnassignedReplica => &self.replica_config.config_file,
            Role::BoundaryNode => &self.boundary_node_config.config_file,
        };
        write_string_using_tmp_file(f, content)
            .map_err(|e| OrchestratorError::file_write_error(f, e))?;
        Ok(())
    }

    /// Checks for new firewall config, and if found, update local firewall
    /// rules
    pub fn poll(&mut self) {
        if !self.enabled {
            return;
        }
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking for firewall config registry version: {}", registry_version
        );

        if let Err(e) = self.check_for_firewall_config(registry_version) {
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

trait FirewallConfigTemplate {
    fn insert_rules(&self, tcp_rules: Vec<FirewallRule>, udp_rules: Vec<FirewallRule>) -> String;
}

impl FirewallConfigTemplate for ReplicaFirewallConfig {
    fn insert_rules(&self, tcp_rules: Vec<FirewallRule>, udp_rules: Vec<FirewallRule>) -> String {
        self.file_template
            .replace(
                "<<IPv4_TCP_RULES>>",
                &compile_rules(
                    &self.ipv4_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv4_UDP_RULES>>",
                &compile_rules(
                    &self.ipv4_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_TCP_RULES>>",
                &compile_rules(
                    &self.ipv6_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_UDP_RULES>>",
                &compile_rules(
                    &self.ipv6_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv4_OUTBOUND_RULES>>",
                &compile_rules(
                    &self.ipv4_user_output_rule_template,
                    &tcp_rules,
                    vec![FirewallRuleDirection::Outbound],
                ),
            )
            .replace(
                "<<IPv6_OUTBOUND_RULES>>",
                &compile_rules(
                    &self.ipv6_user_output_rule_template,
                    &tcp_rules,
                    vec![FirewallRuleDirection::Outbound],
                ),
            )
            .replace(
                "<<MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS>>",
                &self.max_simultaneous_connections_per_ip_address.to_string(),
            )
    }
}

impl FirewallConfigTemplate for BoundaryNodeFirewallConfig {
    fn insert_rules(&self, tcp_rules: Vec<FirewallRule>, udp_rules: Vec<FirewallRule>) -> String {
        self.file_template
            .replace(
                "<<IPv4_TCP_RULES>>",
                &compile_rules(
                    &self.ipv4_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv4_UDP_RULES>>",
                &compile_rules(
                    &self.ipv4_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_TCP_RULES>>",
                &compile_rules(
                    &self.ipv6_tcp_rule_template,
                    &tcp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<IPv6_UDP_RULES>>",
                &compile_rules(
                    &self.ipv6_udp_rule_template,
                    &udp_rules,
                    vec![
                        FirewallRuleDirection::Inbound,
                        FirewallRuleDirection::Unspecified,
                    ],
                ),
            )
            .replace(
                "<<MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS>>",
                &self.max_simultaneous_connections_per_ip_address.to_string(),
            )
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
                    FirewallRuleDirection::try_from(v).unwrap_or(FirewallRuleDirection::Unspecified)
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
                        &action_to_nftables_action(FirewallAction::try_from(rule.action).ok()),
                    )
                    .replace("<<COMMENT>>", &rule.comment),
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
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

/// takes a list of IP address and returns a list containing only IPv4 and one only IPv6 addresses
fn split_ips_by_address_family(ips: &BTreeSet<IpAddr>) -> (Vec<String>, Vec<String>) {
    let ipv4s: Vec<String> = ips
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| ip.to_string())
        .collect();
    let ipv6s: Vec<String> = ips
        .iter()
        .filter(|ip| ip.is_ipv6())
        .map(|ip| ip.to_string())
        .collect();
    (ipv4s, ipv6s)
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use ic_config::{ConfigOptional, ConfigSource};
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, firewall::v1::FirewallRuleSet,
    };
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::node_operator::{ConnectionEndpoint, NodeRecord};
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_firewall_rules_record_key, make_node_record_key,
    };
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities_registry::{
        SubnetRecordBuilder, add_single_subnet_record, add_subnet_list_record,
    };
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};

    use super::*;

    const NFTABLES_GOLDEN_BYTES: &[u8] =
        include_bytes!("../testdata/nftables_assigned_replica.conf.golden");
    const NFTABLES_BOUNDARY_NODE_APP_SUBNET_GOLDEN_BYTES: &[u8] =
        include_bytes!("../testdata/nftables_boundary_node_app_subnet.conf.golden");
    const NFTABLES_BOUNDARY_NODE_SYSTEM_SUBNET_GOLDEN_BYTES: &[u8] =
        include_bytes!("../testdata/nftables_boundary_node_system_subnet.conf.golden");
    const API_BOUNDARY_NODE_ID: u64 = 3003;

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

        let config = ReplicaFirewallConfig {
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
            config.insert_rules(tcp_rules, udp_rules)
        );
    }

    #[test]
    fn nftables_golden_test() {
        golden_test(
            Role::AssignedReplica(subnet_test_id(1)),
            node_test_id(0),
            NFTABLES_GOLDEN_BYTES,
            "assigned_replica",
        );
    }

    #[test]
    fn nftables_golden_boundary_node_system_subnet_test() {
        // pick the node id such that the API BN's SOCKS proxy serves system subnet nodes
        // the assert checks that
        let api_bn_id_for_system_subnet = node_test_id(0);
        assert!(api_bn_id_for_system_subnet < node_test_id(API_BOUNDARY_NODE_ID));

        golden_test(
            Role::BoundaryNode,
            api_bn_id_for_system_subnet,
            NFTABLES_BOUNDARY_NODE_SYSTEM_SUBNET_GOLDEN_BYTES,
            "boundary_node",
        );
    }

    #[test]
    fn nftables_golden_boundary_node_app_subnet_test() {
        // pick the node id such that the API BN's SOCKS proxy serves app subnet nodes
        // the assert checks that
        let api_bn_id_for_app_subnet = node_test_id(1234);
        assert!(api_bn_id_for_app_subnet > node_test_id(API_BOUNDARY_NODE_ID));

        golden_test(
            Role::BoundaryNode,
            api_bn_id_for_app_subnet,
            NFTABLES_BOUNDARY_NODE_APP_SUBNET_GOLDEN_BYTES,
            "boundary_node",
        );
    }

    /// Runs [`Firewall::check_for_firewall_config`] and compares the output against the specified
    /// golden output.
    fn golden_test(role: Role, node_id: NodeId, golden_bytes: &[u8], label: &str) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let nftables_config_path = tmp_dir.path().join("nftables.conf");
        let config = get_config();
        let mut replica_firewall_config = config.firewall.unwrap();
        replica_firewall_config
            .config_file
            .clone_from(&nftables_config_path);
        let mut boundary_node_firewall_config = config.boundary_node_firewall.unwrap();
        boundary_node_firewall_config
            .config_file
            .clone_from(&nftables_config_path);
        let mut firewall = set_up_firewall_dependencies(
            replica_firewall_config,
            boundary_node_firewall_config,
            tmp_dir.path(),
            role,
            node_id,
        );

        firewall
            .check_for_firewall_config(RegistryVersion::new(1))
            .expect("Should successfully produce a firewall config");

        let golden = String::from_utf8(golden_bytes.to_vec()).unwrap();
        let nftables = std::fs::read_to_string(&nftables_config_path).unwrap();
        let file_name = format!("nftables_{label}.conf");
        if nftables != golden {
            maybe_write_golden(nftables, &file_name);
            panic!(
                "The output doesn't match the golden. \
                In order to see the generated `nftables.conf` file please \
                look inside `outputs.zip` file under `bazel-testlogs`"
            );
        }
    }

    /// Returns the `ic.json5` config filled with some dummy values.
    fn get_config() -> ConfigOptional {
        let template = config::guestos::generate_ic_config::IcConfigTemplate {
            ipv6_address: "::".to_string(),
            ipv6_prefix: "::/64".to_string(),
            ipv4_address: "".to_string(),
            ipv4_gateway: "".to_string(),
            nns_urls: "http://www.fakeurl.com/".to_string(),
            backup_retention_time_secs: "0".to_string(),
            backup_purging_interval_secs: "0".to_string(),
            query_stats_epoch_length: "600".to_string(),
            jaeger_addr: "".to_string(),
            domain_name: "".to_string(),
            node_reward_type: "".to_string(),
            malicious_behavior: "null".to_string(),
        };

        let ic_json = config::guestos::generate_ic_config::render_ic_config(template)
            .expect("Failed to render config template");
        ConfigSource::Literal(ic_json)
            .load()
            .expect("Failed to parse dummy config")
    }

    /// When `TEST_UNDECLARED_OUTPUTS_DIR` is set, writes the `content` to a file in the specified
    /// directory. Later that file can be inspected manually, i.e. it won't be erased by the test
    /// runner.
    ///
    /// See: the `TEST_UNDECLARED_OUTPUTS_DIR` in https://bazel.build/reference/test-encyclopedia
    fn maybe_write_golden(content: String, file_name: &str) {
        let Ok(dir_str) = std::env::var("TEST_UNDECLARED_OUTPUTS_DIR") else {
            return;
        };

        let dir = PathBuf::from(dir_str);
        let mut file = std::fs::File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join(file_name))
            .unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    /// Sets up all the necessary dependencies of the [`Firewall`]
    fn set_up_firewall_dependencies(
        config: ReplicaFirewallConfig,
        boundary_node_config: BoundaryNodeFirewallConfig,
        tmp_dir: &Path,
        role: Role,
        node_id: NodeId,
    ) -> Firewall {
        let registry = set_up_registry(role, node_id);

        let registry_helper = Arc::new(RegistryHelper::new(
            node_id,
            registry.clone(),
            no_op_logger(),
        ));

        let (crypto, _) =
            ic_crypto_test_utils_tls::temp_crypto_component_with_tls_keys(registry, node_id);
        let catch_up_package_provider = CatchUpPackageProvider::new(
            registry_helper.clone(),
            tmp_dir.join("cups"),
            Arc::new(CryptoReturningOk::default()),
            Arc::new(crypto),
            no_op_logger(),
            node_id,
        );

        Firewall::new(
            node_id,
            registry_helper,
            Arc::new(OrchestratorMetrics::new(&ic_metrics::MetricsRegistry::new())),
            config,
            boundary_node_config,
            Arc::new(catch_up_package_provider),
            no_op_logger(),
        )
    }

    /// Sets up the registry with:
    /// 1) two node records - one for the specified node + another one,
    /// 2) a bunch of firewall rules,
    /// 3) a Subnet record,
    ///    and returns a registry client.
    fn set_up_registry(role: Role, node: NodeId) -> Arc<FakeRegistryClient> {
        let registry_version = RegistryVersion::new(1);
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

        // add [`NodeRecord`] for the given node
        add_node_record(
            &registry_data_provider,
            registry_version,
            node,
            /*ip=*/ "1.1.1.1",
        );

        // create a system subnet with one node
        let system_subnet_node_id = node_test_id(1001);
        add_node_record(
            &registry_data_provider,
            registry_version,
            system_subnet_node_id,
            /*ip=*/ "a4c2:7f91:3db6:1e8c:5a4f:cc92:0b37:6e41",
        );
        let system_subnet_record = SubnetRecordBuilder::from(&[system_subnet_node_id])
            .with_subnet_type(SubnetType::System)
            .build();
        let system_subnet_id = subnet_test_id(100);
        add_single_subnet_record(
            &registry_data_provider,
            registry_version.get(),
            system_subnet_id,
            system_subnet_record,
        );

        // create an application subnet
        let app_subnet_node_id = node_test_id(2002);
        add_node_record(
            &registry_data_provider,
            registry_version,
            app_subnet_node_id,
            /*ip=*/ "3fda:92b7:4c1e:8a23:7d61:2f9c:ab42:19e5",
        );
        let app_subnet_record = SubnetRecordBuilder::from(&[app_subnet_node_id])
            .with_subnet_type(SubnetType::Application)
            .build();
        let app_subnet_id = subnet_test_id(200);
        add_single_subnet_record(
            &registry_data_provider,
            registry_version.get(),
            app_subnet_id,
            app_subnet_record,
        );

        // Add an API boundary node
        let api_boundary_node_id = node_test_id(API_BOUNDARY_NODE_ID);
        add_node_record(
            &registry_data_provider,
            registry_version,
            api_boundary_node_id,
            /*ip=*/ "3.0.0.3",
        );
        add_api_boundary_node_record(
            &registry_data_provider,
            registry_version,
            api_boundary_node_id,
        );

        // Add an unassigned node
        let unassigned_node_id = node_test_id(4004);
        add_node_record(
            &registry_data_provider,
            registry_version,
            unassigned_node_id,
            /*ip=*/ "4.0.0.4",
        );

        // Add a bunch of firewall rules for different scopes.
        add_firewall_rules_record(
            &registry_data_provider,
            registry_version,
            &FirewallRulesScope::Subnet(subnet_test_id(1)),
            /*ip=*/ "3.3.3.3",
            /*port=*/ 1003,
        );
        add_firewall_rules_record(
            &registry_data_provider,
            registry_version,
            &FirewallRulesScope::ReplicaNodes,
            /*ip=*/ "4.4.4.4",
            /*port=*/ 1004,
        );
        add_firewall_rules_record(
            &registry_data_provider,
            registry_version,
            &FirewallRulesScope::Node(node),
            /*ip=*/ "5.5.5.5",
            /*port=*/ 1005,
        );
        add_firewall_rules_record(
            &registry_data_provider,
            registry_version,
            &FirewallRulesScope::Global,
            /*ip=*/ "6.6.6.6",
            /*port=*/ 1006,
        );
        add_firewall_rules_record(
            &registry_data_provider,
            RegistryVersion::from(registry_version),
            &FirewallRulesScope::ApiBoundaryNodes,
            /*ip=*/ "7.7.7.7",
            /*port=*/ 1007,
        );

        let mut subnet_ids = vec![system_subnet_id, app_subnet_id];

        match role {
            Role::AssignedReplica(subnet_id) => {
                let subnet_record = SubnetRecordBuilder::from(&[node]).build();
                add_single_subnet_record(
                    &registry_data_provider,
                    registry_version.get(),
                    subnet_id,
                    subnet_record,
                );
                subnet_ids.push(subnet_id);
            }
            Role::BoundaryNode => {
                registry_data_provider
                    .add(
                        &make_api_boundary_node_record_key(node),
                        RegistryVersion::from(registry_version),
                        Some(ApiBoundaryNodeRecord {
                            version: String::from("11"),
                        }),
                    )
                    .expect("Failed to add API BN record.");
            }
            Role::UnassignedReplica => {}
        }

        add_subnet_list_record(&registry_data_provider, registry_version.get(), subnet_ids);

        let registry = Arc::new(FakeRegistryClient::new(
            Arc::clone(&registry_data_provider) as Arc<_>
        ));

        registry.update_to_latest_version();

        registry
    }

    /// Adds a [`NodeRecord`] to the registry.
    fn add_node_record(
        registry_data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        node: NodeId,
        ip: &str,
    ) {
        registry_data_provider
            .add(
                &make_node_record_key(node),
                registry_version,
                Some(NodeRecord {
                    http: Some(ConnectionEndpoint {
                        ip_addr: String::from(ip),
                        port: 80,
                    }),
                    xnet: None,
                    node_operator_id: vec![],
                    chip_id: None,
                    hostos_version_id: None,
                    public_ipv4_config: None,
                    domain: None,
                    node_reward_type: None,
                    ssh_node_state_write_access: vec![],
                }),
            )
            .expect("Failed to add node record.");
    }

    /// Adds an [`ApiBoundaryNodeRecord`] to the registry.
    fn add_api_boundary_node_record(
        registry_data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        node: NodeId,
    ) {
        registry_data_provider
            .add(
                &make_api_boundary_node_record_key(node),
                registry_version,
                Some(ApiBoundaryNodeRecord {
                    version: String::from("11"),
                }),
            )
            .expect("Failed to add API boundary node record.");
    }

    /// Adds a [`FirewallRule`] to the registry.
    fn add_firewall_rules_record(
        registry_data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        scope: &FirewallRulesScope,
        ip: &str,
        port: u32,
    ) {
        registry_data_provider
            .add(
                &make_firewall_rules_record_key(scope),
                registry_version,
                Some(FirewallRuleSet {
                    entries: vec![FirewallRule {
                        ipv4_prefixes: vec![String::from(ip)],
                        ipv6_prefixes: vec![format!("::ffff:{}", ip)],
                        ports: vec![port],
                        action: FirewallAction::Allow as i32,
                        comment: scope.to_string(),
                        user: None,
                        direction: Some(FirewallRuleDirection::Inbound as i32),
                    }],
                }),
            )
            .unwrap();
    }
}
