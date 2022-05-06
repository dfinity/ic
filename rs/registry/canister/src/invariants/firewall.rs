use crate::invariants::common::{
    get_node_records_from_snapshot, get_subnet_ids_from_snapshot, get_value_from_snapshot,
    InvariantCheckError, RegistrySnapshot,
};

use std::{
    collections::BTreeSet,
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr},
};

use ipnet::{Ipv4Net, Ipv6Net};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::firewall::v1::{FirewallAction, FirewallRule, FirewallRuleSet};
use ic_registry_keys::{
    get_firewall_rules_record_principal_id, make_firewall_rules_record_key, FirewallRulesScope,
};

const COMMENT_SIZE: usize = 255;

/// Checks the firewall invariants:
///    * Principals refer to existing subnets and nodes
///    * A firewall rule is valid, iff:
///        * At least one IPv4 or IPv6 prefix is specified
///        * IP prefixes are valid (either v4 or v6, correct format)
///        * At least one port is specified
///        * Port numbers are valid (<= 65535)
///        * Action is allow or deny
///        * Comment is bounded in size (up to 255 characters)
pub(crate) fn check_firewall_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    validate_firewall_rule_principals(snapshot)?;

    for node_id in get_node_records_from_snapshot(snapshot).keys() {
        let node_ruleset = get_node_firewall_rules(snapshot, node_id);
        validate_firewall_ruleset(node_ruleset)?;
    }

    for subnet_id in get_subnet_ids_from_snapshot(snapshot) {
        let subnet_ruleset = get_subnet_firewall_rules(snapshot, &subnet_id);
        validate_firewall_ruleset(subnet_ruleset)?;
    }

    let replica_node_ruleset = get_replica_nodes_firewall_rules(snapshot);
    validate_firewall_ruleset(replica_node_ruleset)?;

    let global_ruleset = get_global_firewall_rules(snapshot);
    validate_firewall_ruleset(global_ruleset)?;

    Ok(())
}

/// A helper function that checks the invariant that each node and subnet specific
/// ruleset refers either to an existing node/subnet principal or is empty.
fn validate_firewall_rule_principals(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut principal_ids: BTreeSet<PrincipalId> = get_node_records_from_snapshot(snapshot)
        .keys()
        .map(|s| s.get())
        .collect();

    principal_ids.extend(
        get_subnet_ids_from_snapshot(snapshot)
            .iter()
            .map(|s| s.get()),
    );

    for key in snapshot.keys() {
        let record_key = String::from_utf8(key.clone()).unwrap();
        if let Some(principal_id) = get_firewall_rules_record_principal_id(&record_key) {
            if let Some(firewall_rules) = get_firewall_rules(snapshot, record_key.to_string()) {
                if !principal_ids.contains(&principal_id) && !firewall_rules.entries.is_empty() {
                    return Err(InvariantCheckError {
                        msg: format!(
                            "Firewall rule entry refers to non-existing principal: {:?}",
                            record_key
                        ),
                        source: None,
                    });
                }
            }
        }
    }

    Ok(())
}

/// A helper function that validates invariants for a firewall ruleset by checking
/// one rule after another. The ruleset is only valid if every single rule within
/// is valid.
fn validate_firewall_ruleset(
    firewall_ruleset: Option<FirewallRuleSet>,
) -> Result<(), InvariantCheckError> {
    if let Some(firewall_rules) = firewall_ruleset {
        for firewall_rule in firewall_rules.entries {
            validate_firewall_rule(&firewall_rule)?;
        }
    }

    Ok(())
}

/// A helper function that validates invariants for a single firewall rule:
///    * At least one IPv4 or IPv6 prefix is specified
///    * IP prefix is valid (either v4 or v6, correct format)
///    * At least one port is specified
///    * Port number is valid (<= 65535)
///    * Action is allow or deny
///    * Comment is bounded in size (up to 255 bytes)
fn validate_firewall_rule(rule: &FirewallRule) -> Result<(), InvariantCheckError> {
    // check that at least one IPv4 or IPv6 prefix exists
    if rule.ipv4_prefixes.is_empty() && rule.ipv6_prefixes.is_empty() {
        return Err(InvariantCheckError {
            msg: "At least one IPv4 or IPv6 prefix must be specified".to_string(),
            source: None,
        });
    }

    // check the validity of the specified IPv4 prefixes/addresses by trying to parse them
    for ipv4_prefix in rule.ipv4_prefixes.iter() {
        // check if it is a prefix (i.e., ip address / prefix length) or an address
        if ipv4_prefix.contains('/') {
            ipv4_prefix
                .parse::<Ipv4Net>()
                .map_err(|e| InvariantCheckError {
                    msg: format!("Failed to parse IPv4 prefix: {:?}", ipv4_prefix),
                    source: Some(Box::new(e)),
                })?;
        } else {
            ipv4_prefix
                .parse::<Ipv4Addr>()
                .map_err(|e| InvariantCheckError {
                    msg: format!("Failed to parse IPv4 address: {:?}", ipv4_prefix),
                    source: Some(Box::new(e)),
                })?;
        }
    }

    // check the validity of the specified IPv6 prefixes/addresses by trying to parse them
    for ipv6_prefix in rule.ipv6_prefixes.iter() {
        // check if it is a prefix (i.e., ip address / prefix length) or an address
        if ipv6_prefix.contains('/') {
            ipv6_prefix
                .parse::<Ipv6Net>()
                .map_err(|e| InvariantCheckError {
                    msg: format!("Failed to parse IPv6 prefix: {:?}", ipv6_prefix),
                    source: Some(Box::new(e)),
                })?;
        } else {
            ipv6_prefix
                .parse::<Ipv6Addr>()
                .map_err(|e| InvariantCheckError {
                    msg: format!("Failed to parse IPv6 address: {:?}", ipv6_prefix),
                    source: Some(Box::new(e)),
                })?;
        }
    }

    // check that at least one port is specified
    if rule.ports.is_empty() {
        return Err(InvariantCheckError {
            msg: "At least one port must be specified".to_string(),
            source: None,
        });
    }

    // check that port number is <= 65535
    for &port in rule.ports.iter() {
        u16::try_from(port).map_err(|e| InvariantCheckError {
            msg: format!("Port is outside of the allowed range: {:?}", port),
            source: Some(Box::new(e)),
        })?;
    }

    // check that action is not unspecified
    if rule.action != (FirewallAction::Allow as i32) && rule.action != (FirewallAction::Deny as i32)
    {
        return Err(InvariantCheckError {
            msg: format!("Action {:?} is unspecified", rule.action),
            source: None,
        });
    }

    // check that the size of comment is 255 bytes or less
    if rule.comment.len() > COMMENT_SIZE {
        return Err(InvariantCheckError {
            msg: format!(
                "Comment {:?} is too long (> {:?} bytes)",
                rule.comment, COMMENT_SIZE
            ),
            source: None,
        });
    }

    Ok(())
}

/// A helper function that returns the global firewall ruleset (if it exists).
fn get_global_firewall_rules(snapshot: &RegistrySnapshot) -> Option<FirewallRuleSet> {
    let firewall_record_key = make_firewall_rules_record_key(&FirewallRulesScope::Global);
    get_firewall_rules(snapshot, firewall_record_key)
}

/// A helper function that returns the firewall ruleset specific for the replica
/// nodes (if it exists).
fn get_replica_nodes_firewall_rules(snapshot: &RegistrySnapshot) -> Option<FirewallRuleSet> {
    let firewall_record_key = make_firewall_rules_record_key(&FirewallRulesScope::ReplicaNodes);
    get_firewall_rules(snapshot, firewall_record_key)
}

/// A helper function that returns the firewall ruleset specific to the subnet
/// with the supplied subnet id (if it exists).
fn get_subnet_firewall_rules(
    snapshot: &RegistrySnapshot,
    subnet_id: &SubnetId,
) -> Option<FirewallRuleSet> {
    let firewall_record_key =
        make_firewall_rules_record_key(&FirewallRulesScope::Subnet(*subnet_id));
    get_firewall_rules(snapshot, firewall_record_key)
}

/// A helper function that returns the firewall ruleset specific to the node
/// with the supplied node id (if it exists).
fn get_node_firewall_rules(
    snapshot: &RegistrySnapshot,
    node_id: &NodeId,
) -> Option<FirewallRuleSet> {
    let firewall_record_key = make_firewall_rules_record_key(&FirewallRulesScope::Node(*node_id));
    get_firewall_rules(snapshot, firewall_record_key)
}

/// A helper function that returns the firewall ruleset stored in the registry
/// under the given record key (if it exists).
fn get_firewall_rules(snapshot: &RegistrySnapshot, record_key: String) -> Option<FirewallRuleSet> {
    if snapshot.contains_key(record_key.as_bytes()) {
        Some(
            get_value_from_snapshot(snapshot, record_key.clone())
                .unwrap_or_else(|| panic!("Could not find firewall rules: {}", record_key)),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_nns_common::registry::encode_or_panic;
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_protobuf::registry::subnet::v1::SubnetListRecord;
    use ic_registry_keys::{make_node_record_key, make_subnet_list_record_key};

    // helper function that returns a generic firewall rule for use in the tests.
    fn firewall_rule_builder() -> FirewallRule {
        FirewallRule {
            ipv4_prefixes: vec![
                "66.180.176.0/20".to_string(),
                "192.12.53.0/24".to_string(),
                "205.172.164.0/22".to_string(),
            ],
            ipv6_prefixes: vec![
                "2620:c4::/48".to_string(),
                "2a02:a90::/32".to_string(),
                "2001:67c:10ec::/48".to_string(),
            ],
            ports: vec![3012, 4704, 8192, 8180, 8051],
            action: FirewallAction::Allow as i32,
            comment: "COMMENT".to_string(),
        }
    }

    // helper function that returns a generic firewall ruleset for use in the tests.
    fn firewall_ruleset_builder() -> FirewallRuleSet {
        let mut firewall_rule_1 = firewall_rule_builder();
        firewall_rule_1.ipv4_prefixes = vec![];
        firewall_rule_1.ipv6_prefixes = vec![
            "2620:c4::/48".to_string(),
            "2a02:a90::/32".to_string(),
            "2001:67c:10ec::/48".to_string(),
        ];

        let mut firewall_rule_2 = firewall_rule_builder();
        firewall_rule_2.ipv4_prefixes = vec!["66.180.176.0/20".to_string()];
        firewall_rule_2.ipv6_prefixes = vec![];

        FirewallRuleSet {
            entries: vec![firewall_rule_1, firewall_rule_2],
        }
    }

    // helper function that returns a node record for use in the tests.
    fn node_record_builder() -> NodeRecord {
        NodeRecord {
            node_operator_id: vec![0],
            xnet: None,
            http: None,
            p2p_flow_endpoints: vec![],
            prometheus_metrics_http: None,
            public_api: vec![],
            private_api: vec![],
            prometheus_metrics: vec![],
            xnet_api: vec![],
        }
    }

    #[test]
    fn test_validate_firewall_rule_no_prefixes() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec![];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = "At least one IPv4 or IPv6 prefix must be specified".to_string();
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_only_ipv4_prefixes() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv6_prefixes = vec![];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_single_ipv4_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec!["66.180.176.0/20".to_string()];
        fw_rule.ipv6_prefixes = vec![];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_malformed_ipv4_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec!["66..176.0/20".to_string()];
        fw_rule.ipv6_prefixes = vec![];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Failed to parse IPv4 prefix: {:?}",
            fw_rule.ipv4_prefixes[0]
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_single_host_ipv4_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec!["66.180.176.219/32".to_string()];
        fw_rule.ipv6_prefixes = vec![];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_ipv4_address() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec!["66.180.176.219".to_string()];
        fw_rule.ipv6_prefixes = vec![];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_malformed_ipv4_address() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec!["66.XYZ.176.219".to_string()];
        fw_rule.ipv6_prefixes = vec![];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Failed to parse IPv4 address: {:?}",
            fw_rule.ipv4_prefixes[0]
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_only_ipv6_prefixes() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec![
            "2620:c4::/48".to_string(),
            "2a02:a90::/32".to_string(),
            "2001:67c:10ec::/48".to_string(),
        ];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_single_ipv6_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec!["2620:c4::/48".to_string()];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_malformed_ipv6_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec!["2620::a90:c4::/48".to_string()];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Failed to parse IPv6 prefix: {:?}",
            fw_rule.ipv6_prefixes[0]
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_single_host_ipv6_prefix() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec!["2001:0db8:0000:0000:0000:ff00:0042:8329/128".to_string()];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_ipv6_address() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec!["2001:0db8:0000:0000:0000:ff00:0042:8329".to_string()];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_malformed_ipv6_address() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ipv4_prefixes = vec![];
        fw_rule.ipv6_prefixes = vec!["2001::000000:ff::0042:8329".to_string()];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Failed to parse IPv6 address: {:?}",
            fw_rule.ipv6_prefixes[0]
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_many_ports() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ports = vec![3012, 4704, 8192, 8180, 8051];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_single_port() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ports = vec![8180];
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_out_of_range_port() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ports = vec![3012, 4704, 81920, 8180, 8051];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Port is outside of the allowed range: {:?}",
            fw_rule.ports[2]
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_no_ports() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.ports = vec![];

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = "At least one port must be specified".to_string();
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_allow_action() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.action = FirewallAction::Allow as i32;
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_deny_action() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.action = FirewallAction::Deny as i32;
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_unspecified_action() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.action = FirewallAction::Unspecified as i32;

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!("Action {:?} is unspecified", fw_rule.action);
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_empty_comment() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.comment = "".to_string();
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_normal_comment() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.comment = "X".repeat(10);
        assert!(validate_firewall_rule(&fw_rule).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_too_long_comment() {
        let mut fw_rule = firewall_rule_builder();
        fw_rule.comment = "X".repeat(300);

        let actual_error = validate_firewall_rule(&fw_rule).unwrap_err().msg;
        let expected_error = format!(
            "Comment {:?} is too long (> {:?} bytes)",
            fw_rule.comment, COMMENT_SIZE
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_principals_full_node_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(),
            encode_or_panic::<NodeRecord>(&node_record_builder()),
        );
        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Node(node_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&firewall_ruleset_builder()),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_empty_node_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(),
            encode_or_panic::<NodeRecord>(&node_record_builder()),
        );
        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Node(node_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&FirewallRuleSet { entries: vec![] }),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_no_node_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(),
            encode_or_panic::<NodeRecord>(&node_record_builder()),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_missing_node_record() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));

        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Node(node_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&firewall_ruleset_builder()),
        );

        let actual_error = validate_firewall_rule_principals(&snapshot)
            .unwrap_err()
            .msg;
        let expected_error = format!(
            "Firewall rule entry refers to non-existing principal: {:?}",
            make_firewall_rules_record_key(&FirewallRulesScope::Node(node_id))
        );
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn test_validate_firewall_rule_principals_full_subnet_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));

        snapshot.insert(
            make_subnet_list_record_key().into_bytes(),
            encode_or_panic::<SubnetListRecord>(&SubnetListRecord {
                subnets: vec![subnet_id.get().to_vec()],
            }),
        );
        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Subnet(subnet_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&firewall_ruleset_builder()),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_empty_subnet_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));

        snapshot.insert(
            make_subnet_list_record_key().into_bytes(),
            encode_or_panic::<SubnetListRecord>(&SubnetListRecord {
                subnets: vec![subnet_id.get().to_vec()],
            }),
        );
        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Subnet(subnet_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&FirewallRuleSet { entries: vec![] }),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_no_subnet_ruleset() {
        let mut snapshot = RegistrySnapshot::new();
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));

        snapshot.insert(
            make_subnet_list_record_key().into_bytes(),
            encode_or_panic::<SubnetListRecord>(&SubnetListRecord {
                subnets: vec![subnet_id.get().to_vec()],
            }),
        );

        assert!(validate_firewall_rule_principals(&snapshot).is_ok());
    }

    #[test]
    fn test_validate_firewall_rule_principals_missing_subnet_record() {
        let mut snapshot = RegistrySnapshot::new();
        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));

        snapshot.insert(
            make_firewall_rules_record_key(&FirewallRulesScope::Subnet(subnet_id)).into_bytes(),
            encode_or_panic::<FirewallRuleSet>(&firewall_ruleset_builder()),
        );

        let actual_error = validate_firewall_rule_principals(&snapshot)
            .unwrap_err()
            .msg;
        let expected_error = format!(
            "Firewall rule entry refers to non-existing principal: {:?}",
            make_firewall_rules_record_key(&FirewallRulesScope::Subnet(subnet_id))
        );
        assert_eq!(actual_error, expected_error);
    }
}
