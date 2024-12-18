use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use ic_base_types::NodeId;

use super::common::{
    get_api_boundary_node_ids_from_snapshot, get_node_record_from_snapshot, InvariantCheckError,
    RegistrySnapshot,
};

/// Checks API Boundary Node invariants:
///    * Ensure API Boundary Nodes have unique domain names
///    * Ensure each API Boundary Node record has a corresponding NodeRecord
///    * Ensure that both `domain` and `http` fields of the NodeRecord are not None
///    * Ensure that both `ipv6`(required) and `ipv4`(optional) of the NodeRecord can be parsed
pub(crate) fn check_api_boundary_node_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut domain_to_id: HashMap<String, NodeId> = HashMap::new();
    // IMPORTANT: this code structure below rigorously follows the structure of the `fn try_to_populate_api_boundary_nodes(..)` in message_routing.rs.
    // These two code blocks should be kept in sync to avoid stalling the subnets.
    // Please be very mindful when modifying the code below.
    // Here is an example of code changes leading to subnet stalling:
    // - Assume the requirement for an API BN to have a related NodeRecord is remove/relaxed below
    // - However, this requirement still exists and holds in the message_route.rs code
    // - An attempt to read the related NodeRecord for an API BN would fail and cause ReadRegistryError::Transient()
    // - Transient registry errors are retried in `message_route.rs` code. However, in this case it's not helpful, the error is persistent in nature
    // - As a result, the subnet is stalled
    let api_boundary_node_ids = get_api_boundary_node_ids_from_snapshot(snapshot)?;
    for api_bn_id in api_boundary_node_ids {
        let node_record = get_node_record_from_snapshot(api_bn_id, snapshot)?;
        let Some(node_record) = node_record else {
            return Err(InvariantCheckError {
                msg: format!(
                    "API Boundary Node with id={api_bn_id} doesn't have a corresponding NodeRecord"
                ),
                source: None,
            });
        };

        let Some(domain) = node_record.domain else {
            return Err(InvariantCheckError {
                msg: format!("domain field of the NodeRecord with id={api_bn_id} is None"),
                source: None,
            });
        };

        let Some(http) = node_record.http else {
            return Err(InvariantCheckError {
                msg: format!("http field of the NodeRecord with id={api_bn_id} is None"),
                source: None,
            });
        };

        let Ok(_ipv6) = http.ip_addr.parse::<Ipv6Addr>() else {
            return Err(InvariantCheckError {
                msg: "failed to parse ipv6 address of the node".to_string(),
                source: None,
            });
        };

        if let Some(ipv4_config) = node_record.public_ipv4_config {
            let Ok(_ipv4) = ipv4_config.ip_addr.parse::<Ipv4Addr>() else {
                return Err(InvariantCheckError {
                    msg: "failed to parse ipv4 address of the node".to_string(),
                    source: None,
                });
            };
        }

        if let Some(existing_api_bn) = domain_to_id.get(&domain) {
            return Err(InvariantCheckError {
                msg: format!("domain {domain} has two nodes associated with it with id={existing_api_bn} and id={api_bn_id}"),
                source: None,
            });
        }
        domain_to_id.insert(domain, api_bn_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord,
        node::v1::{ConnectionEndpoint, IPv4InterfaceConfig, NodeRecord},
    };
    use ic_registry_keys::{make_api_boundary_node_record_key, make_node_record_key};
    use prost::Message;

    use crate::invariants::common::RegistrySnapshot;

    use super::check_api_boundary_node_invariants;

    #[test]
    fn test_check_api_boundary_node_invariants_succeed() {
        let mut snapshot = RegistrySnapshot::new();

        for (id, domain) in [
            (0, "example-1.com"),
            (1, "example-2.com"),
            (2, "example-3.com"),
        ] {
            let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

            snapshot.insert(
                make_api_boundary_node_record_key(node_id).into_bytes(), // key
                ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
            );
            snapshot.insert(
                make_node_record_key(node_id).into_bytes(), // key
                NodeRecord {
                    public_ipv4_config: Some(IPv4InterfaceConfig {
                        ip_addr: "127.0.0.1".to_string(),
                        ..Default::default()
                    }),
                    http: Some(ConnectionEndpoint {
                        ip_addr: "2001:db8:3333:4444:5555:6666:7777:8888".to_string(),
                        ..Default::default()
                    }),
                    domain: Some(domain.into()),
                    ..Default::default()
                }
                .encode_to_vec(), // record
            );
        }

        assert!(check_api_boundary_node_invariants(&snapshot).is_ok());
    }

    #[test]
    fn test_check_api_boundary_node_no_node_record_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        let id = 0;
        let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            format!("API Boundary Node with id={node_id} doesn't have a corresponding NodeRecord"),
        );
    }

    #[test]
    fn test_check_api_boundary_node_empty_http_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        let id = 0;
        let domain = "example-1.com";
        let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord {
                domain: Some(domain.into()),
                ..Default::default()
            }
            .encode_to_vec(), // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            format!("http field of the NodeRecord with id={node_id} is None"),
        );
    }

    #[test]
    fn test_check_api_boundary_node_empty_domain_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        let id = 0;
        let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord {
                http: Some(ConnectionEndpoint::default()),
                ..Default::default()
            }
            .encode_to_vec(), // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            format!("domain field of the NodeRecord with id={node_id} is None"),
        );
    }

    #[test]
    fn test_check_api_boundary_node_duplicate_domains_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        for (id, domain) in [
            (0, "example-1.com"),
            (1, "example-2.com"),
            (2, "example-2.com"), // Duplicate
        ] {
            let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

            snapshot.insert(
                make_api_boundary_node_record_key(node_id).into_bytes(), // key
                ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
            );
            snapshot.insert(
                make_node_record_key(node_id).into_bytes(), // key
                NodeRecord {
                    public_ipv4_config: Some(IPv4InterfaceConfig {
                        ip_addr: "127.0.0.1".to_string(),
                        ..Default::default()
                    }),
                    http: Some(ConnectionEndpoint {
                        ip_addr: "2001:db8:3333:4444:5555:6666:7777:8888".to_string(),
                        ..Default::default()
                    }),
                    domain: Some(domain.into()),
                    ..Default::default()
                }
                .encode_to_vec(), // record
            );
        }

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            format!(
                "domain example-2.com has two nodes associated with it with id={} and id={}",
                PrincipalId::new_node_test_id(1),
                PrincipalId::new_node_test_id(2)
            )
        );
    }

    #[test]
    fn test_check_api_boundary_node_ipv6_parsing_error() {
        let mut snapshot = RegistrySnapshot::new();
        let (node_id, domain) = (0, "example-1.com");
        let node_id: NodeId = PrincipalId::new_node_test_id(node_id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );
        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord {
                public_ipv4_config: Some(IPv4InterfaceConfig {
                    ip_addr: "127.0.0.1".to_string(),
                    ..Default::default()
                }),
                http: Some(ConnectionEndpoint {
                    ip_addr: "not_an_ipv6".to_string(),
                    ..Default::default()
                }),
                domain: Some(domain.into()),
                ..Default::default()
            }
            .encode_to_vec(), // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            "failed to parse ipv6 address of the node".to_string(),
        );
    }

    #[test]
    fn test_check_api_boundary_node_ipv4_parsing_error() {
        let mut snapshot = RegistrySnapshot::new();
        let (node_id, domain) = (0, "example-1.com");
        let node_id: NodeId = PrincipalId::new_node_test_id(node_id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );
        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord {
                public_ipv4_config: Some(IPv4InterfaceConfig {
                    ip_addr: "not_an_ipv4".to_string(),
                    ..Default::default()
                }),
                http: Some(ConnectionEndpoint {
                    ip_addr: "2001:db8:3333:4444:5555:6666:7777:8888".to_string(),
                    ..Default::default()
                }),
                domain: Some(domain.into()),
                ..Default::default()
            }
            .encode_to_vec(), // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            "failed to parse ipv4 address of the node".to_string(),
        );
    }
}
