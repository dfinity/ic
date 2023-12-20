use std::collections::HashMap;

use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_keys::make_node_record_key;

use super::common::{
    get_api_boundary_node_records_from_snapshot, get_value_from_snapshot, InvariantCheckError,
    RegistrySnapshot,
};

/// Checks API Boundary Node invariants:
///    * Ensure API Boundary Nodes have unique domain names
///    * Ensure each API Boundary Node record has a corresponding NodeRecord
///    * Ensure that http field of the corresponding NodeRecord is not None.
pub(crate) fn check_api_boundary_node_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let api_boundary_nodes = get_api_boundary_node_records_from_snapshot(snapshot);

    let mut domain_to_ids: HashMap<String, Vec<NodeId>> = HashMap::new();
    let mut errors: Vec<String> = vec![];
    for (id, n) in api_boundary_nodes {
        let node_record_key = make_node_record_key(id);
        if let Some(record) = get_value_from_snapshot::<NodeRecord>(snapshot, node_record_key) {
            if record.http.is_none() {
                errors.push(format!("http field of the NodeRecord with id={id} is None"));
            }
        } else {
            errors.push(format!(
                "API Boundary Node with id={id} doesn't have a corresponding NodeRecord"
            ));
        }
        domain_to_ids.entry(n.domain.clone()).or_default().push(id);
    }

    domain_to_ids.iter().for_each(|(domain, ids)| {
        if ids.len() != 1 {
            errors.push(format!("domain {domain} should have one node associated with it, but has the following: {ids:?}"));
        }
    });

    if !errors.is_empty() {
        return Err(InvariantCheckError {
            msg: errors.join("\n"),
            source: None,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord,
        node::v1::{ConnectionEndpoint, NodeRecord},
    };
    use ic_registry_keys::{make_api_boundary_node_record_key, make_node_record_key};

    use crate::{invariants::common::RegistrySnapshot, mutations::common::encode_or_panic};

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
                encode_or_panic(&ApiBoundaryNodeRecord {
                    domain: domain.into(),
                    ..Default::default()
                }), // record
            );
            snapshot.insert(
                make_node_record_key(node_id).into_bytes(), // key
                encode_or_panic(&NodeRecord {
                    http: Some(ConnectionEndpoint::default()),
                    ..Default::default()
                }), // record
            );
        }

        assert!(check_api_boundary_node_invariants(&snapshot).is_ok());
    }

    #[test]
    fn test_check_api_boundary_node_no_node_record_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        let id = 0;
        let domain = "example-1.com";
        let node_id: NodeId = PrincipalId::new_node_test_id(id).into();

        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            encode_or_panic(&ApiBoundaryNodeRecord {
                domain: domain.into(),
                ..Default::default()
            }), // record
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
            encode_or_panic(&ApiBoundaryNodeRecord {
                domain: domain.into(),
                ..Default::default()
            }), // record
        );

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            encode_or_panic(&NodeRecord {
                http: None,
                ..Default::default()
            }), // record
        );

        assert_eq!(
            check_api_boundary_node_invariants(&snapshot)
                .unwrap_err()
                .msg,
            format!("http field of the NodeRecord with id={node_id} is None"),
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
                encode_or_panic(&ApiBoundaryNodeRecord {
                    domain: domain.into(),
                    ..Default::default()
                }), // record
            );
            snapshot.insert(
                make_node_record_key(node_id).into_bytes(), // key
                encode_or_panic(&NodeRecord {
                    http: Some(ConnectionEndpoint::default()),
                    ..Default::default()
                }), // record
            );
        }

        assert_eq!(check_api_boundary_node_invariants(&snapshot)
            .unwrap_err()
            .msg,
            format!("domain example-2.com should have one node associated with it, but has the following: [{}, {}]", 
            PrincipalId::new_node_test_id(1), PrincipalId::new_node_test_id(2))
        );
    }
}
