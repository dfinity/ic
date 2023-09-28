use std::collections::HashMap;

use ic_base_types::NodeId;

use super::common::{
    get_api_boundary_node_records_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

/// Checks API Boundary Node invariants:
///    * Ensure API Boundary Nodes have unique domain names
pub(crate) fn check_api_boundary_node_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let api_boundary_nodes = get_api_boundary_node_records_from_snapshot(snapshot);

    let mut domain_to_ids: HashMap<String, Vec<NodeId>> = HashMap::new();

    for (id, n) in &api_boundary_nodes {
        domain_to_ids
            .entry(n.domain.clone())
            .or_insert(vec![])
            .push(*id);
    }

    let errors: Vec<String> = domain_to_ids
        .iter()
        .map(|(domain, ids)| match ids.len() {
            1 => Ok(()),
            _ => Err(format!("domain {domain} should have one node associated with it, but has the following: {ids:?}")),
        })
        .filter_map(Result::err)
        .collect();

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
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_keys::make_api_boundary_node_record_key;

    use crate::{invariants::common::RegistrySnapshot, mutations::common::encode_or_panic};

    use super::check_api_boundary_node_invariants;

    #[test]
    fn test_check_api_boundary_node_invariants() {
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
        }

        assert!(check_api_boundary_node_invariants(&snapshot).is_ok());
    }

    #[test]
    fn test_check_api_boundary_node_invariants_conflict() {
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
        }

        assert!(check_api_boundary_node_invariants(&snapshot).is_err());
    }
}
