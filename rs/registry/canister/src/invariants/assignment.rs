use std::collections::HashSet;

use ic_base_types::{NodeId, PrincipalId};

use super::{
    common::{
        get_api_boundary_node_records_from_snapshot, get_node_records_from_snapshot,
        InvariantCheckError, RegistrySnapshot,
    },
    subnet::get_subnet_records_map,
};

/// Checks node assignment invariants:
///    * A node can only have one of the following three assignments:
///         - Unassigned
///         - Replica
///         - ApiBoundaryNode
pub(crate) fn check_node_assignment_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    // Replica
    let replicas: HashSet<NodeId> = get_subnet_records_map(snapshot)
        .into_iter()
        .flat_map(|(_, s)| s.membership)
        .map(|v| NodeId::from(PrincipalId::try_from(v).unwrap()))
        .collect();

    // ApiBoundaryNode
    let api_boundary_nodes: HashSet<NodeId> = get_api_boundary_node_records_from_snapshot(snapshot)
        .into_keys()
        .collect();

    let errors: Vec<String> = get_node_records_from_snapshot(snapshot).keys().map(|node_id| {
            let (is_replica, is_api_boundary_node) = (
                replicas.contains(node_id),
                api_boundary_nodes.contains(node_id),
            );

            match (is_replica, is_api_boundary_node) {
                // replica
                (true, false) |

                // api boundary node
                (false, true) |

                // unassigned
                (false, false) => Ok(()),

                // invalid
                _ => Err(format!("invalid assignment for node {node_id}: is_replica = {is_replica}, is_api_boundary_node = {is_api_boundary_node}")),
            }
        }).filter_map(Result::err).collect();

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
    use std::str::FromStr;

    use ic_base_types::{NodeId, PrincipalId, SubnetId};
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, node::v1::NodeRecord,
        subnet::v1::SubnetRecord,
    };
    use ic_registry_keys::{
        make_api_boundary_node_record_key, make_node_record_key, make_subnet_record_key,
    };
    use prost::Message;

    use crate::invariants::common::RegistrySnapshot;

    use super::check_node_assignment_invariants;

    pub(crate) const TEST_PRINCIPAL_ID: &str = "2vxsx-fae";

    #[test]
    fn test_check_node_assignment_invariants() {
        let mut snapshot = RegistrySnapshot::new();

        // Create Node
        let node_id: NodeId = PrincipalId::from_str(TEST_PRINCIPAL_ID)
            .expect("failed to parse principal id")
            .into();

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord::default().encode_to_vec(),      // record
        );

        // Create Subnet
        let subnet_id: SubnetId = PrincipalId::from_str(TEST_PRINCIPAL_ID)
            .expect("failed to parse principal id")
            .into();

        snapshot.insert(
            make_subnet_record_key(subnet_id).into_bytes(), // key
            SubnetRecord::default().encode_to_vec(),        // record
        );

        // Create ApiBoundaryNode
        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );

        assert!(check_node_assignment_invariants(&snapshot).is_ok());
    }

    #[test]
    fn test_check_node_assignment_invariants_conflict() {
        let mut snapshot = RegistrySnapshot::new();

        // Create Node
        let node_id: NodeId = PrincipalId::from_str(TEST_PRINCIPAL_ID)
            .expect("failed to parse principal id")
            .into();

        snapshot.insert(
            make_node_record_key(node_id).into_bytes(), // key
            NodeRecord::default().encode_to_vec(),      // record
        );

        // Create Subnet
        let subnet_id: SubnetId = PrincipalId::from_str(TEST_PRINCIPAL_ID)
            .expect("failed to parse principal id")
            .into();

        let subnet = SubnetRecord {
            membership: vec![node_id.get().into_vec()],
            ..Default::default()
        };

        snapshot.insert(
            make_subnet_record_key(subnet_id).into_bytes(), // key
            subnet.encode_to_vec(),                         // record
        );

        // Create ApiBoundaryNode
        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // key
            ApiBoundaryNodeRecord::default().encode_to_vec(),        // record
        );

        assert!(check_node_assignment_invariants(&snapshot).is_err());
    }
}
