use crate::{common::LOG_PREFIX, mutations::common::decode_registry_value, registry::Registry};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::pb::v1::RegistryValue;
use std::convert::TryFrom;

pub fn find_subnet_for_node(
    registry: &Registry,
    node_id: NodeId,
    subnet_list_record: &SubnetListRecord,
) -> Option<SubnetId> {
    subnet_list_record
        .subnets
        .iter()
        .find(|subnet_id| -> bool {
            let subnet_id = SubnetId::new(PrincipalId::try_from(*subnet_id).unwrap());
            let subnet_record = get_subnet_record(registry, subnet_id);
            subnet_record.membership.contains(&node_id.get().to_vec())
        })
        .map(|subnet_vector| SubnetId::new(PrincipalId::try_from(subnet_vector).unwrap()))
}

fn get_subnet_record(registry: &Registry, subnet_id: SubnetId) -> SubnetRecord {
    let subnet_key = make_subnet_record_key(subnet_id);
    let RegistryValue {
        value: subnet_record_vec,
        version: _,
        deletion_marker: _,
    } = registry
        .get(subnet_key.as_bytes(), registry.latest_version())
        .map_or(
            Err(format!(
                "{}do_remove_node: Subnet not found in the registry, aborting node removal.",
                LOG_PREFIX
            )),
            Ok,
        )
        .unwrap();

    decode_registry_value::<SubnetRecord>(subnet_record_vec.to_vec())
}

pub fn get_subnet_list_record(registry: &Registry) -> SubnetListRecord {
    let RegistryValue {
        value: subnet_list_record_vec,
        version: _,
        deletion_marker: _,
    } = registry
        .get(
            make_subnet_list_record_key().as_bytes(),
            registry.latest_version(),
        )
        .map_or(
            Err(format!(
                "{}do_remove_node: Subnet List not found in the registry, aborting node removal.",
                LOG_PREFIX
            )),
            Ok,
        )
        .unwrap();

    decode_registry_value::<SubnetListRecord>(subnet_list_record_vec.to_vec())
}

pub fn get_node_operator_id_for_node(
    registry: &Registry,
    node_id: NodeId,
) -> Result<PrincipalId, String> {
    let node_key = make_node_record_key(node_id);
    registry
        .get(node_key.as_bytes(), registry.latest_version())
        .map_or(
            Err(format!("Node Id {:} not found in the registry", node_id)),
            |result| {
                PrincipalId::try_from(
                    decode_registry_value::<NodeRecord>(result.value.to_vec()).node_operator_id,
                )
                .map_err(|_| {
                    format!(
                        "Could not decode node_record's node_operator_id for Node Id {}",
                        node_id
                    )
                })
            },
        )
}

pub fn get_node_operator_record(
    registry: &Registry,
    node_operator_id: PrincipalId,
) -> Result<NodeOperatorRecord, String> {
    let node_operator_key = make_node_operator_record_key(node_operator_id);
    registry
        .get(node_operator_key.as_bytes(), registry.latest_version())
        .map_or(
            Err(format!(
                "Node Operator Id {:} not found in the registry.",
                node_operator_key
            )),
            |result| {
                let decoded = decode_registry_value::<NodeOperatorRecord>(result.value.to_vec());
                Ok(decoded)
            },
        )
}
