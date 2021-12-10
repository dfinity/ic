use std::convert::TryFrom;

use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::{
    replica_version::v1::BlessedReplicaVersions, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::make_blessed_replica_version_key;
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

use crate::registry::Registry;

/// Wraps around Message::encode and panics on error.
pub(crate) fn encode_or_panic<T: Message>(msg: &T) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    msg.encode(&mut buf).unwrap();
    buf
}

pub fn decode_registry_value<T: Message + Default>(registry_value: Vec<u8>) -> T {
    T::decode(registry_value.as_slice()).unwrap()
}

pub fn get_subnet_ids_from_subnet_list(subnet_list: SubnetListRecord) -> Vec<SubnetId> {
    subnet_list
        .subnets
        .iter()
        .map(|subnet_id_vec| SubnetId::new(PrincipalId::try_from(subnet_id_vec).unwrap()))
        .collect()
}

fn blessed_versions_to_string(blessed: &BlessedReplicaVersions) -> String {
    format!("[{}]", blessed.blessed_version_ids.join(", "))
}

pub(crate) fn check_replica_version_is_blessed(registry: &Registry, replica_version_id: &str) {
    let blessed_replica_key = make_blessed_replica_version_key();
    // Get the current list of blessed replica versions
    if let Some(RegistryValue {
        value: blessed_list_vec,
        version,
        deletion_marker: _,
    }) = registry.get(blessed_replica_key.as_bytes(), registry.latest_version())
    {
        let blessed_list =
            decode_registry_value::<BlessedReplicaVersions>(blessed_list_vec.clone());
        // Verify that the new one is blessed
        assert!(
            blessed_list
                .blessed_version_ids
                .iter()
                .any(|v| v == replica_version_id),
            "Attempt to change the replica version to '{}' is rejected, \
            because that version is NOT blessed. The list of blessed replica versions, at \
            version {}, is: {}.",
            replica_version_id,
            version,
            blessed_versions_to_string(&blessed_list)
        );
    } else {
        panic!(
            "Error while fetching the list of blessed replica versions record: {}",
            replica_version_id
        )
    }
}
