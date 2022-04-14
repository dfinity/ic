use std::collections::BTreeMap;

use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::crypto::v1::EcdsaSigningSubnetList;
use ic_registry_keys::ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX;
use ic_types::{
    registry::RegistryClientError, subnet_id_try_from_protobuf, RegistryVersion, SubnetId,
};

use crate::deserialize_registry_value;

/// A trait that exposes which subnets are responsible for each ECDSA key.
pub trait EcdsaKeysRegistry {
    fn get_ecdsa_keys(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<String, Vec<SubnetId>>>;
}

impl<T: RegistryClient + ?Sized> EcdsaKeysRegistry for T {
    fn get_ecdsa_keys(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<String, Vec<SubnetId>>> {
        let all_key_id_keys = self.get_key_family(ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, version)?;
        let mut result = BTreeMap::new();
        for registry_key in all_key_id_keys {
            let bytes = self.get_value(&registry_key, version);
            let subnets_proto =
                deserialize_registry_value::<EcdsaSigningSubnetList>(bytes)?.unwrap_or_default();
            let mut subnets = vec![];
            for subnet_proto in subnets_proto.subnets.into_iter() {
                subnets.push(subnet_id_try_from_protobuf(subnet_proto)?);
            }
            let key_id = registry_key
                .strip_prefix(ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX)
                .ok_or_else(|| RegistryClientError::DecodeError {
                    error: format!(
                        "ECDSA Signing Subnet List key id {} does not start with prefix {}",
                        registry_key, ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX
                    ),
                })?;
            result.insert(key_id.to_string(), subnets);
        }
        Ok(Some(result))
    }
}
