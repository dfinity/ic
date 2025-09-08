use std::collections::BTreeMap;

use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::registry::crypto::v1::ChainKeyEnabledSubnetList;
use ic_registry_keys::{
    CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX, get_master_public_key_id_from_signing_subnet_list_key,
};
use ic_types::{
    RegistryVersion, SubnetId, registry::RegistryClientError, subnet_id_try_from_protobuf,
};

use crate::deserialize_registry_value;

/// A trait that exposes which subnets are enabled to sign for each Chain key.
pub trait ChainKeysRegistry {
    /// Get a map from Master public key ID -> list of subnets enabled to use the
    /// key. Chain keys which are not enabled on any subnet are not included in the
    /// result.
    fn get_chain_key_enabled_subnets(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<MasterPublicKeyId, Vec<SubnetId>>>;
}

impl<T: RegistryClient + ?Sized> ChainKeysRegistry for T {
    fn get_chain_key_enabled_subnets(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<MasterPublicKeyId, Vec<SubnetId>>> {
        let all_key_id_keys =
            self.get_key_family(CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX, version)?;
        let mut result = BTreeMap::new();
        for registry_key in all_key_id_keys {
            let bytes = self.get_value(&registry_key, version);
            let subnets_proto =
                deserialize_registry_value::<ChainKeyEnabledSubnetList>(bytes)?.unwrap_or_default();
            let mut subnets = vec![];
            for subnet_proto in subnets_proto.subnets.into_iter() {
                subnets.push(subnet_id_try_from_protobuf(subnet_proto).map_err(|err| {
                    RegistryClientError::DecodeError {
                        error: err.to_string(),
                    }
                })?);
            }
            if !subnets.is_empty() {
                let key_id = get_master_public_key_id_from_signing_subnet_list_key(&registry_key)?;
                result.insert(key_id, subnets);
            }
        }
        Ok(Some(result))
    }
}
