use std::collections::BTreeMap;

use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_management_canister_types_private::EcdsaKeyId;
use ic_protobuf::registry::crypto::v1::EcdsaSigningSubnetList;
use ic_registry_keys::{
    ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, get_ecdsa_key_id_from_signing_subnet_list_key,
};
use ic_types::{
    RegistryVersion, SubnetId, registry::RegistryClientError, subnet_id_try_from_protobuf,
};

use crate::deserialize_registry_value;

/// A trait that exposes which subnets are enabled to sign for each ECDSA key.
pub trait EcdsaKeysRegistry {
    /// Get a map from ECDSA key ID -> list of subnets enabled to sign with the
    /// key.  ECDSA keys which have no signing subnets are not included in the
    /// result.
    fn get_ecdsa_signing_subnets(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<EcdsaKeyId, Vec<SubnetId>>>;
}

impl<T: RegistryClient + ?Sized> EcdsaKeysRegistry for T {
    fn get_ecdsa_signing_subnets(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BTreeMap<EcdsaKeyId, Vec<SubnetId>>> {
        let all_key_id_keys = self.get_key_family(ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, version)?;
        let mut result = BTreeMap::new();
        for registry_key in all_key_id_keys {
            let bytes = self.get_value(&registry_key, version);
            let subnets_proto =
                deserialize_registry_value::<EcdsaSigningSubnetList>(bytes)?.unwrap_or_default();
            let mut subnets = vec![];
            for subnet_proto in subnets_proto.subnets.into_iter() {
                subnets.push(subnet_id_try_from_protobuf(subnet_proto).map_err(|err| {
                    RegistryClientError::DecodeError {
                        error: err.to_string(),
                    }
                })?);
            }
            let key_id = get_ecdsa_key_id_from_signing_subnet_list_key(&registry_key)?;
            if !subnets.is_empty() {
                result.insert(key_id, subnets);
            }
        }
        Ok(Some(result))
    }
}
