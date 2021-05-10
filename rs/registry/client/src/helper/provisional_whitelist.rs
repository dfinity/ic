use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::provisional_whitelist::v1 as pb;
use ic_registry_common::values::deserialize_registry_value;
use ic_registry_keys::make_provisional_whitelist_record_key;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::RegistryVersion;
use std::convert::TryFrom;

/// A trait that allows access to `ProvisionalWhitelist`.
pub trait ProvisionalWhitelistRegistry {
    fn get_provisional_whitelist(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<ProvisionalWhitelist>;
}

impl<T: RegistryClient + ?Sized> ProvisionalWhitelistRegistry for T {
    fn get_provisional_whitelist(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<ProvisionalWhitelist> {
        let bytes = self.get_value(&make_provisional_whitelist_record_key(), version);
        deserialize_registry_value::<pb::ProvisionalWhitelist>(bytes).map(
            |option_pb_provisional_whitelist| {
                option_pb_provisional_whitelist.map(|pb_provisional_whitelist| {
                    ProvisionalWhitelist::try_from(pb_provisional_whitelist).unwrap()
                })
            },
        )
    }
}
