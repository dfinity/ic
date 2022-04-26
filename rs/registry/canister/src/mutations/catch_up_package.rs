use crate::common::LOG_PREFIX;
use crate::mutations::common::decode_registry_value;
use crate::registry::{Registry, Version};
use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_registry_keys::make_catch_up_package_contents_key;

impl Registry {
    pub fn get_subnet_catch_up_package(
        &self,
        subnet_id: SubnetId,
        version: Option<Version>,
    ) -> Result<CatchUpPackageContents, String> {
        let cup_contents_key = make_catch_up_package_contents_key(subnet_id);

        match self.get(
            &cup_contents_key.into_bytes(),
            version.unwrap_or_else(|| self.latest_version()),
        ) {
            Some(cup) => Ok(decode_registry_value::<CatchUpPackageContents>(
                cup.value.clone(),
            )),
            None => Err(format!(
                "{}CatchUpPackage not found for subnet: {}",
                LOG_PREFIX, subnet_id
            )),
        }
    }
}
