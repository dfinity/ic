use crate::deserialize_registry_value;
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_registry_common_proto::pb::test_protos::v1::TestProto;
use ic_types::RegistryVersion;

/// Provides functionality to get values of type TestProto from the registry.
pub trait TestProtoHelper {
    fn get_test_proto(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientResult<TestProto>;
}

impl<R: RegistryClient> TestProtoHelper for R {
    fn get_test_proto(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientResult<TestProto> {
        deserialize_registry_value::<TestProto>(self.get_value(key, version))
    }
}
