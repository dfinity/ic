// Not all tests have to use these functions
#![allow(dead_code)]
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use registry_canister::init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder};
use test_registry_builder::builder::CompliantRegistryMutations;

pub mod test_helpers;

pub trait GetInitPayloadBuilder {
    fn get_builder(&self) -> RegistryCanisterInitPayloadBuilder;
}
pub trait GetInitPayload {
    fn get_payload(&self) -> RegistryCanisterInitPayload;
}

fn build_payload_builder_from_mutations(
    mutations: &CompliantRegistryMutations,
) -> RegistryCanisterInitPayloadBuilder {
    let mut builder = RegistryCanisterInitPayloadBuilder::new();

    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations: mutations.mutations(),
        preconditions: vec![],
    });

    builder
}

impl GetInitPayloadBuilder for CompliantRegistryMutations {
    fn get_builder(&self) -> RegistryCanisterInitPayloadBuilder {
        build_payload_builder_from_mutations(self)
    }
}

impl GetInitPayload for CompliantRegistryMutations {
    fn get_payload(&self) -> RegistryCanisterInitPayload {
        build_payload_builder_from_mutations(self).build()
    }
}
