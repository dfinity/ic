use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use registry_canister::init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder};
use test_registry_builder::builder::CompliantRegistryMutations;

pub mod test_helpers;

pub trait IntoInitPayloadBuilder {
    fn into_builder(&self) -> RegistryCanisterInitPayloadBuilder;
}
pub trait IntoInitPayload {
    fn into_payload(&self) -> RegistryCanisterInitPayload;
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

impl IntoInitPayloadBuilder for CompliantRegistryMutations {
    fn into_builder(&self) -> RegistryCanisterInitPayloadBuilder {
        build_payload_builder_from_mutations(&self)
    }
}

impl IntoInitPayload for CompliantRegistryMutations {
    fn into_payload(&self) -> RegistryCanisterInitPayload {
        build_payload_builder_from_mutations(&self).build()
    }
}
