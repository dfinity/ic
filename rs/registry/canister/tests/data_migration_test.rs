use common::test_helpers::install_registry_canister_with_payload_builder;
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use pocket_ic::PocketIcBuilder;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

mod common;

#[tokio::test]
async fn ensure_successful_migration_against_mainnet_registry() {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(RegistryAtomicMutateRequest {
        mutations: fetch_all_mainnet_changes(),
        preconditions: vec![],
    });

    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), false).await;
}

async fn fetch_all_mainnet_changes() -> Vec<RegistryMutation> {
    vec![]
}
