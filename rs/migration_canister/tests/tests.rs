use candid::{Encode, Principal};
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterSettings;
use ic_nns_test_utils::common::build_registry_wasm;
use pocket_ic::PocketIcBuilder;
use registry_canister::init::RegistryCanisterInitPayload;
use tempfile::TempDir;

pub const REGISTRY_CANISTER_ID: CanisterId = CanisterId::from_u64(0);

#[tokio::test]
async fn test() {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let controller = Principal::anonymous();

    let registry_wasm = build_registry_wasm();
    pic.create_canister_with_id(
        Some(controller),
        Some(CanisterSettings {
            controllers: Some(vec![controller]),
            ..Default::default()
        }),
        REGISTRY_CANISTER_ID.into(),
    )
    .await
    .unwrap();
    pic.install_canister(
        REGISTRY_CANISTER_ID.into(),
        registry_wasm.bytes(),
        Encode!(&RegistryCanisterInitPayload::default()).unwrap(),
        Some(controller),
    )
    .await;
}
