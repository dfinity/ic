use std::collections::BTreeSet;

use candid::Principal;
use canister_test::Wasm;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    await_with_timeout, install_canister_on_subnet, nns, sns,
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{add_wasms_to_sns_wasm, install_nns_canisters},
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_sns_governance::pb::v1::{ChunkedCanisterWasm, UpgradeSnsControlledCanister};
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;

const MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 20;
const MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 5 * 60;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

// TODO: Figure out how to best support uploading chunks into the target itself, which has
// SNS Root as the controller but not SNS Governance.
//
// #[tokio::test]
// async fn test_store_same_as_target() {
//     let store_same_as_target = true;
//     run_test(store_same_as_target).await;
// }

#[tokio::test]
async fn test_store_different_from_target() {
    let store_same_as_target = false;
    run_test(store_same_as_target).await;
}

fn very_large_wasm_bytes() -> Vec<u8> {
    let image_classification_canister_wasm_path =
        std::env::var("IMAGE_CLASSIFICATION_CANISTER_WASM_PATH")
            .expect("Please ensure that this Bazel test target correctly specifies env and data.");

    let wasm_path = std::path::PathBuf::from(image_classification_canister_wasm_path);

    std::fs::read(&wasm_path).expect("Failed to read WASM file")
}

fn format_full_hash(hash: &[u8]) -> String {
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

/// Uploads `wasm` into the store canister, one [`CHUNK_SIZE`]-sized chunk at a time.
///
/// Returns the vector of uploaded chunk hashes.
async fn upload_wasm_as_chunks(
    pocket_ic: &PocketIc,
    store_controller_id: Principal,
    store_canister_id: Principal,
    wasm: Wasm,
    num_chunks_expected: usize,
) -> Vec<Vec<u8>> {
    let sender = Some(store_controller_id);

    let mut uploaded_chunk_hashes = Vec::new();

    for chunk in wasm.bytes().chunks(CHUNK_SIZE) {
        let uploaded_chunk_hash = pocket_ic
            .upload_chunk(store_canister_id, sender, chunk.to_vec())
            .await
            .unwrap();

        uploaded_chunk_hashes.push(uploaded_chunk_hash);
    }

    // Smoke test
    {
        let stored_chunk_hashes = pocket_ic
            .stored_chunks(store_canister_id, sender)
            .await
            .unwrap()
            .into_iter()
            .map(|hash| format_full_hash(&hash[..]))
            .collect::<Vec<_>>();

        let stored_chunk_hashes = BTreeSet::from_iter(stored_chunk_hashes.iter());

        let uploaded_chunk_hashes = uploaded_chunk_hashes
            .iter()
            .map(|hash| format_full_hash(&hash[..]))
            .collect::<Vec<_>>();
        let uploaded_chunk_hashes = BTreeSet::from_iter(uploaded_chunk_hashes.iter());

        assert!(uploaded_chunk_hashes.is_subset(&stored_chunk_hashes));
        assert_eq!(uploaded_chunk_hashes.len(), num_chunks_expected);
    }

    uploaded_chunk_hashes
}

async fn run_test(store_same_as_target: bool) {
    // 1. Prepare the world
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Install the NNS canisters.
    {
        let with_mainnet_nns_canisters = false;
        install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, None, vec![]).await;
    }

    // Publish SNS Wasms to SNS-W.
    {
        let with_mainnet_sns_canisters = false;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
            .await
            .unwrap();
    };

    // Install a dapp canister.
    let original_wasm = Wasm::from_bytes(very_large_wasm_bytes());
    let original_wasm_hash = original_wasm.sha256_hash();

    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];

    let target_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(original_wasm.clone()),
        vec![ROOT_CANISTER_ID.into()],
    )
    .await;

    let sns = {
        let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
            .with_dapp_canisters(vec![target_canister_id])
            .build();

        let swap_parameters = create_service_nervous_system
            .swap_parameters
            .clone()
            .unwrap();

        let sns_instance_label = "1";
        let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
            &pocket_ic,
            create_service_nervous_system,
            sns_instance_label,
        )
        .await;

        sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
            .await
            .unwrap();
        sns::swap::smoke_test_participate_and_finalize(
            &pocket_ic,
            sns.swap.canister_id,
            swap_parameters,
        )
        .await;

        sns
    };

    let store_canister_id = if store_same_as_target {
        target_canister_id
    } else {
        install_canister_on_subnet(
            &pocket_ic,
            app_subnet,
            vec![],
            None,
            vec![sns.root.canister_id],
        )
        .await
    };

    let new_wasm = {
        let new_wasm_bytes = modify_wasm_bytes(&original_wasm.bytes(), 42);
        Wasm::from_bytes(&new_wasm_bytes[..])
    };
    let new_wasm_hash = new_wasm.sha256_hash();

    // Smoke test
    assert_ne!(new_wasm_hash, original_wasm_hash);

    // WASM with 15_843_866 bytes (`image-classification.wasm.gz`) is split into 1 MiB chunks.
    let num_chunks_expected = 16;

    let chunk_hashes_list = upload_wasm_as_chunks(
        &pocket_ic,
        sns.root.canister_id.into(),
        store_canister_id.into(),
        new_wasm,
        num_chunks_expected,
    )
    .await;

    // 2. Run code under test.
    sns::governance::propose_to_upgrade_sns_controlled_canister_and_wait(
        &pocket_ic,
        sns.governance.canister_id,
        UpgradeSnsControlledCanister {
            canister_id: Some(target_canister_id.get()),
            new_canister_wasm: vec![],
            canister_upgrade_arg: None,
            mode: Some(CanisterInstallMode::Upgrade as i32),
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                wasm_module_hash: new_wasm_hash.clone().to_vec(),
                store_canister_id: Some(store_canister_id.get()),
                chunk_hashes_list,
            }),
        },
    )
    .await;

    // 3. Inspect the resulting state.
    await_with_timeout(
        &pocket_ic,
        MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS..MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS,
        |pocket_ic| async {
            let status = pocket_ic
                .canister_status(target_canister_id.into(), Some(sns.root.canister_id.into()))
                .await;
            status
                .expect("canister status must be available")
                .module_hash
        },
        &Some(new_wasm_hash.to_vec()),
    )
    .await
    .unwrap();
}
