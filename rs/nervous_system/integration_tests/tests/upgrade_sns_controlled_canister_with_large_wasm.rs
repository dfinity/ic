use canister_test::Wasm;
use ic_base_types::PrincipalId;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    await_with_timeout, install_canister_on_subnet, nns, sns,
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{add_wasms_to_sns_wasm, install_nns_canisters},
};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nervous_system_root::change_canister::ChunkedCanisterWasm;
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_sns_swap::pb::v1::Lifecycle;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_wasm;
use pocket_ic::PocketIcBuilder;

const MIN_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 20;
const MAX_INSTALL_CHUNKED_CODE_TIME_SECONDS: u64 = 5 * 60;

/// This many bytes would not fit into a single cross-subnet ICP message, so including this many
/// extra bytes into a WASM module would require splitting the module into multiple chunks.
const LARGE_WASM_MIN_BYTES: usize = 2 * 1024 * 1024 + 1;

#[tokio::test]
async fn test_store_same_as_target() {
    let store_same_as_target = true;
    run_test(store_same_as_target).await;
}

#[tokio::test]
async fn test_store_different_from_target() {
    let store_same_as_target = false;
    run_test(store_same_as_target).await;
}

mod interim_sns_helpers {
    use super::*;

    use candid::{Decode, Encode};
    use pocket_ic::nonblocking::PocketIc;
    use pocket_ic::WasmResult;

    /// Interim test function for calling Root.change_canister.
    ///
    /// This function is not in src/pocket_ic_helpers.rs because it's going to be replaced with
    /// a proposal with the same effect. It should not be used in any other tests.
    pub async fn change_canister(
        pocket_ic: &PocketIc,
        canister_id: PrincipalId,
        sender: PrincipalId,
        request: ChangeCanisterRequest,
    ) {
        let result = pocket_ic
            .update_call(
                canister_id.into(),
                sender.into(),
                "change_canister",
                Encode!(&request).unwrap(),
            )
            .await
            .unwrap();
        let result = match result {
            WasmResult::Reply(result) => result,
            WasmResult::Reject(s) => panic!("Call to change_canister failed: {:#?}", s),
        };
        Decode!(&result, ()).unwrap()
    }
}

/// Produces a valid WASM module based on `wasm`, extending it with so much junk bytes that it
/// no longer fits into ICP message limits.
///
/// See also [`LARGE_WASM_MIN_BYTES`].
fn oversize_wasm(wasm: Wasm) -> Wasm {
    let modify_with = vec![0_u8; LARGE_WASM_MIN_BYTES];
    let mut wasm_module = ic_wasm::utils::parse_wasm(&wasm.bytes(), false).unwrap();
    ic_wasm::metadata::add_metadata(
        &mut wasm_module,
        ic_wasm::metadata::Kind::Public,
        "aux",
        modify_with,
    );
    let modified_bytes = wasm_module.emit_wasm();
    Wasm::from_bytes(&modified_bytes[..])
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
    let original_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec());
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

    let new_wasm = oversize_wasm(original_wasm);
    let new_wasm_hash = new_wasm.sha256_hash();

    // Smoke test
    assert_ne!(new_wasm_hash, original_wasm_hash);

    let chunk_hashes_list = {
        pocket_ic
            .upload_chunk(
                store_canister_id.into(),
                // This is a simplification; for now, we assume the Root itself decides to upload
                // some WASM chunks, but eventually this should be triggered via proposal.
                Some(sns.root.canister_id.into()),
                new_wasm.bytes(),
            )
            .await
            .unwrap();
        let chunk_hashes_list = pocket_ic
            .stored_chunks(store_canister_id.into(), Some(sns.root.canister_id.into()))
            .await
            .unwrap();
        assert_eq!(chunk_hashes_list.len(), 2);
        chunk_hashes_list
    };

    // 2. Run code under test.
    interim_sns_helpers::change_canister(
        &pocket_ic,
        sns.root.canister_id,
        sns.governance.canister_id,
        ChangeCanisterRequest {
            stop_before_installing: true,
            mode: CanisterInstallMode::Upgrade,
            canister_id: target_canister_id,
            // This is the old field being generalized.
            wasm_module: vec![],
            // This is the new field we want to test.
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                wasm_module_hash: new_wasm_hash.clone().to_vec(),
                store_canister_id,
                chunk_hashes_list,
            }),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
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
