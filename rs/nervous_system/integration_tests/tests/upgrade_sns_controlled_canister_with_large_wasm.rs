
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_nervous_system_integration_tests::{create_service_nervous_system_builder::CreateServiceNervousSystemBuilder, pocket_ic_helpers::{add_wasms_to_sns_wasm, install_nns_canisters}};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_test_utils::common::modify_wasm_bytes;
use pocket_ic::{management_canister::{CanisterInstallMode, CanisterInstallModeUpgradeInner}, PocketIcBuilder};
use pocket_ic::management_canister::CanisterSettings;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister_on_subnet;
use canister_test::Wasm;
use ic_base_types::SubnetId;

#[tokio::test]
async fn test() {
    // 1. Prepare the world

    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];

    // Install a dapp canister.
    let developer = PrincipalId::new_user_test_id(42);

    let original_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec());
    let original_wasm_hash = original_wasm.sha256_hash();

    let target_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(original_wasm.clone()),
        vec![developer],
    ).await;

    // Install the (mainnet) NNS canisters.
    {
        let with_mainnet_nns_canisters = false;
        install_nns_canisters(&pocket_ic, vec![], with_mainnet_nns_canisters, None, vec![]).await;
    }

    // Publish (mainnet) SNS Wasms to SNS-W.
    {
        let with_mainnet_sns_canisters = false;
        let deployed_sns_starting_info =
            add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
                .await
                .unwrap();
    };

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_governance_parameters_neuron_minimum_dissolve_delay_to_vote(ONE_MONTH_SECONDS * 6)
        .with_one_developer_neuron(
            PrincipalId::new_user_test_id(830947),
            ONE_MONTH_SECONDS * 6,
            756575,
            0,
        )
        .with_dapp_canisters(vec![target_canister_id.clone()])
        .build();

    // TODO: Make SNS Root the target canister's only controller.

    // let sns_instance_label = "1";
    // let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
    //     &pocket_ic,
    //     create_service_nervous_system,
    //     sns_instance_label,
    // )
    // .await;

    // TODO: Use SNS proposal to perform the upgrade using chunked Wasm.
    let store_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        None,
        vec![developer],
    ).await;

    // TODO: Make the new WASM bigger than 2 MiB so that it does not fit into an ingress message.
    let new_wasm = modify_wasm_bytes(&original_wasm.bytes(), 123);
    let new_wasm_hash = new_wasm.sha256_hash();

    let chunk_hashes_list = {
        pocket_ic.upload_chunk(store_canister_id.into(), Some(developer.into()), new_wasm).await;
        let chunk_hashes_list = pocket_ic.stored_chunks(store_canister_id.into(), Some(developer.into())).await.unwrap();
        assert_eq!(chunk_hashes_list[0], new_wasm_hash);
        chunk_hashes_list
    };

    // Finally, trigger the chunked upgrade
    pocket_ic.install_chunked_canister(
        target_canister_id.into(),
        Some(developer.into()),
        CanisterInstallMode::Upgrade(Some(CanisterInstallModeUpgradeInner {
            wasm_memory_persistence: None,
            skip_pre_upgrade: Some(false),
        })),
        store_canister_id.into(),
        chunk_hashes_list,
        new_wasm_hash.to_vec(),
        vec![],
    ).await;

    panic!("hello");
}
