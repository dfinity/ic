use candid::{Encode, Principal};
use ic_crypto_sha2::Sha256;
use ic_nns_test_utils::common::modify_wasm_bytes;
use ic_rate_limit_canister_integration_tests::pocket_ic_helpers::{
    canister_call, get_installed_wasm_hash, install_rate_limit_canister_on_ii_subnet,
    setup_subnets_and_registry_canister,
};
use rate_limits_api::{AddConfigResponse, GetConfigResponse, InitArg, InputConfig, Version};

const AUTHORIZED_PRINCIPAL: &str =
    "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";

#[tokio::test]
async fn test() {
    // Setup:
    // - Two system subnets: NNS and II
    // - Registry canister on NNS subnet
    // - Rate-limit canister on II subnet
    let authorized_principal = Principal::from_text(AUTHORIZED_PRINCIPAL).unwrap();
    let initial_payload = InitArg {
        authorized_principal: Some(authorized_principal),
        registry_polling_period_secs: 1,
    };
    let pocket_ic = setup_subnets_and_registry_canister().await;
    let (canister_id, wasm) =
        install_rate_limit_canister_on_ii_subnet(&pocket_ic, initial_payload.clone()).await;

    // Read config by non-authorized principal
    let input_version = Encode!(&None::<Version>).unwrap();

    let response: GetConfigResponse = canister_call(
        &pocket_ic,
        "get_config",
        canister_id,
        Principal::anonymous(),
        input_version,
    )
    .await
    .unwrap();

    let config = response.unwrap();

    assert_eq!(config.version, 1);

    // Try add config using non-authorized principal as sender, assert failure
    let input_config = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![],
    })
    .unwrap();

    let response: AddConfigResponse = canister_call(
        &pocket_ic,
        "add_config",
        canister_id,
        Principal::anonymous(),
        input_config.clone(),
    )
    .await
    .unwrap();

    assert!(response.unwrap_err().contains("Unauthorized"));

    // Try add config using authorized principal as sender, assert success
    let response: AddConfigResponse = canister_call(
        &pocket_ic,
        "add_config",
        canister_id,
        authorized_principal,
        input_config,
    )
    .await
    .unwrap();

    assert!(response.is_ok());

    // Read config by non-authorized principal
    let input_version = Encode!(&None::<Version>).unwrap();

    let response: GetConfigResponse = canister_call(
        &pocket_ic,
        "get_config",
        canister_id,
        Principal::anonymous(),
        input_version,
    )
    .await
    .unwrap();

    let config = response.unwrap();

    assert_eq!(config.version, 2);

    // Upgrade canister with a new wasm
    let current_wasm_hash = get_installed_wasm_hash(&pocket_ic, canister_id).await;
    let new_wasm = modify_wasm_bytes(&wasm.clone().bytes(), 42);
    let new_wasm_hash = Sha256::hash(&new_wasm.clone());

    assert_ne!(current_wasm_hash, new_wasm_hash);

    pocket_ic
        .upgrade_canister(
            canister_id,
            new_wasm,
            Encode!(&initial_payload).unwrap(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        get_installed_wasm_hash(&pocket_ic, canister_id).await,
        new_wasm_hash,
    );
}
