use candid::Principal;
use ic_cdk::management_canister::{
    canister_info, create_canister_with_extra_cycles, install_code, uninstall_code,
    update_settings, CanisterInfoArgs, CanisterInfoResult,
    CanisterInstallMode::{Install, Reinstall, Upgrade},
    CanisterSettings, CreateCanisterArgs, InstallCodeArgs, UninstallCodeArgs, UpdateSettingsArgs,
};

#[ic_cdk::update]
async fn info(canister_id: Principal) -> CanisterInfoResult {
    let request = CanisterInfoArgs {
        canister_id,
        num_requested_changes: Some(20),
    };
    canister_info(&request).await.unwrap()
}

#[ic_cdk::update]
async fn canister_lifecycle() -> Principal {
    let canister_id =
        create_canister_with_extra_cycles(&CreateCanisterArgs::default(), 1_000_000_000_000)
            .await
            .unwrap()
            .canister_id;
    install_code(&InstallCodeArgs {
        mode: Install,
        arg: vec![],
        wasm_module: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        canister_id,
    })
    .await
    .unwrap();
    uninstall_code(&UninstallCodeArgs { canister_id })
        .await
        .unwrap();
    install_code(&InstallCodeArgs {
        mode: Install,
        arg: vec![],
        wasm_module: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        canister_id,
    })
    .await
    .unwrap();
    install_code(&InstallCodeArgs {
        mode: Reinstall,
        arg: vec![],
        wasm_module: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        canister_id,
    })
    .await
    .unwrap();
    install_code(&InstallCodeArgs {
        mode: Upgrade(None),
        arg: vec![],
        wasm_module: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        canister_id,
    })
    .await
    .unwrap();
    update_settings(&UpdateSettingsArgs {
        settings: CanisterSettings {
            controllers: Some(vec![
                ic_cdk::api::canister_self(),
                canister_id,
                Principal::anonymous(),
            ]),
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
            log_visibility: None,
            wasm_memory_limit: None,
            wasm_memory_threshold: None,
            environment_variables: None,
        },
        canister_id,
    })
    .await
    .unwrap();
    canister_id
}

fn main() {}
