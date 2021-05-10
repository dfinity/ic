use ic_base_types::CanisterInstallMode;
use ic_types::{
    ic00::{CanisterIdRecord, InstallCodeArgs, Method, IC_00},
    CanisterId,
};

use on_wire::IntoWire;

pub async fn install_code<Arg: IntoWire>(
    canister_id: CanisterId,
    wasm_module: Vec<u8>,
    arg: Arg,
) -> Result<(), (Option<i32>, String)> {
    dfn_core::api::print("[spawn] install_code()");
    let install_code = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module,
        arg: arg.into_bytes().unwrap(),
        compute_allocation: None,
        memory_allocation: Some(candid::Nat::from(8 * 1024 * 1024 * 1024u64)),
        query_allocation: None,
    };
    dfn_core::api::call_with_cleanup(
        IC_00,
        &Method::InstallCode.to_string(),
        dfn_candid::candid::<(), (InstallCodeArgs,)>,
        (install_code,),
    )
    .await
}

pub async fn create_canister() -> CanisterId {
    dfn_core::api::print("[spawn] create_canister()");
    let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_cleanup(
        IC_00,
        &Method::CreateCanister.to_string(),
        dfn_candid::candid_one,
        ic_types::ic00::CreateCanisterArgs::default(),
    )
    .await;
    dfn_core::api::print(format!("[spawn] create_canister() = {:?}", result));
    result.unwrap().get_canister_id()
}
