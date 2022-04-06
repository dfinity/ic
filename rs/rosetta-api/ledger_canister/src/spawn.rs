use dfn_core::api::Funds;
use ic_base_types::CanisterId;
use ic_ic00_types::{CanisterIdRecord, CanisterInstallMode, InstallCodeArgs, Method, IC_00};

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

pub async fn create_canister(cycles_for_canister_creation: u64) -> CanisterId {
    dfn_core::api::print(format!(
        "[spawn] create_canister(cycles_for_canister_creation={})",
        cycles_for_canister_creation
    ));
    // dfn_core::api::call_with_funds_and_cleanup()
    let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds_and_cleanup(
        IC_00,
        &Method::CreateCanister.to_string(),
        dfn_candid::candid_one,
        ic_ic00_types::CreateCanisterArgs::default(),
        Funds::new(cycles_for_canister_creation),
    )
    .await;
    dfn_core::api::print(format!("[spawn] create_canister() = {:?}", result));
    result.unwrap().get_canister_id()
}
