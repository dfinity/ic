use crate::runtime::Runtime;
use ic_base_types::CanisterId;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, IC_00, InstallCodeArgs,
};

pub async fn install_code<Rt>(
    canister_id: CanisterId,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    Rt::print("[spawn] install_code()");

    let install_code = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id: canister_id.get(),
        wasm_module,
        arg,
        sender_canister_version: None,
    };

    () = Rt::call(IC_00, "install_code", /*cycles=*/ 0, (install_code,)).await?;

    Ok(())
}

pub async fn create_canister<Rt>(
    cycles_for_canister_creation: u64,
) -> Result<CanisterId, (i32, String)>
where
    Rt: Runtime,
{
    Rt::print(format!(
        "[spawn] create_canister(cycles_for_canister_creation={cycles_for_canister_creation})"
    ));

    let result = Rt::call(
        IC_00,
        "create_canister",
        cycles_for_canister_creation,
        (ic_management_canister_types_private::CreateCanisterArgs::default(),),
    )
    .await
    .map(|(record,): (CanisterIdRecord,)| record);

    Rt::print(format!("[spawn] create_canister() = {result:?}"));
    result.map(|r| r.get_canister_id())
}
