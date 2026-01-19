use ic_management_canister_types_private::{
    CanisterSnapshotResponse, IC_00, TakeCanisterSnapshotArgs,
};
use ic_nervous_system_runtime::Runtime;

pub async fn take_canister_snapshot<Rt>(
    args: TakeCanisterSnapshotArgs,
) -> Result<CanisterSnapshotResponse, (i32, String)>
where
    Rt: Runtime,
{
    let (res,) = Rt::call_with_cleanup(IC_00, "take_canister_snapshot", (args,)).await?;
    Ok(res)
}
