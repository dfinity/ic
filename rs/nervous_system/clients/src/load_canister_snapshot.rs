use ic_management_canister_types_private::{IC_00, LoadCanisterSnapshotArgs};
use ic_nervous_system_runtime::Runtime;

pub async fn load_canister_snapshot<Rt>(args: LoadCanisterSnapshotArgs) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    Rt::call_with_cleanup(IC_00, "load_canister_snapshot", (args,)).await
}
