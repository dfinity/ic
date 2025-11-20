use crate::canister_id_record::CanisterIdRecord;
use ic_management_canister_types_private::IC_00;
use ic_nervous_system_runtime::Runtime;

pub async fn stop_canister<Rt>(canister_id_record: CanisterIdRecord) -> Result<(), (i32, String)>
where
    Rt: Runtime,
{
    Rt::call_with_cleanup(IC_00, "stop_canister", (canister_id_record,)).await
}
