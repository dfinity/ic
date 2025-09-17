// DO NOT MERGE
use ic_base_types::PrincipalId;
use subnet_rental_canister::RentalConditionId;

/// A proposal payload for a subnet rental request,
/// used to deserialize `ExecuteNnsFunction.payload`,
/// where `ExecuteNnsFunction.nns_function == NnsFunction::SubnetRentalRequest as i32`.
/// Also used to serialize the subnet rental request payload in `ic-admin`.
#[derive(Clone, Debug, candid::CandidType, candid::Deserialize)]
pub struct SubnetRentalRequest {
    pub user: PrincipalId,
    pub rental_condition_id: RentalConditionId,
}
