use ic_base_types::PrincipalId;
use std::str::FromStr;

/// A proposal payload for a subnet rental request,
/// used to deserialize `ExecuteNnsFunction.payload`,
/// where `ExecuteNnsFunction.nns_function == NnsFunction::SubnetRentalRequest as i32`.
/// Also used to serialize the subnet rental request payload in `ic-admin`.
#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub struct SubnetRentalRequest {
    pub user: PrincipalId,
    pub rental_condition_id: RentalConditionId,
}

// The following two Subnet Rental Canister types are copied
// from the Subnet Rental Canister's repository and used
// to serialize the payload passed to Subnet Rental Canister's
// method `execute_rental_request_proposal`.
#[derive(Copy, Clone, Debug, candid::CandidType, candid::Deserialize, serde::Serialize)]
pub enum RentalConditionId {
    App13CH,
}

impl FromStr for RentalConditionId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "App13CH" => Ok(Self::App13CH),
            other => Err(format!("Unknown rental condition ID {}", other)),
        }
    }
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct SubnetRentalProposalPayload {
    pub user: PrincipalId,
    pub rental_condition_id: RentalConditionId,
    pub proposal_id: u64,
    pub proposal_creation_time_seconds: u64,
}
