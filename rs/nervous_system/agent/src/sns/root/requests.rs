use crate::Request;
use ic_base_types::CanisterId;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
};
use ic_sns_root::{
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
    pb::v1::{ListSnsCanistersRequest, ListSnsCanistersResponse},
};

impl Request for GetSnsCanistersSummaryRequest {
    fn method(&self) -> &'static str {
        "get_sns_canisters_summary"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = GetSnsCanistersSummaryResponse;
}

impl Request for ListSnsCanistersRequest {
    fn method(&self) -> &'static str {
        "list_sns_canisters"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ListSnsCanistersResponse;
}

// @rvem: Canister query 'canister_status' accepts 'CanisterIdRecord' as input.
// However, implementing 'Request' for 'CanisterIdRecord' may be a bad idea since
// other canisters may expose endpoints that accept 'CanisterIdRecord' as input too.
// So we're providing a newtype struct and implementing 'Request' for it.
pub(crate) struct GetSnsControlledCanisterStatus {
    pub canister_id: CanisterId,
}

impl Request for GetSnsControlledCanisterStatus {
    fn method(&self) -> &'static str {
        "canister_status"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(CanisterIdRecord {
            canister_id: self.canister_id,
        })
    }

    type Response = CanisterStatusResult;
}
