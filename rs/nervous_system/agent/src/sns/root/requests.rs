use crate::Request;
use ic_sns_root::{
    pb::v1::{ListSnsCanistersRequest, ListSnsCanistersResponse},
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
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
