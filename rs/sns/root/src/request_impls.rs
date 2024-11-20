use crate::{
    pb::v1::{ListSnsCanistersRequest, ListSnsCanistersResponse},
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
};
use ic_nervous_system_clients::Request;

impl Request for GetSnsCanistersSummaryRequest {
    type Response = GetSnsCanistersSummaryResponse;
    const METHOD: &'static str = "get_sns_canisters_summary";
    const UPDATE: bool = true;
}

impl Request for ListSnsCanistersRequest {
    type Response = ListSnsCanistersResponse;
    const METHOD: &'static str = "list_sns_canisters";
    const UPDATE: bool = false;
}
