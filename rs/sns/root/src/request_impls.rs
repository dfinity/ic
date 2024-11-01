use crate::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_nervous_system_clients::Request;

impl Request for GetSnsCanistersSummaryRequest {
    type Response = GetSnsCanistersSummaryResponse;
    const METHOD: &'static str = "get_sns_canisters_summary";
    const UPDATE: bool = true;
}
