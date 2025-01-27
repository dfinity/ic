use crate::pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister};
use ic_nervous_system_clients::Request;

impl Request for GetSubnetForCanisterRequest {
    type Response = Result<SubnetForCanister, String>;
    const METHOD: &'static str = "get_subnet_for_canister";
    const UPDATE: bool = false;
}
