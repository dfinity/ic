use crate::Request;
use registry_canister::pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister};

impl Request for GetSubnetForCanisterRequest {
    fn method(&self) -> &'static str {
        "get_subnet_for_canister"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Result<SubnetForCanister, String>;
}
