use crate::Request;
use ic_registry_canister_api::{Chunk, GetChunkRequest};
use registry_canister::{
    mutations::do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload,
    pb::v1::{GetSubnetForCanisterRequest, SubnetForCanister},
};

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

impl Request for GetChunkRequest {
    fn method(&self) -> &'static str {
        "get_chunk"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Result<Chunk, String>;
}

impl Request for SwapNodeInSubnetDirectlyPayload {
    fn method(&self) -> &'static str {
        "swap_node_in_subnet_directly"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ();
}
