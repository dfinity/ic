use crate::Request;
use cycles_minting_canister::{CreateCanister, CreateCanisterResult};

impl Request for CreateCanister {
    fn method(&self) -> &'static str {
        "create_canister"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = CreateCanisterResult;
}
