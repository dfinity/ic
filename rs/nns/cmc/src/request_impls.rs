use crate::{CreateCanister, CreateCanisterResult};
use ic_nervous_system_clients::Request;

impl Request for CreateCanister {
    type Response = CreateCanisterResult;
    const METHOD: &'static str = "create_canister";
    const UPDATE: bool = true;
}
