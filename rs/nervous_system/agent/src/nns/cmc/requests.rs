use crate::Request;
use cycles_minting_canister::{
    CreateCanister, CreateCanisterResult, NotifyMintCyclesArg, NotifyMintCyclesResult,
    SetAuthorizedSubnetworkListArgs,
};

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

impl Request for SetAuthorizedSubnetworkListArgs {
    fn method(&self) -> &'static str {
        "set_authorized_subnetwork_list"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = ();
}

impl Request for NotifyMintCyclesArg {
    fn method(&self) -> &'static str {
        "notify_mint_cycles"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = NotifyMintCyclesResult;
}
