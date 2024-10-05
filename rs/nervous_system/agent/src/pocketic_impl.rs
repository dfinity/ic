use candid::Principal;
use ic_nervous_system_clients::Request;
use pocket_ic::PocketIc;
use thiserror::Error;

use crate::CallCanisters;

#[derive(Error, Debug)]
pub enum PocketIcCallError {
    #[error("pocket_ic error: {0}")]
    PocketIc(pocket_ic::UserError),
    #[error("canister rejected the request: {0}")]
    Reject(String),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for PocketIc {}

impl CallCanisters for PocketIc {
    type Error = PocketIcCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();
        let request_bytes =
            candid::encode_one(&request).map_err(PocketIcCallError::CandidEncode)?;
        let response = if R::UPDATE {
            self.update_call(
                canister_id,
                Principal::anonymous(),
                R::METHOD,
                request_bytes,
            )
        } else {
            self.query_call(
                canister_id,
                Principal::anonymous(),
                R::METHOD,
                request_bytes,
            )
        }
        .map_err(PocketIcCallError::PocketIc)?;

        match response {
            pocket_ic::WasmResult::Reply(reply) => {
                let response = candid::decode_one(reply.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?;
                Ok(response)
            }
            pocket_ic::WasmResult::Reject(reject) => Err(PocketIcCallError::Reject(reject)),
        }
    }
}
