use crate::Request;
use candid::Principal;
use pocket_ic::nonblocking::PocketIc;
use thiserror::Error;

use crate::CallCanisters;

/// A wrapper around PocketIc that specifies a sender for the requests.
/// The name is an analogy for `ic_agent::Agent`, since each `ic_agent::Agent` specifies a sender.
pub struct PocketIcAgent<'a> {
    pub pocket_ic: &'a PocketIc,
    pub sender: Principal,
}

impl<'a> PocketIcAgent<'a> {
    pub fn new(pocket_ic: &'a PocketIc, sender: impl Into<Principal>) -> Self {
        let sender = sender.into();
        Self { pocket_ic, sender }
    }
}

#[derive(Error, Debug)]
pub enum PocketIcCallError {
    #[error("pocket_ic error: {0}")]
    PocketIc(pocket_ic::RejectResponse),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for PocketIc {}
impl crate::sealed::Sealed for PocketIcAgent<'_> {}

impl CallCanisters for PocketIcAgent<'_> {
    type Error = PocketIcCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();
        let request_bytes = request.payload().map_err(PocketIcCallError::CandidEncode)?;
        let response = if request.update() {
            self.pocket_ic
                .update_call(canister_id, self.sender, request.method(), request_bytes)
                .await
        } else {
            self.pocket_ic
                .query_call(canister_id, self.sender, request.method(), request_bytes)
                .await
        }
        .map_err(PocketIcCallError::PocketIc)?;

        candid::decode_one(response.as_slice()).map_err(PocketIcCallError::CandidDecode)
    }
}

impl CallCanisters for PocketIc {
    type Error = PocketIcCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        PocketIcAgent::new(self, Principal::anonymous())
            .call(canister_id, request)
            .await
    }
}
