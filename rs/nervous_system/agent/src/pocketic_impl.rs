use crate::Request;
use crate::{CallCanisters, CanisterInfo};
use candid::Principal;
use pocket_ic::management_canister::DefiniteCanisterSettings;
use pocket_ic::{management_canister::CanisterStatusResult, nonblocking::PocketIc};
use thiserror::Error;

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

    async fn canister_info(
        &self,
        canister_id: impl Into<Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        let canister_id = canister_id.into();

        let CanisterStatusResult {
            module_hash,
            settings: DefiniteCanisterSettings { controllers, .. },
            ..
        } = self
            .pocket_ic
            .canister_status(canister_id, Some(self.sender))
            .await
            .map_err(PocketIcCallError::PocketIc)?;

        Ok(CanisterInfo {
            module_hash,
            controllers: controllers.into_iter().collect(),
        })
    }

    fn caller(&self) -> Result<Principal, Self::Error> {
        Ok(self.sender)
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

    async fn canister_info(
        &self,
        canister_id: impl Into<Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        PocketIcAgent::new(self, Principal::anonymous())
            .canister_info(canister_id)
            .await
    }

    fn caller(&self) -> Result<Principal, Self::Error> {
        Ok(Principal::anonymous())
    }
}
