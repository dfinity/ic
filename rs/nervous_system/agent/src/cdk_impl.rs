use crate::{sealed, CallCanisters, CanisterInfo, Request};
use thiserror::Error;

pub struct CdkAgent {}

#[derive(Error, Debug)]
pub enum CdkAgentError {
    #[error("ic_cdk error code {0}: {1}")]
    IcCdk(i32, String),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
    #[error("CdkAgent function is not implemented: {0}")]
    NotImplemented(String),
}

impl sealed::Sealed for CdkAgent {}

impl CallCanisters for CdkAgent {
    type Error = CdkAgentError;

    fn caller(&self) -> Result<candid::Principal, Self::Error> {
        Ok(ic_cdk::caller())
    }

    async fn call<R: Request>(
        &self,
        canister_id: impl Into<candid::Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let args_raw = request.payload().map_err(CdkAgentError::CandidEncode)?;

        let response =
            ic_cdk::api::call::call_raw(canister_id.into(), request.method(), args_raw, 0)
                .await
                .map_err(|(err_code, err_message)| {
                    CdkAgentError::IcCdk(err_code as i32, err_message)
                })?;

        let result =
            candid::decode_one(response.as_slice()).map_err(CdkAgentError::CandidDecode)?;

        Ok(result)
    }

    async fn canister_info(
        &self,
        _canister_id: impl Into<candid::Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        Err(CdkAgentError::NotImplemented("canister_info".to_string()))
    }
}
