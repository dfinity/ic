use crate::Request;
use candid::Principal;
use ic_management_canister_types::InstallCodeArgs;
use ic_types::Cycles;
use pocket_ic::{management_canister::CanisterSettings, nonblocking::PocketIc};
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

#[derive(Error, Debug)]
pub enum PocketIcInstallWasmError {
    #[error("invalid argument: {0}")]
    InvalidArgument(InstallCodeArgs),
}

impl crate::sealed::Sealed for PocketIc {}

impl CallCanisters for PocketIc {
    type CallError = PocketIcCallError;
    type CreateCanisterError = std::convert::Infallible;
    type InstallWasmError = PocketIcInstallWasmError;

    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::CallError> {
        let canister_id = canister_id.into();
        let request_bytes = request.payload();
        let response = if request.update() {
            self.update_call(
                canister_id,
                Principal::anonymous(),
                request.method(),
                request_bytes,
            )
            .await
        } else {
            self.query_call(
                canister_id,
                Principal::anonymous(),
                request.method(),
                request_bytes,
            )
            .await
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

    async fn create_canister(
        &self,
        cycles: Cycles,
        controllers: Vec<Principal>,
    ) -> Result<Principal, Self::CreateCanisterError> {
        let settings = CanisterSettings {
            controllers: Some(controllers),
            ..Default::default()
        };
        let canister_id = self
            .create_canister_with_settings(None, Some(settings))
            .await;

        self.add_cycles(canister_id, cycles.into()).await;

        Ok(canister_id)
    }

    async fn install_wasm(&self, args: InstallCodeArgs) -> Result<(), Self::InstallWasmError> {
        let InstallCodeArgs {
            arg,
            mode: _,
            canister_id,
            wasm_module,
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: None,
        } = args
        else {
            return Err(Self::InstallWasmError::InvalidArgument(args));
        };
        self.install_canister(Principal::from(canister_id), wasm_module, arg, None)
            .await;

        Ok(())
    }
}
