use crate::Request;
use candid::Principal;
use ic_agent::Agent;
use ic_management_canister_types::InstallCodeArgs;
use ic_types::Cycles;
use thiserror::Error;

use crate::CallCanisters;

#[derive(Error, Debug)]
pub enum AgentCallError {
    #[error("agent error: {0}")]
    Agent(#[from] ic_agent::AgentError),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for Agent {}

impl CallCanisters for Agent {
    type CallError = AgentCallError;
    type CreateCanisterError = AgentCallError;
    type InstallWasmError = AgentCallError;

    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::CallError> {
        let canister_id = canister_id.into();
        let request_bytes = request.payload();
        let response = if request.update() {
            let request = self
                .update(&canister_id, request.method())
                .with_arg(request_bytes)
                .call()
                .await?;
            let (response, _cert) = match request {
                ic_agent::agent::CallResponse::Response(response) => response,
                ic_agent::agent::CallResponse::Poll(request_id) => {
                    self.wait(&request_id, canister_id).await?
                }
            };
            response
        } else {
            self.query(&canister_id, request.method())
                .with_arg(request_bytes)
                .call()
                .await?
        };

        let response =
            candid::decode_one(response.as_slice()).map_err(AgentCallError::CandidDecode)?;
        Ok(response)
    }

    async fn create_canister(
        &self,
        _cycles: Cycles,
        _controllers: Vec<Principal>,
    ) -> Result<Principal, Self::CreateCanisterError> {
        unimplemented!()
    }

    async fn install_wasm(&self, _args: InstallCodeArgs) -> Result<(), Self::InstallWasmError> {
        unimplemented!()
    }
}
