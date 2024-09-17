pub mod nns;
pub mod sns;

use candid::Principal;
use ic_agent::Agent;
use ic_nervous_system_clients::Request;
use std::fmt::Display;
use thiserror::Error;

pub trait CallCanisters {
    type Error: Display + Send;
    fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> impl std::future::Future<Output = Result<R::Response, Self::Error>> + Send;
}

#[derive(Error, Debug)]
pub enum AgentCallError {
    #[error("agent error: {0}")]
    AgentError(#[from] ic_agent::AgentError),
    #[error("canister request could not be encoded: {0}")]
    CandidEncodeError(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecodeError(candid::Error),
}

impl CallCanisters for Agent {
    type Error = AgentCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();
        let request_bytes =
            candid::encode_one(&request).map_err(AgentCallError::CandidEncodeError)?;
        let response = if R::UPDATE {
            let request = self
                .update(&canister_id, R::METHOD)
                .with_arg(request_bytes)
                .call()
                .await?;
            match request {
                ic_agent::agent::CallResponse::Response(response) => response,
                ic_agent::agent::CallResponse::Poll(request_id) => {
                    self.wait(&request_id, canister_id).await?
                }
            }
        } else {
            self.query(&canister_id, R::METHOD)
                .with_arg(request_bytes)
                .call()
                .await?
        };

        let response =
            candid::decode_one(response.as_slice()).map_err(AgentCallError::CandidDecodeError)?;
        Ok(response)
    }
}
