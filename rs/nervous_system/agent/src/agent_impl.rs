use crate::{
    CallCanisters, CallCanistersWithStoppedCanisterError, CanisterInfo, ProgressNetwork, Request,
};
use candid::Principal;
use ic_agent::agent::{RejectCode, RejectResponse};
use ic_agent::{Agent, AgentError};
use itertools::{Either, Itertools};
use serde_cbor::Value;
use std::collections::BTreeSet;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentCallError {
    #[error("agent identity error: {0}")]
    Identity(String),
    #[error("agent error: {0}")]
    Agent(#[from] ic_agent::AgentError),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
    #[error("invalid canister controllers: {0}")]
    CanisterControllers(String),
}

impl crate::sealed::Sealed for Agent {}

impl CallCanisters for Agent {
    type Error = AgentCallError;

    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();
        let method = request.method();
        let payload = request.payload().map_err(AgentCallError::CandidEncode)?;

        let response = if request.update() {
            let mut call = self.update(&canister_id, method).with_arg(payload);

            if let Some(effective_canister_id) = request.effective_canister_id() {
                call = call.with_effective_canister_id(effective_canister_id);
            }

            let response = call.call().await?;

            let (response, _cert) = match response {
                ic_agent::agent::CallResponse::Response(response) => response,
                ic_agent::agent::CallResponse::Poll(request_id) => {
                    self.wait(&request_id, canister_id).await?
                }
            };

            response
        } else {
            let mut call = self.query(&canister_id, method).with_arg(payload);

            if let Some(effective_canister_id) = request.effective_canister_id() {
                call = call.with_effective_canister_id(effective_canister_id);
            }

            call.call().await?
        };

        let response =
            candid::decode_one(response.as_slice()).map_err(AgentCallError::CandidDecode)?;
        Ok(response)
    }

    async fn canister_info(
        &self,
        canister_id: impl Into<Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        let canister_id = canister_id.into();

        let read_state_result = self
            .read_state_canister_info(canister_id, "module_hash")
            .await;

        let module_hash = match read_state_result {
            Ok(module_hash) => Some(module_hash),
            Err(ic_agent::AgentError::LookupPathAbsent(_)) => {
                // https://internetcomputer.org/docs/current/references/ic-interface-spec#state-tree-canister-information
                None
            }
            Err(err) => {
                return Err(Self::Error::Agent(err));
            }
        };

        let controllers_blob = self
            .read_state_canister_info(canister_id, "controllers")
            .await
            .map_err(AgentCallError::Agent)?;

        let cbor: Value = serde_cbor::from_slice(&controllers_blob).map_err(|err| {
            Self::Error::CanisterControllers(format!("Failed decoding CBOR data: {err:?}"))
        })?;

        let Value::Array(controllers) = cbor else {
            return Err(Self::Error::CanisterControllers(format!(
                "Expected controllers to be an array, but got {cbor:?}"
            )));
        };

        let (controllers, errors): (Vec<_>, Vec<_>) =
            controllers.into_iter().partition_map(|value| {
                let Value::Bytes(bytes) = value else {
                    let err =
                        format!("Expected canister controller to be of type bytes, got {value:?}");
                    return Either::Right(err);
                };
                match Principal::try_from(&bytes) {
                    Err(err) => {
                        let err = format!("Cannot interpret canister controller principal: {err}");
                        Either::Right(err)
                    }
                    Ok(principal) => Either::Left(principal),
                }
            });

        if !errors.is_empty() {
            return Err(Self::Error::CanisterControllers(format!(
                "\n  - {}",
                errors.join("\n  - ")
            )));
        }

        let unique_controllers = BTreeSet::from_iter(controllers.iter().copied());

        if unique_controllers.len() != controllers.len() {
            return Err(Self::Error::CanisterControllers(format!(
                "Canister controllers have duplicates: {}",
                controllers.into_iter().join(", ")
            )));
        }

        Ok(CanisterInfo {
            module_hash,
            controllers: unique_controllers,
        })
    }

    fn caller(&self) -> Result<Principal, Self::Error> {
        self.get_principal().map_err(Self::Error::Identity)
    }
}

impl CallCanistersWithStoppedCanisterError for Agent {
    fn is_canister_stopped_error(&self, err: &Self::Error) -> bool {
        match err {
            AgentCallError::Agent(AgentError::CertifiedReject {
                reject:
                    RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        error_code: Some(error_code),
                        ..
                    },
                ..
            }) => {
                // CanisterStopped or CanisterStopping
                ["IC0508".to_string(), "IC0509".to_string()].contains(error_code)
            }
            _ => false,
        }
    }
}

impl ProgressNetwork for Agent {
    async fn progress(&self, duration: Duration) {
        if duration > Duration::from_secs(5) {
            eprintln!("Warning: waiting for {duration:?}, this may take a while");
            eprintln!("Consider using shorter duration in 'progress' method calls");
        }
        tokio::time::sleep(duration).await;
    }
}
