use crate::{AgentFor, CallCanisters, CanisterInfo, Request};
use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use ic_state_machine_tests::{StateMachine, UserError, WasmResult};
use std::time::Duration;
use thiserror::Error;

pub struct StateMachineAgent<'a> {
    state_machine: &'a StateMachine,
    sender: Principal,
}

impl<'a> StateMachineAgent<'a> {
    pub fn new(state_machine: &'a StateMachine, sender: impl Into<Principal>) -> Self {
        let sender = sender.into();
        Self {
            state_machine,
            sender,
        }
    }
}

#[derive(Error, Debug)]
pub enum StateMachineCallError {
    #[error("state machine ingress state error: {0}")]
    IngressStateError(UserError),
    #[error("the canister being called decides to reject the message: {0}")]
    MessageRejected(String),
    #[error("canister does not exist: {0}")]
    CanisterDoesNotExist(Principal),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for StateMachine {}
impl crate::sealed::Sealed for StateMachineAgent<'_> {}

impl CallCanisters for StateMachineAgent<'_> {
    type Error = StateMachineCallError;

    fn caller(&self) -> Result<Principal, Self::Error> {
        Ok(self.sender)
    }

    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        // This is to be backward compatible with the previous implementation from
        // /rs/nns/test_utils/src/state_test_helpers.rs
        self.state_machine.advance_time(Duration::from_secs(2));

        let request_bytes = request.payload().map_err(Self::Error::CandidEncode)?;

        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from(canister_id.into()));

        let sender = PrincipalId::from(self.sender);

        let response = self
            .state_machine
            .execute_ingress_as(sender, canister_id, request.method(), request_bytes)
            .map_err(Self::Error::IngressStateError)?;

        let response_bytes = match response {
            WasmResult::Reply(bytes) => bytes,
            WasmResult::Reject(err) => {
                return Err(Self::Error::MessageRejected(err));
            }
        };

        candid::decode_one(response_bytes.as_slice()).map_err(Self::Error::CandidDecode)
    }

    async fn canister_info(
        &self,
        canister_id: impl Into<candid::Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        let canister_id = CanisterId::unchecked_from_principal(PrincipalId(canister_id.into()));

        let module_hash = self
            .state_machine
            .module_hash(canister_id)
            .map(|hash| hash.to_vec());

        let Some(controllers) = self.state_machine.get_controllers(canister_id) else {
            return Err(Self::Error::CanisterDoesNotExist(canister_id.get().0));
        };

        Ok(CanisterInfo {
            module_hash,
            controllers: controllers
                .into_iter()
                .map(|controller| controller.0)
                .collect(),
        })
    }
}

impl CallCanisters for StateMachine {
    type Error = StateMachineCallError;

    fn caller(&self) -> Result<Principal, Self::Error> {
        Ok(Principal::anonymous())
    }

    async fn call<R: crate::Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        StateMachineAgent::new(self, Principal::anonymous())
            .call(canister_id, request)
            .await
    }

    async fn canister_info(
        &self,
        canister_id: impl Into<candid::Principal> + Send,
    ) -> Result<CanisterInfo, Self::Error> {
        StateMachineAgent::new(self, Principal::anonymous())
            .canister_info(canister_id)
            .await
    }
}

impl AgentFor for StateMachine {
    fn agent_for(&self, principal: impl Into<Principal>) -> impl CallCanisters {
        StateMachineAgent::new(self, principal)
    }
}
