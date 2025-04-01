use std::time::Duration;

use crate::management_canister::requests::{
    CanisterStatusArgs, DeleteCanisterArgs, StopCanisterArgs, StoredChunksArgs, UploadChunkArgs,
};
use crate::Request;
use crate::{CallCanisters, CanisterInfo, ProgressNetwork};
use candid::Principal;
use ic_management_canister_types::{CanisterStatusResult, DefiniteCanisterSettings};
use pocket_ic::common::rest::RawEffectivePrincipal;
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::ErrorCode;
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
    #[error("retrieving canister info is not implemented for canister without controllers, such as this one.")]
    BlackHole,
    #[error("pocket_ic failed to find the subnet of canister {0}")]
    CanisterSubnetNotFound(Principal),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for PocketIc {}
impl crate::sealed::Sealed for PocketIcAgent<'_> {}

impl PocketIcAgent<'_> {
    async fn get_subnet(
        &self,
        canister_id: Principal,
    ) -> Result<RawEffectivePrincipal, PocketIcCallError> {
        let Some(subnet_id) = self.pocket_ic.get_subnet(canister_id).await else {
            return Err(PocketIcCallError::CanisterSubnetNotFound(canister_id));
        };

        Ok(RawEffectivePrincipal::CanisterId(
            subnet_id.as_slice().to_vec(),
        ))
    }

    async fn management_canister_call<R: Request>(
        &self,
        request: R,
    ) -> Result<R::Response, PocketIcCallError> {
        let payload = request.payload().map_err(PocketIcCallError::CandidEncode)?;

        let canister_id = match request.method() {
            "upload_chunk" => {
                candid::decode_one::<UploadChunkArgs>(payload.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?
                    .canister_id
            }
            "stored_chunks" => {
                candid::decode_one::<StoredChunksArgs>(payload.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?
                    .canister_id
            }
            "canister_status" => {
                candid::decode_one::<CanisterStatusArgs>(payload.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?
                    .canister_id
            }
            "stop_canister" => {
                candid::decode_one::<StopCanisterArgs>(payload.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?
                    .canister_id
            }
            "delete_canister" => {
                candid::decode_one::<DeleteCanisterArgs>(payload.as_slice())
                    .map_err(PocketIcCallError::CandidDecode)?
                    .canister_id
            }
            mathod_name => {
                unimplemented!(
                    "PocketIcAgent does not currently implement IC00.{}",
                    mathod_name
                );
            }
        };

        let effective_principal = self.get_subnet(canister_id).await?;

        let response = self
            .pocket_ic
            .update_call_with_effective_principal(
                Principal::management_canister(),
                effective_principal,
                self.sender,
                request.method(),
                payload,
            )
            .await
            .map_err(PocketIcCallError::PocketIc)?;

        candid::decode_one(response.as_slice()).map_err(PocketIcCallError::CandidDecode)
    }
}

impl CallCanisters for PocketIcAgent<'_> {
    type Error = PocketIcCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();

        // Currently, PocketIc does not route calls to aaaaa-aa, saying that it does not belong
        // to any subnet. So we need to explicitly treat this case.
        if canister_id == Principal::management_canister() {
            return self.management_canister_call(request).await;
        }

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

        let canister_exists = self.pocket_ic.canister_exists(canister_id).await;
        let controllers = if canister_exists {
            self.pocket_ic.get_controllers(canister_id).await
        } else {
            vec![]
        };

        let Some(controller) = controllers.into_iter().last() else {
            return Err(Self::Error::BlackHole);
        };

        let CanisterStatusResult {
            module_hash,
            settings: DefiniteCanisterSettings { controllers, .. },
            ..
        } = self
            .pocket_ic
            .canister_status(canister_id, Some(controller))
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

    fn is_canister_stopped_error(&self, err: &Self::Error) -> bool {
        self.pocket_ic.is_canister_stopped_error(err)
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

    fn is_canister_stopped_error(&self, err: &Self::Error) -> bool {
        match err {
            PocketIcCallError::PocketIc(err) => {
                [ErrorCode::CanisterStopped, ErrorCode::CanisterStopping].contains(&err.error_code)
            }
            _ => false,
        }
    }
}

impl ProgressNetwork for PocketIcAgent<'_> {
    async fn progress(&self, duration: Duration) {
        self.pocket_ic.progress(duration).await
    }
}

impl ProgressNetwork for PocketIc {
    async fn progress(&self, duration: Duration) {
        if !self.auto_progress_enabled().await {
            self.advance_time(duration).await;
            self.tick().await;
        } else {
            // Otherwise, we have to wait for the time to pass "naturally".
            if duration > Duration::from_secs(5) {
                eprintln!("Warning: waiting for {:?}, this may take a while", duration);
                eprintln!("Consider using shorter duration in 'progress' method calls");
            }
            std::thread::sleep(duration);
        }
    }
}
