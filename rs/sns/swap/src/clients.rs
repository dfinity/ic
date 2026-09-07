use crate::pb::v1::{
    CanisterCallError, SetDappControllersRequest, SetDappControllersResponse,
    SettleNeuronsFundParticipationRequest, SettleNeuronsFundParticipationResponse,
};
use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_cdk::call::{Call, Error as IcCdkCallError};
use ic_sns_governance::pb::v1::{
    ClaimSwapNeuronsRequest, ClaimSwapNeuronsResponse, ManageNeuron, ManageNeuronResponse, SetMode,
    SetModeResponse,
};

#[async_trait]
pub trait SnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError>;
}

pub struct RealSnsRootClient {
    canister_id: CanisterId,
}

impl RealSnsRootClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl SnsRootClient for RealSnsRootClient {
    async fn set_dapp_controllers(
        &mut self,
        request: SetDappControllersRequest,
    ) -> Result<SetDappControllersResponse, CanisterCallError> {
        Call::unbounded_wait(self.canister_id.get().0, "set_dapp_controllers")
            .with_arg(&request)
            .await
            .map_err(IcCdkCallError::from)
            .and_then(|response| {
                response
                    .candid::<SetDappControllersResponse>()
                    .map_err(IcCdkCallError::from)
            })
            .map_err(CanisterCallError::from)
    }
}

#[async_trait]
pub trait SnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError>;

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError>;

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError>;
}

pub struct RealSnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealSnsGovernanceClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl SnsGovernanceClient for RealSnsGovernanceClient {
    async fn manage_neuron(
        &mut self,
        request: ManageNeuron,
    ) -> Result<ManageNeuronResponse, CanisterCallError> {
        Call::unbounded_wait(self.canister_id.get().0, "manage_neuron")
            .with_arg(&request)
            .await
            .map_err(IcCdkCallError::from)
            .and_then(|response| {
                response
                    .candid::<ManageNeuronResponse>()
                    .map_err(IcCdkCallError::from)
            })
            .map_err(CanisterCallError::from)
    }

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        // TODO: Eliminate repetitive code. At least textually, the only
        // difference is the second argument that gets passed to
        // Call::unbounded_wait (the name of the method).
        Call::unbounded_wait(self.canister_id.get().0, "set_mode")
            .with_arg(request)
            .await
            .map_err(IcCdkCallError::from)
            .and_then(|response| {
                response
                    .candid::<SetModeResponse>()
                    .map_err(IcCdkCallError::from)
            })
            .map_err(CanisterCallError::from)
    }

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError> {
        Call::unbounded_wait(self.canister_id.get().0, "claim_swap_neurons")
            .with_arg(&request)
            .await
            .map_err(IcCdkCallError::from)
            .and_then(|response| {
                response
                    .candid::<ClaimSwapNeuronsResponse>()
                    .map_err(IcCdkCallError::from)
            })
            .map_err(CanisterCallError::from)
    }
}

#[async_trait]
pub trait NnsGovernanceClient {
    async fn settle_neurons_fund_participation(
        &mut self,
        request: SettleNeuronsFundParticipationRequest,
    ) -> Result<SettleNeuronsFundParticipationResponse, CanisterCallError>;
}

pub struct RealNnsGovernanceClient {
    canister_id: CanisterId,
}

impl RealNnsGovernanceClient {
    pub fn new(canister_id: CanisterId) -> Self {
        Self { canister_id }
    }
}

#[async_trait]
impl NnsGovernanceClient for RealNnsGovernanceClient {
    async fn settle_neurons_fund_participation(
        &mut self,
        request: SettleNeuronsFundParticipationRequest,
    ) -> Result<SettleNeuronsFundParticipationResponse, CanisterCallError> {
        Call::unbounded_wait(
            self.canister_id.get().0,
            "settle_neurons_fund_participation",
        )
        .with_arg(&request)
        .await
        .map_err(IcCdkCallError::from)
        .and_then(|response| {
            response
                .candid::<SettleNeuronsFundParticipationResponse>()
                .map_err(IcCdkCallError::from)
        })
        .map_err(CanisterCallError::from)
    }
}
