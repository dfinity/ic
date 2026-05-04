#![allow(deprecated)]
use crate::pb::v1::{
    CanisterCallError, SetDappControllersRequest, SetDappControllersResponse,
    SettleNeuronsFundParticipationRequest, SettleNeuronsFundParticipationResponse,
};
use async_trait::async_trait;
use ic_base_types::CanisterId;
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
        ic_cdk::call(self.canister_id.get().0, "set_dapp_controllers", (request,))
            .await
            .map(|response: (SetDappControllersResponse,)| response.0)
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
        ic_cdk::call(self.canister_id.get().0, "manage_neuron", (request,))
            .await
            .map(|response: (ManageNeuronResponse,)| response.0)
            .map_err(CanisterCallError::from)
    }

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        // TODO: Eliminate repetitive code. At least textually, the only
        // difference is the second argument that gets passed to
        // ic_cdk::call (the name of the method).
        ic_cdk::call(self.canister_id.get().0, "set_mode", (request,))
            .await
            .map(|response: (SetModeResponse,)| response.0)
            .map_err(CanisterCallError::from)
    }

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError> {
        ic_cdk::call(self.canister_id.get().0, "claim_swap_neurons", (request,))
            .await
            .map(|response: (ClaimSwapNeuronsResponse,)| response.0)
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
        ic_cdk::call(
            self.canister_id.get().0,
            "settle_neurons_fund_participation",
            (request,),
        )
        .await
        .map(|response: (SettleNeuronsFundParticipationResponse,)| response.0)
        .map_err(CanisterCallError::from)
    }
}
