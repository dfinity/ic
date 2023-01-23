use crate::pb::v1::{
    CanisterCallError, GovernanceError, SetDappControllersRequest, SetDappControllersResponse,
    SettleCommunityFundParticipation,
};
use async_trait::async_trait;
use ic_base_types::CanisterId;
use ic_ic00_types::CanisterStatusResultV2;
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
        dfn_core::api::call(
            self.canister_id,
            "set_dapp_controllers",
            dfn_candid::candid_one,
            request,
        )
        .await
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
        dfn_core::api::call(
            self.canister_id,
            "manage_neuron",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }

    async fn set_mode(&mut self, request: SetMode) -> Result<SetModeResponse, CanisterCallError> {
        // TODO: Eliminate repetitive code. At least textually, the only
        // difference is the second argument that gets passed to
        // dfn_core::api::call (the name of the method).
        dfn_core::api::call(
            self.canister_id,
            "set_mode",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }

    async fn claim_swap_neurons(
        &mut self,
        request: ClaimSwapNeuronsRequest,
    ) -> Result<ClaimSwapNeuronsResponse, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "claim_swap_neurons",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

#[async_trait]
pub trait NnsGovernanceClient {
    async fn settle_community_fund_participation(
        &mut self,
        request: SettleCommunityFundParticipation,
    ) -> Result<Result<(), GovernanceError>, CanisterCallError>;
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
    async fn settle_community_fund_participation(
        &mut self,
        request: SettleCommunityFundParticipation,
    ) -> Result<Result<(), GovernanceError>, CanisterCallError> {
        dfn_core::api::call(
            self.canister_id,
            "settle_community_fund_participation",
            dfn_candid::candid_one,
            request,
        )
        .await
        .map_err(CanisterCallError::from)
    }
}

/// A trait that wraps calls to the IC's Management Canister. More details on the management
/// canister can be found in the InternetComputer spec:
///
/// https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
#[async_trait]
pub trait ManagementCanister {
    async fn canister_status(&self, canister_id: &CanisterId) -> CanisterStatusResultV2;
}

#[derive(Default)]
pub struct ProdManagementCanister {}

#[async_trait]
impl ManagementCanister for ProdManagementCanister {
    async fn canister_status(&self, canister_id: &CanisterId) -> CanisterStatusResultV2 {
        let result = ic_nervous_system_common::get_canister_status(canister_id.get()).await;
        result.unwrap_or_else(|err| {
            panic!(
                "Couldn't get canister_status of {}. Err: {:#?}",
                canister_id, err
            )
        })
    }
}
