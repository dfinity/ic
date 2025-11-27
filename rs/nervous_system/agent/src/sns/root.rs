use crate::{
    CallCanisters, sns::Sns, sns::archive::ArchiveCanister, sns::governance::GovernanceCanister,
    sns::index::IndexCanister, sns::ledger::LedgerCanister, sns::swap::SwapCanister,
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::canister_status::CanisterStatusResult;
use ic_sns_root::{
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
    pb::v1::{ListSnsCanistersRequest, ListSnsCanistersResponse},
};
use requests::GetSnsControlledCanisterStatus;
use serde::{Deserialize, Serialize};

pub mod requests;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct RootCanister {
    pub canister_id: PrincipalId,
}

pub struct SnsCanisters {
    pub sns: Sns,
    pub dapps: Vec<PrincipalId>,
    pub extensions: Vec<PrincipalId>,
}

impl TryFrom<ListSnsCanistersResponse> for SnsCanisters {
    type Error = String;

    fn try_from(src: ListSnsCanistersResponse) -> Result<Self, Self::Error> {
        let ListSnsCanistersResponse {
            root: Some(sns_root_canister_id),
            governance: Some(sns_governance_canister_id),
            ledger: Some(sns_ledger_canister_id),
            swap: Some(swap_canister_id),
            index: Some(index_canister_id),
            archives,
            dapps,
            extensions,
        } = src
        else {
            return Err(format!("Some SNS canisters were missing: {src:?}"));
        };

        let sns = Sns {
            root: RootCanister::new(sns_root_canister_id),
            governance: GovernanceCanister::new(sns_governance_canister_id),
            ledger: LedgerCanister::new(sns_ledger_canister_id),
            swap: SwapCanister::new(swap_canister_id),
            index: IndexCanister::new(index_canister_id),
            archive: archives.into_iter().map(ArchiveCanister::new).collect(),
        };

        let extensions =
            extensions.map_or_else(Vec::new, |extensions| extensions.extension_canister_ids);

        Ok(Self {
            sns,
            dapps,
            extensions,
        })
    }
}

impl RootCanister {
    pub fn new(canister_id: impl Into<PrincipalId>) -> Self {
        let canister_id = canister_id.into();
        Self { canister_id }
    }

    pub async fn sns_canisters_summary<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<GetSnsCanistersSummaryResponse, C::Error> {
        agent
            .call(
                self.canister_id,
                GetSnsCanistersSummaryRequest {
                    update_canister_list: None,
                },
            )
            .await
    }

    pub async fn list_sns_canisters<C: CallCanisters>(
        &self,
        agent: &C,
    ) -> Result<ListSnsCanistersResponse, C::Error> {
        let response = agent
            .call(self.canister_id, ListSnsCanistersRequest {})
            .await?;

        Ok(response)
    }

    pub async fn get_sns_controlled_canister_status<C: CallCanisters>(
        &self,
        agent: &C,
        canister_id: CanisterId,
    ) -> Result<CanisterStatusResult, C::Error> {
        agent
            .call(
                self.canister_id,
                GetSnsControlledCanisterStatus { canister_id },
            )
            .await
    }
}
