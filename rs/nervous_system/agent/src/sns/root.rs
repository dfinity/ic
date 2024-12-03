use ic_base_types::PrincipalId;
use ic_sns_root::{
    pb::v1::{ListSnsCanistersRequest, ListSnsCanistersResponse},
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    sns::archive::ArchiveCanister, sns::governance::GovernanceCanister, sns::index::IndexCanister,
    sns::ledger::LedgerCanister, sns::swap::SwapCanister, sns::Sns, CallCanisters,
};

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct RootCanister {
    pub canister_id: PrincipalId,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum ListSnsCanistersError<E> {
    #[error("SNS root canister did not return canister IDs for all canisters - this should never happen")]
    SnsRootDidNotReturnAllCanisterIds(ListSnsCanistersResponse),
    #[error("Failed to call SNS root canister")]
    CallFailed(#[from] E),
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
    ) -> Result<Sns, ListSnsCanistersError<C::Error>> {
        let response = agent
            .call(self.canister_id, ListSnsCanistersRequest {})
            .await?;
        let ListSnsCanistersResponse {
            root: Some(sns_root_canister_id),
            governance: Some(sns_governance_canister_id),
            ledger: Some(sns_ledger_canister_id),
            swap: Some(swap_canister_id),
            index: Some(index_canister_id),
            archives,
            dapps: _,
        } = response
        else {
            return Err(ListSnsCanistersError::SnsRootDidNotReturnAllCanisterIds(
                response,
            ));
        };

        Ok(Sns {
            root: RootCanister::new(sns_root_canister_id),
            governance: GovernanceCanister::new(sns_governance_canister_id),
            ledger: LedgerCanister::new(sns_ledger_canister_id),
            swap: SwapCanister::new(swap_canister_id),
            index: IndexCanister::new(index_canister_id),
            archive: archives.into_iter().map(ArchiveCanister::new).collect(),
        })
    }
}
