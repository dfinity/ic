pub mod pb;

use crate::pb::v1::SnsRootCanister;
use dfn_core::api::{call, id};
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_ic00_types::CanisterStatusResultV2;
use ic_nervous_system_common::get_canister_status;

impl SnsRootCanister {
    /// Return the canister status of all SNS canisters of the SNS that is Root is part of
    pub async fn get_sns_canisters_summary(
        &self,
        dapp_canisters: Vec<PrincipalId>,
    ) -> Vec<(String, PrincipalId, CanisterStatusResultV2)> {
        let mut summary = vec![];

        if let Some(governance_id) = self.governance_canister_id {
            let root_status = get_root_status(governance_id).await;
            summary.push(("root".into(), id().get(), root_status));

            let governance_status = get_canister_status(governance_id).await;
            summary.push(("governance".into(), governance_id, governance_status));
        }

        if let Some(ledger_id) = self.ledger_canister_id {
            let ledger_status = get_canister_status(ledger_id).await;
            summary.push(("ledger".into(), ledger_id, ledger_status));
        }

        for dapp_id in dapp_canisters {
            let dapp_status = get_canister_status(dapp_id).await;
            summary.push(("dapp".into(), dapp_id, dapp_status));
        }

        summary
    }
}

/// Get the canister status of the Root canister controlled by the given Governance canister.
/// Root cannot get its own status because only the controller of a canister is able to
/// query the canister's status, and Root is solely controlled by Governance.
async fn get_root_status(governance_id: PrincipalId) -> CanisterStatusResultV2 {
    call(
        CanisterId::new(governance_id).unwrap(),
        "get_root_canister_status",
        dfn_candid::candid,
        (),
    )
    .await
    .unwrap()
}
