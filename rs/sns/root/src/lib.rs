pub mod pb;

use crate::pb::v1::SnsRootCanister;
use dfn_core::api::call;
use dfn_core::CanisterId;
use ic_base_types::PrincipalId;
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResultV2, IC_00};

impl SnsRootCanister {
    /// Return the canister status of all canisters that Root controls.
    pub async fn get_sns_canisters_summary(
        &self,
        dapp_canisters: Vec<PrincipalId>,
    ) -> Vec<(String, PrincipalId, CanisterStatusResultV2)> {
        let mut summary = vec![];

        if let Some(governance_id) = self.governance_canister_id {
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

/// Return the status of the given canister. The caller must control the given canister.
pub async fn get_canister_status(canister_id: PrincipalId) -> CanisterStatusResultV2 {
    let canister_id_record: CanisterIdRecord = CanisterId::new(canister_id).unwrap().into();

    call(
        IC_00,
        "canister_status",
        dfn_candid::candid,
        (canister_id_record,),
    )
    .await
    .unwrap()
}
