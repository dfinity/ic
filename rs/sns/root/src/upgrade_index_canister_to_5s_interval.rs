use crate::{logs::ERROR, pb::v1::SnsRootCanister};

use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_icrc1_index_ng::{IndexArg, UpgradeArg};
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_governance_api::pb::v1::{GetRunningSnsVersionRequest, GetRunningSnsVersionResponse};
use std::cell::RefCell;
use std::thread::LocalKey;

// These types are defined locally to avoid a circular dependency (sns-root -> sns-wasm -> sns-root).
#[derive(candid::CandidType, candid::Deserialize)]
struct GetWasmRequest {
    hash: Vec<u8>,
}

#[derive(candid::CandidType, candid::Deserialize)]
struct GetWasmResponse {
    wasm: Option<SnsWasm>,
}

#[derive(candid::CandidType, candid::Deserialize)]
struct SnsWasm {
    wasm: Vec<u8>,
    canister_type: i32,
    proposal_id: Option<u64>,
}

impl SnsRootCanister {
    /// Upgrades the index canister to set `retrieve_blocks_from_ledger_interval_seconds` to 5s.
    /// Uses the same WASM version but passes an UpgradeArg to override the interval.
    pub async fn upgrade_index_canister_to_5s_interval(self_ref: &'static LocalKey<RefCell<Self>>) {
        let (governance_canister_id, index_canister_id) = self_ref.with(|r| {
            let r = r.borrow();
            (r.governance_canister_id, r.index_canister_id)
        });

        let result = try_upgrade_index_canister(governance_canister_id, index_canister_id).await;

        if let Err(e) = result {
            log!(
                ERROR,
                "Error upgrading index canister to 5s interval: {}",
                e
            );
        }
    }
}

fn get_canister_id(principal_id: Option<PrincipalId>, label: &str) -> Result<CanisterId, String> {
    let principal_id = principal_id.ok_or(format!("No canister id for {label} provided"))?;
    CanisterId::try_from_principal_id(principal_id)
        .map_err(|e| format!("Error getting canister id for {label}: {e}"))
}

async fn try_upgrade_index_canister(
    governance_canister_id: Option<PrincipalId>,
    index_canister_id: Option<PrincipalId>,
) -> Result<(), String> {
    let governance_canister_id = get_canister_id(governance_canister_id, "Governance")?;
    let index_canister_id = get_canister_id(index_canister_id, "Index")?;

    let request = GetRunningSnsVersionRequest {};
    let (response,): (GetRunningSnsVersionResponse,) = CdkRuntime::call_with_cleanup(
        governance_canister_id,
        "get_running_sns_version",
        (request,),
    )
    .await
    .map_err(|(code, message)| format!("Error getting running sns version: {code}: {message}"))?;
    let index_wasm_hash = response
        .deployed_version
        .ok_or("Deployed version not found")?
        .index_wasm_hash;

    // Get the Wasm from SNS-WASM canister.
    let request = GetWasmRequest {
        hash: index_wasm_hash,
    };
    let (response,): (GetWasmResponse,) =
        CdkRuntime::call_with_cleanup(SNS_WASM_CANISTER_ID, "get_wasm", (request,))
            .await
            .map_err(|(code, message)| format!("Error getting wasm: {code}: {message}"))?;
    let wasm_module = response.wasm.ok_or("Wasm not found")?.wasm;

    // Prepare the upgrade args.
    let args = Some(IndexArg::Upgrade(UpgradeArg {
        ledger_id: None,
        retrieve_blocks_from_ledger_interval_seconds: Some(5),
    }));
    let args = Encode!(&args).map_err(|e| format!("Error encoding args: {}", e))?;

    // Prepare the change canister request.
    let change_canister_request = ChangeCanisterRequest {
        canister_id: index_canister_id,
        wasm_module,
        arg: args,
        mode: CanisterInstallMode::Upgrade,
        stop_before_installing: true,
        chunked_canister_wasm: None,
    };

    // Perform the change.
    ic_nervous_system_root::change_canister::change_canister(change_canister_request)
        .await
        .map_err(|e| format!("Error changing canister: {}", e))
}
