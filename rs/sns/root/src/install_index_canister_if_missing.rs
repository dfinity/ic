use crate::{logs::ERROR, pb::v1::SnsRootCanister};

use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_icrc1_index_ng::{IndexArg, InitArg};
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_clients::canister_id_record::CanisterIdRecord;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_sns_governance_api::pb::v1::{GetRunningSnsVersionRequest, GetRunningSnsVersionResponse};
use std::cell::RefCell;
use std::thread::LocalKey;

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
    /// Reinstalls the index canister if it's needed (i.e., if it has no wasm module).
    pub async fn install_index_canister_if_missing(self_ref: &'static LocalKey<RefCell<Self>>) {
        let (governance_canister_id, ledger_canister_id, index_canister_id) = self_ref.with(|r| {
            let r = r.borrow();
            (
                r.governance_canister_id,
                r.ledger_canister_id,
                r.index_canister_id,
            )
        });

        if !should_install_index_canister(index_canister_id).await {
            return;
        }

        let result = try_install_index_canister(
            governance_canister_id,
            ledger_canister_id,
            index_canister_id,
        )
        .await;

        if let Err(e) = result {
            log!(ERROR, "Error installing index canister: {}", e);
        }
    }
}

fn get_canister_id(principal_id: Option<PrincipalId>, label: &str) -> Result<CanisterId, String> {
    let principal_id = principal_id.ok_or(format!("No canister id for {label} provided"))?;
    CanisterId::try_from_principal_id(principal_id)
        .map_err(|e| format!("Error getting canister id for {label}: {e}"))
}

async fn should_install_index_canister(index_canister_id: Option<PrincipalId>) -> bool {
    let Ok(index_canister_id) = get_canister_id(index_canister_id, "Index") else {
        return false;
    };
    let result = ic_nervous_system_clients::canister_status::canister_status::<CdkRuntime>(
        CanisterIdRecord::from(index_canister_id),
    )
    .await;
    let Ok(canister_status) = result else {
        return false;
    };
    canister_status.module_hash.is_none()
}

async fn try_install_index_canister(
    governance_canister_id: Option<PrincipalId>,
    ledger_canister_id: Option<PrincipalId>,
    index_canister_id: Option<PrincipalId>,
) -> Result<(), String> {
    let governance_canister_id = get_canister_id(governance_canister_id, "Governance")?;
    let ledger_canister_id = get_canister_id(ledger_canister_id, "Ledger")?;
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

    // Prepare the init args.
    let args = Some(IndexArg::Init(InitArg {
        ledger_id: ledger_canister_id.get().into(),
        retrieve_blocks_from_ledger_interval_seconds: None,
    }));
    let args = Encode!(&args).map_err(|e| format!("Error encoding args: {}", e))?;

    // Prepare the change canister request.
    let change_canister_request = ChangeCanisterRequest {
        canister_id: index_canister_id,
        wasm_module,
        arg: args,
        mode: CanisterInstallMode::Install,
        // No need to stop before installing as the canister is uninstalled, and also because the
        // mode is install, so even if the canister is running, it's safe as the install will simply
        // fail.
        stop_before_installing: false,
        chunked_canister_wasm: None,
    };

    // Perform the change.
    ic_nervous_system_root::change_canister::change_canister::<CdkRuntime>(change_canister_request)
        .await
        .map_err(|e| format!("Error changing canister: {}", e))
}
