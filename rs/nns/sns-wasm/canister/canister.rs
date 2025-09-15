#![allow(deprecated)]
use async_trait::async_trait;
use ic_base_types::{PrincipalId, SubnetId};
use ic_cdk::api::call::{CallResult, RejectionCode};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_management_canister_types_private::{
    CanisterInstallMode::Install, CanisterSettingsArgsBuilder, CreateCanisterArgs, InstallCodeArgs,
    Method, UpdateSettingsArgs,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResultV2, CanisterStatusType, canister_status},
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_handler_root_interface::client::NnsRootCanisterClientImpl;
use ic_sns_wasm::{
    canister_api::CanisterApi,
    canister_stable_memory::CanisterStableMemory,
    init::SnsWasmCanisterInitPayload,
    pb::v1::{
        AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
        GetAllowedPrincipalsRequest, GetAllowedPrincipalsResponse,
        GetDeployedSnsByProposalIdRequest, GetDeployedSnsByProposalIdResponse,
        GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetProposalIdThatAddedWasmRequest,
        GetProposalIdThatAddedWasmResponse, GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse,
        GetWasmMetadataRequest, GetWasmMetadataResponse, GetWasmRequest, GetWasmResponse,
        InsertUpgradePathEntriesRequest, InsertUpgradePathEntriesResponse,
        ListDeployedSnsesRequest, ListDeployedSnsesResponse, ListUpgradeStepsRequest,
        ListUpgradeStepsResponse, SnsWasmError, UpdateAllowedPrincipalsRequest,
        UpdateAllowedPrincipalsResponse, UpdateSnsSubnetListRequest, UpdateSnsSubnetListResponse,
        update_allowed_principals_response::UpdateAllowedPrincipalsResult,
    },
    sns_wasm::SnsWasmCanister,
};
use ic_types::{CanisterId, Cycles};
use std::{cell::RefCell, collections::HashMap, convert::TryInto};

use ic_cdk::{init, post_upgrade, pre_upgrade, println, query, update};
use ic_nervous_system_common::serve_metrics;

pub const LOG_PREFIX: &str = "[SNS-WASM] ";

thread_local! {
    static SNS_WASM: RefCell<SnsWasmCanister<CanisterStableMemory>> = RefCell::new(SnsWasmCanister::new());
}

// TODO possibly determine how to make a single static that is thread-safe?
fn canister_api() -> CanisterApiImpl {
    CanisterApiImpl {}
}

#[derive()]
struct CanisterApiImpl {}

#[async_trait]
impl CanisterApi for CanisterApiImpl {
    /// See CanisterApi::local_canister_id
    fn local_canister_id(&self) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(ic_cdk::api::id()))
    }

    /// See CanisterApi::create_canister
    async fn create_canister(
        &self,
        target_subnet: SubnetId,
        controller_id: PrincipalId,
        cycles: Cycles,
        wasm_memory_limit: u64,
    ) -> Result<CanisterId, String> {
        let settings = CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![controller_id])
            .with_wasm_memory_limit(wasm_memory_limit);

        let result: CallResult<(CanisterIdRecord,)> = ic_cdk::api::call::call_with_payment(
            target_subnet.get().0,
            &Method::CreateCanister.to_string(),
            (CreateCanisterArgs {
                settings: Some(settings.build()),
                sender_canister_version: Some(ic_cdk::api::canister_version()),
            },),
            cycles.get().try_into().unwrap(),
        )
        .await;

        result
            .map_err(handle_call_error(format!(
                "Creating canister in subnet {target_subnet} failed"
            )))
            .map(|record| record.0.get_canister_id())
    }

    /// See CanisterApi::delete_canister
    async fn delete_canister(&self, canister: CanisterId) -> Result<(), String> {
        // Try to stop the canister first
        self.stop_canister(canister).await?;

        // TODO(NNS1-1524) We need to collect the cycles from the canister before we delete it
        let response: CallResult<()> = ic_cdk::call(
            CanisterId::ic_00().get().0,
            "delete_canister",
            (CanisterIdRecord::from(canister),),
        )
        .await;

        response.map_err(handle_call_error(format!(
            "Failed to delete canister {canister}"
        )))
    }

    /// See CanisterApi::install_wasm
    async fn install_wasm(
        &self,
        target_canister: CanisterId,
        wasm: Vec<u8>,
        init_payload: Vec<u8>,
    ) -> Result<(), String> {
        let install_args = InstallCodeArgs {
            mode: Install,
            canister_id: target_canister.get(),
            wasm_module: wasm,
            arg: init_payload,
            sender_canister_version: Some(ic_cdk::api::canister_version()),
        };
        let install_res: CallResult<()> =
            ic_cdk::call(CanisterId::ic_00().get().0, "install_code", (install_args,)).await;

        install_res.map_err(handle_call_error(format!(
            "Failed to install WASM on canister {target_canister}"
        )))
    }

    /// See CanisterApi::set_controller
    async fn set_controllers(
        &self,
        canister: CanisterId,
        controllers: Vec<PrincipalId>,
    ) -> Result<(), String> {
        let args = UpdateSettingsArgs {
            canister_id: canister.get(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_controllers(controllers)
                .build(),
            sender_canister_version: Some(ic_cdk::api::canister_version()),
        };

        let result: CallResult<()> =
            ic_cdk::call(CanisterId::ic_00().get().0, "update_settings", (args,)).await;

        result.map_err(handle_call_error(format!(
            "Failed to update controllers for canister {canister}"
        )))
    }

    fn this_canister_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
        let available = ic_cdk::api::canister_balance();

        if available < required_cycles {
            return Err(format!(
                "Message execution requires at least {required_cycles} cycles, but canister only has {available} cycles.",
            ));
        }
        Ok(available)
    }

    fn message_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
        let available = ic_cdk::api::call::msg_cycles_available();

        if available < required_cycles {
            return Err(format!(
                "Message execution requires at least {required_cycles} cycles, but only {available} cycles were sent.",
            ));
        }
        Ok(available)
    }

    fn accept_message_cycles(&self, cycles: Option<u64>) -> Result<u64, String> {
        let cycles = cycles.unwrap_or_else(ic_cdk::api::call::msg_cycles_available);
        self.message_has_enough_cycles(cycles)?;

        let accepted = ic_cdk::api::call::msg_cycles_accept(cycles);
        Ok(accepted)
    }

    async fn send_cycles_to_canister(&self, target: CanisterId, cycles: u64) -> Result<(), String> {
        let response: CallResult<()> = ic_cdk::api::call::call_with_payment(
            CanisterId::ic_00().get().0,
            "deposit_cycles",
            (CanisterIdRecord::from(target),),
            cycles,
        )
        .await;

        response.map_err(handle_call_error(format!(
            "Failed to send cycles to canister {target}"
        )))
    }
}

/// This handles the errors returned from ic_cdk::call (and related methods)
fn handle_call_error(prefix: String) -> impl FnOnce((RejectionCode, String)) -> String {
    move |(code, msg)| {
        let err = format!("{}: error code {}: {}", prefix, code as i32, msg);
        println!("{}{}", LOG_PREFIX, err);
        err
    }
}

impl CanisterApiImpl {
    async fn stop_canister(&self, canister: CanisterId) -> Result<(), String> {
        () = ic_cdk::call(
            CanisterId::ic_00().get().0,
            "stop_canister",
            (CanisterIdRecord::from(canister),),
        )
        .await
        .map_err(|(code, msg)| {
            format!(
                "Unable to stop target canister: error code {}: {}",
                code as i32, msg
            )
        })?;

        let mut count = 0;
        // Wait until canister is in the stopped state.
        loop {
            let status: CanisterStatusResultV2 =
                canister_status::<CdkRuntime>(CanisterIdRecord::from(canister))
                    .await
                    .map(CanisterStatusResultV2::from)
                    .map_err(|(code, msg)| {
                        format!("Unable to get target canister status: error code {code}: {msg}")
                    })?;

            if status.status() == CanisterStatusType::Stopped {
                return Ok(());
            }

            count += 1;
            if count > 100 {
                return Err(format!(
                    "Canister {canister} never stopped.  Waited 100 iterations"
                ));
            }

            println!(
                "{}Still waiting for canister {} to stop. status: {:?}",
                LOG_PREFIX, canister, status
            );
        }
    }
}

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::caller())
}

/// In contrast to canister_init(), this method does not do deserialization.
/// In addition to canister_init, this method is called by canister_post_upgrade.
#[init]
fn canister_init(init_payload: SnsWasmCanisterInitPayload) {
    println!("{}Executing canister init", LOG_PREFIX);
    SNS_WASM.with(|c| {
        c.borrow_mut().set_sns_subnets(init_payload.sns_subnet_ids);
        c.borrow_mut()
            .set_access_controls_enabled(init_payload.access_controls_enabled);
        c.borrow_mut()
            .set_allowed_principals(init_payload.allowed_principals);
        c.borrow().initialize_stable_memory();
    });
    println!("{}Completed canister init", LOG_PREFIX);
}

/// Executes some logic before executing an upgrade, including serializing and writing the
/// canister state to stable memory so that it is preserved during the upgrade and can
/// be deserialized again in canister_post_upgrade. That is, the stable memory allows
/// saving the state and restoring it after the upgrade.
#[pre_upgrade]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    SNS_WASM.with(|c| c.borrow().write_state_to_stable_memory());

    println!("{}Completed pre upgrade", LOG_PREFIX);
}

/// Executes some logic after executing an upgrade, including deserializing what has been written
/// to stable memory in canister_pre_upgrade and initialising the governance's state with it.
#[post_upgrade]
fn canister_post_upgrade() {
    println!("{}Executing post upgrade", LOG_PREFIX);

    SNS_WASM.with(|c| {
        c.replace(SnsWasmCanister::<CanisterStableMemory>::from_stable_memory());
    });

    println!("{}Completed post upgrade", LOG_PREFIX);
}

#[update]
fn add_wasm(add_wasm_payload: AddWasmRequest) -> AddWasmResponse {
    let access_controls_enabled =
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow().access_controls_enabled);
    if access_controls_enabled && caller() != GOVERNANCE_CANISTER_ID.into() {
        AddWasmResponse::error("add_wasm can only be called by NNS Governance".into())
    } else {
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().add_wasm(add_wasm_payload))
    }
}

#[update]
fn insert_upgrade_path_entries(
    payload: InsertUpgradePathEntriesRequest,
) -> InsertUpgradePathEntriesResponse {
    let access_controls_enabled =
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow().access_controls_enabled);
    if access_controls_enabled && caller() != GOVERNANCE_CANISTER_ID.into() {
        InsertUpgradePathEntriesResponse::error(
            "insert_upgrade_path_entries can only be called by NNS Governance".into(),
        )
    } else {
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().insert_upgrade_path_entries(payload))
    }
}

#[query]
fn list_upgrade_steps(payload: ListUpgradeStepsRequest) -> ListUpgradeStepsResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().list_upgrade_steps(payload))
}

#[query]
fn get_wasm(get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_wasm(get_wasm_payload))
}

#[query]
fn get_wasm_metadata(get_wasm_metadata_payload: GetWasmMetadataRequest) -> GetWasmMetadataResponse {
    SNS_WASM.with(|sns_wasm| {
        sns_wasm
            .borrow()
            .get_wasm_metadata(get_wasm_metadata_payload)
    })
}

#[query]
fn get_proposal_id_that_added_wasm(
    get_proposal_id_that_added_wasm_payload: GetProposalIdThatAddedWasmRequest,
) -> GetProposalIdThatAddedWasmResponse {
    SNS_WASM.with(|sns_wasm| {
        sns_wasm
            .borrow()
            .get_proposal_id_that_added_wasm(get_proposal_id_that_added_wasm_payload)
    })
}

#[query]
fn get_next_sns_version(request: GetNextSnsVersionRequest) -> GetNextSnsVersionResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_next_sns_version(request, caller()))
}

#[query]
fn get_latest_sns_version_pretty(_: ()) -> HashMap<String, String> {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_latest_sns_version_pretty())
}

#[update]
async fn deploy_new_sns(req: DeployNewSnsRequest) -> DeployNewSnsResponse {
    SnsWasmCanister::deploy_new_sns(
        &SNS_WASM,
        &canister_api(),
        &NnsRootCanisterClientImpl::default(),
        req,
        caller(),
    )
    .await
}

#[query]
fn list_deployed_snses(request: ListDeployedSnsesRequest) -> ListDeployedSnsesResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().list_deployed_snses(request))
}

#[update]
fn update_allowed_principals(_: UpdateAllowedPrincipalsRequest) -> UpdateAllowedPrincipalsResponse {
    UpdateAllowedPrincipalsResponse {
        update_allowed_principals_result: Some(UpdateAllowedPrincipalsResult::Error(
            SnsWasmError {
                message: "update_allowed_principals is obsolete. For launching an SNS, please \
                          submit a CreateServiceNervousSystem proposal."
                    .to_string(),
            },
        )),
    }
}

#[query]
fn get_allowed_principals(_request: GetAllowedPrincipalsRequest) -> GetAllowedPrincipalsResponse {
    GetAllowedPrincipalsResponse {
        allowed_principals: vec![],
    }
}

/// Add or remove SNS subnet IDs from the list of subnet IDs that SNS instances will be deployed to
#[update]
fn update_sns_subnet_list(request: UpdateSnsSubnetListRequest) -> UpdateSnsSubnetListResponse {
    if caller() != GOVERNANCE_CANISTER_ID.into() {
        UpdateSnsSubnetListResponse::error(
            "update_sns_subnet_list can only be called by NNS Governance",
        )
    } else {
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().update_sns_subnet_list(request))
    }
}

/// Return the list of SNS subnet IDs that SNS-WASM will deploy SNS instances to
#[query]
fn get_sns_subnet_ids(_request: GetSnsSubnetIdsRequest) -> GetSnsSubnetIdsResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_sns_subnet_ids())
}

#[query]
fn get_deployed_sns_by_proposal_id(
    request: GetDeployedSnsByProposalIdRequest,
) -> GetDeployedSnsByProposalIdResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_deployed_sns_by_proposal_id(request))
}

/// SNS-WASM metrics
fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let number_of_wasms = SNS_WASM.with(|sns_wasm| sns_wasm.borrow().wasm_indexes.len());

    w.encode_gauge(
        "sns_wasm_number_of_wasms",
        number_of_wasms as f64,
        "The number of WASM binaries stored in SNS-WASM",
    )?;

    let stable_memory_usage = SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_stable_memory_usage());

    w.encode_gauge(
        "sns_wasm_stable_memory_usage",
        stable_memory_usage as f64,
        "The amount of stable memory that SNS-WASM has used to store WASMs",
    )?;

    let number_of_deployed_sns =
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow().deployed_sns_list.len());

    w.encode_gauge(
        "sns_wasm_number_of_deployed_sns",
        number_of_deployed_sns as f64,
        "The number of SNSes that SNS-WASM has deployed",
    )?;

    w.encode_gauge(
        "sns_wasm_stable_memory_size_bytes",
        ic_nervous_system_common::stable_memory_size_bytes() as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "sns_wasm_total_memory_size_bytes",
        ic_nervous_system_common::total_memory_size_bytes() as f64,
        "Size of the total memory allocated by this canister measured in bytes.",
    )?;

    Ok(())
}

fn serve_metrics_service_discovery() -> HttpResponse {
    let service_discovery = SNS_WASM.with_borrow(SnsWasmCanister::get_metrics_service_discovery);
    HttpResponseBuilder::ok()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .with_body_and_content_length(service_discovery.as_bytes())
        .build()
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/sns_canisters" => serve_metrics_service_discovery(),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
