use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{
    api::{caller, Funds},
    over, over_async, over_init,
};
use ic_base_types::{PrincipalId, SubnetId};
use ic_management_canister_types::{
    CanisterInstallMode::Install, CanisterSettingsArgsBuilder, CreateCanisterArgs, InstallCodeArgs,
    Method, UpdateSettingsArgs,
};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{canister_status, CanisterStatusResultV2, CanisterStatusType},
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_constants::{DEFAULT_SNS_FRAMEWORK_CANISTER_WASM_MEMORY_LIMIT, GOVERNANCE_CANISTER_ID};
use ic_nns_handler_root_interface::client::NnsRootCanisterClientImpl;
use ic_sns_wasm::{
    canister_api::CanisterApi,
    canister_stable_memory::CanisterStableMemory,
    init::SnsWasmCanisterInitPayload,
    pb::v1::{
        update_allowed_principals_response::UpdateAllowedPrincipalsResult, AddWasmRequest,
        AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse, GetAllowedPrincipalsRequest,
        GetAllowedPrincipalsResponse, GetDeployedSnsByProposalIdRequest,
        GetDeployedSnsByProposalIdResponse, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
        GetProposalIdThatAddedWasmRequest, GetProposalIdThatAddedWasmResponse,
        GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse, GetWasmMetadataRequest,
        GetWasmMetadataResponse, GetWasmRequest, GetWasmResponse, InsertUpgradePathEntriesRequest,
        InsertUpgradePathEntriesResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
        ListUpgradeStepsRequest, ListUpgradeStepsResponse, SnsWasmError,
        UpdateAllowedPrincipalsRequest, UpdateAllowedPrincipalsResponse,
        UpdateSnsSubnetListRequest, UpdateSnsSubnetListResponse,
    },
    sns_wasm::SnsWasmCanister,
};
use ic_types::{CanisterId, Cycles};
use std::{cell::RefCell, collections::HashMap, convert::TryInto};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

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
        dfn_core::api::id()
    }

    /// See CanisterApi::create_canister
    async fn create_canister(
        &self,
        target_subnet: SubnetId,
        controller_id: PrincipalId,
        cycles: Cycles,
    ) -> Result<CanisterId, String> {
        let result: Result<CanisterIdRecord, _> = dfn_core::api::call_with_funds_and_cleanup(
            target_subnet.into(),
            &Method::CreateCanister.to_string(),
            candid_one,
            CreateCanisterArgs {
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![controller_id])
                        .with_wasm_memory_limit(DEFAULT_SNS_FRAMEWORK_CANISTER_WASM_MEMORY_LIMIT)
                        .build(),
                ),
                sender_canister_version: Some(dfn_core::api::canister_version()),
            },
            Funds::new(cycles.get().try_into().unwrap()),
        )
        .await;

        result
            .map_err(handle_call_error(format!(
                "Creating canister in subnet {} failed",
                target_subnet
            )))
            .map(|record| record.get_canister_id())
    }

    /// See CanisterApi::delete_canister
    async fn delete_canister(&self, canister: CanisterId) -> Result<(), String> {
        // Try to stop the canister first
        self.stop_canister(canister).await?;

        // TODO(NNS1-1524) We need to collect the cycles from the canister before we delete it
        let response: Result<(), (Option<i32>, String)> = dfn_core::call(
            CanisterId::ic_00(),
            "delete_canister",
            candid_one,
            CanisterIdRecord::from(canister),
        )
        .await;

        response.map_err(handle_call_error(format!(
            "Failed to delete canister {}",
            canister
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
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: Some(dfn_core::api::canister_version()),
        };
        let install_res: Result<(), (Option<i32>, String)> = dfn_core::call(
            CanisterId::ic_00(),
            "install_code",
            dfn_candid::candid_multi_arity,
            (install_args,),
        )
        .await;
        install_res.map_err(handle_call_error(format!(
            "Failed to install WASM on canister {}",
            target_canister
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
            sender_canister_version: Some(dfn_core::api::canister_version()),
        };

        let result: Result<(), (Option<i32>, String)> =
            dfn_core::call(CanisterId::ic_00(), "update_settings", candid_one, args).await;

        result.map_err(handle_call_error(format!(
            "Failed to update controllers for canister {}",
            canister
        )))
    }

    fn this_canister_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
        let available = dfn_core::api::canister_cycle_balance();

        if available < required_cycles {
            return Err(format!(
                "Message execution requires at least {} cycles, but canister only has {} cycles.",
                required_cycles, available,
            ));
        }
        Ok(available)
    }

    fn message_has_enough_cycles(&self, required_cycles: u64) -> Result<u64, String> {
        let available = dfn_core::api::msg_cycles_available();

        if available < required_cycles {
            return Err(format!(
                "Message execution requires at least {} cycles, but only {} cycles were sent.",
                required_cycles, available,
            ));
        }
        Ok(available)
    }

    fn accept_message_cycles(&self, cycles: Option<u64>) -> Result<u64, String> {
        let cycles = cycles.unwrap_or_else(dfn_core::api::msg_cycles_available);
        self.message_has_enough_cycles(cycles)?;

        let accepted = dfn_core::api::msg_cycles_accept(cycles);
        Ok(accepted)
    }

    async fn send_cycles_to_canister(&self, target: CanisterId, cycles: u64) -> Result<(), String> {
        let response: Result<(), (Option<i32>, String)> = dfn_core::api::call_with_funds(
            CanisterId::ic_00(),
            "deposit_cycles",
            candid_one,
            CanisterIdRecord::from(target),
            Funds::new(cycles),
        )
        .await;

        response.map_err(handle_call_error(format!(
            "Failed to send cycles to canister {}",
            target
        )))
    }
}

/// This handles the errors returned from dfn_core::call (and related methods)
fn handle_call_error(prefix: String) -> impl FnOnce((Option<i32>, String)) -> String {
    move |(code, msg)| {
        let err = format!(
            "{}: {}{}",
            prefix,
            code.map(|c| format!("error code {}: ", c))
                .unwrap_or_default(),
            msg
        );
        println!("{}{}", LOG_PREFIX, err);
        err
    }
}

impl CanisterApiImpl {
    async fn stop_canister(&self, canister: CanisterId) -> Result<(), String> {
        dfn_core::call(
            CanisterId::ic_00(),
            "stop_canister",
            candid_one,
            CanisterIdRecord::from(canister),
        )
        .await
        .map_err(|(code, msg)| {
            format!(
                "{}{}",
                code.map(|c| format!("Unable to stop target canister: error code {}: ", c))
                    .unwrap_or_default(),
                msg
            )
        })?;

        let mut count = 0;
        // Wait until canister is in the stopped state.
        loop {
            let status: CanisterStatusResultV2 =
                canister_status::<DfnRuntime>(CanisterIdRecord::from(canister))
                    .await
                    .map(CanisterStatusResultV2::from)
                    .map_err(|(code, msg)| {
                        format!(
                            "Unable to get target canister status: error code {}: {}",
                            code, msg
                        )
                    })?;

            if status.status() == CanisterStatusType::Stopped {
                return Ok(());
            }

            count += 1;
            if count > 100 {
                return Err(format!(
                    "Canister {} never stopped.  Waited 100 iterations",
                    canister
                ));
            }

            println!(
                "{}Still waiting for canister {} to stop. status: {:?}",
                LOG_PREFIX, canister, status
            );
        }
    }
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

/// In contrast to canister_init(), this method does not do deserialization.
/// In addition to canister_init, this method is called by canister_post_upgrade.
#[candid_method(init)]
fn canister_init_(init_payload: SnsWasmCanisterInitPayload) {
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
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    SNS_WASM.with(|c| c.borrow().write_state_to_stable_memory());

    println!("{}Completed pre upgrade", LOG_PREFIX);
}

/// Executes some logic after executing an upgrade, including deserializing what has been written
/// to stable memory in canister_pre_upgrade and initialising the governance's state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);

    SNS_WASM.with(|c| {
        c.replace(SnsWasmCanister::<CanisterStableMemory>::from_stable_memory());
        c.borrow_mut().populate_wasm_metadata();
    });

    println!("{}Completed post upgrade", LOG_PREFIX);
}

#[export_name = "canister_update add_wasm"]
fn add_wasm() {
    over(candid_one, add_wasm_)
}

#[candid_method(update, rename = "add_wasm")]
fn add_wasm_(add_wasm_payload: AddWasmRequest) -> AddWasmResponse {
    let access_controls_enabled =
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow().access_controls_enabled);
    if access_controls_enabled && caller() != GOVERNANCE_CANISTER_ID.into() {
        AddWasmResponse::error("add_wasm can only be called by NNS Governance".into())
    } else {
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().add_wasm(add_wasm_payload))
    }
}

#[export_name = "canister_update insert_upgrade_path_entries"]
fn insert_upgrade_path_entries() {
    over(candid_one, insert_upgrade_path_entries_)
}

#[candid_method(update, rename = "insert_upgrade_path_entries")]
fn insert_upgrade_path_entries_(
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

#[export_name = "canister_query list_upgrade_steps"]
fn list_upgrade_steps() {
    over(candid_one, list_upgrade_steps_)
}

#[candid_method(query, rename = "list_upgrade_steps")]
fn list_upgrade_steps_(payload: ListUpgradeStepsRequest) -> ListUpgradeStepsResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().list_upgrade_steps(payload))
}

#[export_name = "canister_query get_wasm"]
fn get_wasm() {
    over(candid_one, get_wasm_)
}

#[candid_method(query, rename = "get_wasm")]
fn get_wasm_(get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_wasm(get_wasm_payload))
}

#[export_name = "canister_query get_wasm_metadata"]
fn get_wasm_metadata() {
    over(candid_one, get_wasm_metadata_)
}

#[candid_method(query, rename = "get_wasm_metadata")]
fn get_wasm_metadata_(
    get_wasm_metadata_payload: GetWasmMetadataRequest,
) -> GetWasmMetadataResponse {
    SNS_WASM.with(|sns_wasm| {
        sns_wasm
            .borrow()
            .get_wasm_metadata(get_wasm_metadata_payload)
    })
}

#[export_name = "canister_query get_proposal_id_that_added_wasm"]
fn get_proposal_id_that_added_wasm() {
    over(candid_one, get_proposal_id_that_added_wasm_)
}

#[candid_method(query, rename = "get_proposal_id_that_added_wasm")]
fn get_proposal_id_that_added_wasm_(
    get_proposal_id_that_added_wasm_payload: GetProposalIdThatAddedWasmRequest,
) -> GetProposalIdThatAddedWasmResponse {
    SNS_WASM.with(|sns_wasm| {
        sns_wasm
            .borrow()
            .get_proposal_id_that_added_wasm(get_proposal_id_that_added_wasm_payload)
    })
}

#[export_name = "canister_query get_next_sns_version"]
fn get_next_sns_version() {
    over(candid_one, get_next_sns_version_)
}

#[candid_method(query, rename = "get_next_sns_version")]
fn get_next_sns_version_(request: GetNextSnsVersionRequest) -> GetNextSnsVersionResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_next_sns_version(request, caller()))
}

#[export_name = "canister_query get_latest_sns_version_pretty"]
fn get_latest_sns_version_pretty() {
    over(candid_one, get_latest_sns_version_pretty_)
}

#[candid_method(query, rename = "get_latest_sns_version_pretty")]
fn get_latest_sns_version_pretty_(_: ()) -> HashMap<String, String> {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_latest_sns_version_pretty())
}

#[export_name = "canister_update deploy_new_sns"]
fn deploy_new_sns() {
    over_async(candid_one, deploy_new_sns_)
}

#[candid_method(update, rename = "deploy_new_sns")]
async fn deploy_new_sns_(deploy_new_sns: DeployNewSnsRequest) -> DeployNewSnsResponse {
    SnsWasmCanister::deploy_new_sns(
        &SNS_WASM,
        &canister_api(),
        &NnsRootCanisterClientImpl::default(),
        deploy_new_sns,
        caller(),
    )
    .await
}

#[export_name = "canister_query list_deployed_snses"]
fn list_deployed_snses() {
    over(candid_one, list_deployed_snses_)
}

#[candid_method(query, rename = "list_deployed_snses")]
fn list_deployed_snses_(request: ListDeployedSnsesRequest) -> ListDeployedSnsesResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().list_deployed_snses(request))
}

#[export_name = "canister_update update_allowed_principals"]
fn update_allowed_principals() {
    over(candid_one, update_allowed_principals_)
}

#[candid_method(update, rename = "update_allowed_principals")]
fn update_allowed_principals_(
    _: UpdateAllowedPrincipalsRequest,
) -> UpdateAllowedPrincipalsResponse {
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

#[export_name = "canister_query get_allowed_principals"]
fn get_allowed_principals() {
    over(candid_one, get_allowed_principals_)
}

#[candid_method(query, rename = "get_allowed_principals")]
fn get_allowed_principals_(_request: GetAllowedPrincipalsRequest) -> GetAllowedPrincipalsResponse {
    GetAllowedPrincipalsResponse {
        allowed_principals: vec![],
    }
}

/// Add or remove SNS subnet IDs from the list of subnet IDs that SNS instances will be deployed to
#[export_name = "canister_update update_sns_subnet_list"]
fn update_sns_subnet_list() {
    over(candid_one, update_sns_subnet_list_)
}

#[candid_method(update, rename = "update_sns_subnet_list")]
fn update_sns_subnet_list_(request: UpdateSnsSubnetListRequest) -> UpdateSnsSubnetListResponse {
    if caller() != GOVERNANCE_CANISTER_ID.into() {
        UpdateSnsSubnetListResponse::error(
            "update_sns_subnet_list can only be called by NNS Governance",
        )
    } else {
        SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().update_sns_subnet_list(request))
    }
}

/// Return the list of SNS subnet IDs that SNS-WASM will deploy SNS instances to
#[export_name = "canister_query get_sns_subnet_ids"]
fn get_sns_subnet_ids() {
    over(candid_one, get_sns_subnet_ids_)
}

#[candid_method(query, rename = "get_sns_subnet_ids")]
fn get_sns_subnet_ids_(_request: GetSnsSubnetIdsRequest) -> GetSnsSubnetIdsResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_sns_subnet_ids())
}

#[export_name = "canister_query get_deployed_sns_by_proposal_id"]
fn get_deployed_sns_by_proposal_id() {
    over(candid_one, get_deployed_sns_by_proposal_id_)
}

#[candid_method(query, rename = "get_deployed_sns_by_proposal_id")]
fn get_deployed_sns_by_proposal_id_(
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

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

/// Deprecated: The blessed way to get this information is to do (the equivalent
/// of) `dfx canister metadata $CANISTER 'candid:service'`.
///
/// This makes this Candid service self-describing, so that for example Candid
/// UI, but also other tools, can seamlessly integrate with it.
/// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
/// works.
///
/// We include the .did file as committed, which means it is included verbatim in
/// the .wasm; using `candid::export_service` here would involve unnecessary
/// runtime computation.
#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn expose_candid() {
    over(candid, |_: ()| include_str!("sns-wasm.did").to_string())
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod, this MUST occur at the end.
#[cfg(test)]
mod tests;
