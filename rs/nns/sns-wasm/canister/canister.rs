use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::api::{caller, Funds};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::{over, over_async, over_init};
use ic_base_types::{PrincipalId, SubnetId};
use ic_ic00_types::CanisterInstallMode::Install;
use ic_ic00_types::{
    CanisterIdRecord, CanisterSettingsArgs, CanisterStatusResultV2, CanisterStatusType,
    CreateCanisterArgs, InstallCodeArgs, Method, UpdateSettingsArgs,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_sns_wasm::canister_api::CanisterApi;
use ic_sns_wasm::canister_stable_memory::CanisterStableMemory;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetAllowedPrincipalsRequest, GetAllowedPrincipalsResponse, GetNextSnsVersionRequest,
    GetNextSnsVersionResponse, GetSnsSubnetIdsRequest, GetSnsSubnetIdsResponse, GetWasmRequest,
    GetWasmResponse, ListDeployedSnsesRequest, ListDeployedSnsesResponse,
    UpdateAllowedPrincipalsRequest, UpdateAllowedPrincipalsResponse, UpdateSnsSubnetListRequest,
    UpdateSnsSubnetListResponse,
};
use ic_sns_wasm::sns_wasm::SnsWasmCanister;
use ic_types::{CanisterId, Cycles};
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;

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
                settings: Some(CanisterSettingsArgs {
                    controller: Some(controller_id),
                    ..CanisterSettingsArgs::default()
                }),
            },
            dfn_core::api::Funds::new(cycles.get().try_into().unwrap()),
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
            dfn_candid::candid_one,
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
        init_paylaod: Vec<u8>,
    ) -> Result<(), String> {
        let install_args = InstallCodeArgs {
            mode: Install,
            canister_id: target_canister.get(),
            wasm_module: wasm,
            arg: init_paylaod,
            compute_allocation: None,
            memory_allocation: None,
            query_allocation: None,
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
            settings: CanisterSettingsArgs {
                controllers: Some(controllers),
                // Leave everything else alone.
                controller: None,
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
            },
        };

        let result: Result<(), (Option<i32>, String)> =
            dfn_core::call(CanisterId::ic_00(), "update_settings", candid_one, args).await;

        result.map_err(handle_call_error(format!(
            "Failed to update controllers for canister {}",
            canister
        )))
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
            dfn_candid::candid_one,
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
            dfn_candid::candid_one,
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
            let status: CanisterStatusResultV2 = dfn_core::call(
                CanisterId::ic_00(),
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister),
            )
            .await
            .map_err(|(code, msg)| {
                format!(
                    "{}{}",
                    code.map(|c| format!(
                        "Unable to get target canister status: error code {}: ",
                        c
                    ))
                    .unwrap_or_default(),
                    msg
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
    println!("{}canister_init_", LOG_PREFIX);
    SNS_WASM.with(|c| {
        c.borrow_mut().set_sns_subnets(init_payload.sns_subnet_ids);
        c.borrow_mut()
            .set_access_controls_enabled(init_payload.access_controls_enabled);
        c.borrow_mut()
            .set_allowed_principals(init_payload.allowed_principals);
        c.borrow().initialize_stable_memory();
    })
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

    SNS_WASM.with(|c| c.replace(SnsWasmCanister::<CanisterStableMemory>::from_stable_memory()));
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().add_default_allowed_principals());

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

#[export_name = "canister_query get_wasm"]
fn get_wasm() {
    over(candid_one, get_wasm_)
}

#[candid_method(query, rename = "get_wasm")]
fn get_wasm_(get_wasm_payload: GetWasmRequest) -> GetWasmResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_wasm(get_wasm_payload))
}

#[export_name = "canister_query get_next_sns_version"]
fn get_next_sns_version() {
    over(candid_one, get_next_sns_version_)
}

#[candid_method(query, rename = "get_next_sns_version")]
fn get_next_sns_version_(request: GetNextSnsVersionRequest) -> GetNextSnsVersionResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_next_sns_version(request))
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
    SnsWasmCanister::deploy_new_sns(&SNS_WASM, &canister_api(), deploy_new_sns, caller()).await
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
    request: UpdateAllowedPrincipalsRequest,
) -> UpdateAllowedPrincipalsResponse {
    SNS_WASM.with(|sns_wasm| {
        sns_wasm
            .borrow_mut()
            .update_allowed_principals(request, caller())
    })
}

#[export_name = "canister_query get_allowed_principals"]
fn get_allowed_principals() {
    over(candid_one, get_allowed_principals_)
}

#[candid_method(query, rename = "get_allowed_principals")]
fn get_allowed_principals_(_request: GetAllowedPrincipalsRequest) -> GetAllowedPrincipalsResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_allowed_principals())
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

/// When run on native, this prints the candid service definition of this
/// canister, from the methods annotated with `candid_method` above.
///
/// Note that `cargo test` calls `main`, and `export_service` (which defines
/// `__export_service` in the current scope) needs to be called exactly once. So
/// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
/// to avoid calling `export_service`, which we need to call in the test below.
#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

/// A test that fails if the API was updated but the candid definition was not.
#[test]
fn check_wasm_candid_file() {
    let did_path = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined"),
    )
    .join("canister/sns-wasm.did");

    let did_contents = String::from_utf8(std::fs::read(&did_path).unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if did_contents != expected {
        panic!(
            "Generated candid definition does not match canister/sns-wasm.did. \
            Run `bazel run :generate_did > canister/sns-wasm.did` (no nix and/or direnv) or \
            `cargo run --bin sns-wasm-canister > canister/sns-wasm.did` in \
            rs/nns/sns-wasm to update canister/sns-wasm.did."
        )
    }
}
