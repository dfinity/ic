use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use dfn_core::{over, over_async, over_init};
use ic_base_types::{PrincipalId, SubnetId};
use ic_ic00_types::{CanisterIdRecord, CanisterSettingsArgs, CreateCanisterArgs, Method};
use ic_sns_wasm::canister_api::CanisterApi;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasm, AddWasmResponse, DeployNewSns, DeployNewSnsResponse, GetWasm, GetWasmResponse,
    ListDeployedSnses, ListDeployedSnsesResponse,
};
use ic_sns_wasm::sns_wasm::SnsWasmCanister;
use ic_types::{CanisterId, Cycles};
use std::cell::RefCell;
use std::convert::TryInto;

pub const LOG_PREFIX: &str = "[SNS-WASM] ";

thread_local! {
  static SNS_WASM: RefCell<SnsWasmCanister> = RefCell::new(SnsWasmCanister::new());
}

// TODO possibly determine how to make a single static that is thread-safe?
fn canister_api() -> CanisterApiImpl {
    CanisterApiImpl {}
}

#[derive()]
struct CanisterApiImpl {}

#[async_trait]
impl CanisterApi for CanisterApiImpl {
    fn local_canister_id(&self) -> CanisterId {
        dfn_core::api::id()
    }

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

        match result {
            Ok(canister_id) => Ok(canister_id.get_canister_id()),
            Err((code, msg)) => {
                let err = format!(
                    "Creating canister in subnet {} failed with code {}: {}",
                    target_subnet,
                    code.unwrap_or_default(),
                    msg
                );
                println!("{}{}", LOG_PREFIX, err);
                Err(err)
            }
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
fn canister_init_(_init_payload: SnsWasmCanisterInitPayload) {
    println!("{}canister_init_", LOG_PREFIX);
    SNS_WASM.with(|c| c.borrow_mut().set_sns_subnets(_init_payload.sns_subnet_ids))
}

/// Executes some logic before executing an upgrade, including serializing and writing the
/// governance's state to stable memory so that it is preserved during the upgrade and can
/// be deserialized again in canister_post_upgrade. That is, the stable memory allows
/// saving the state and restoring it after the upgrade.
#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);
    println!("{}Completed pre upgrade", LOG_PREFIX);
}

/// Executes some logic after executing an upgrade, including deserializing what has been written
/// to stable memory in canister_pre_upgrade and initialising the governance's state with it.
#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);
    println!("{}Completed post upgrade", LOG_PREFIX);
}

#[export_name = "canister_update add_wasm"]
fn add_wasm() {
    over(candid_one, add_wasm_)
}

#[candid_method(update, rename = "add_wasm")]
fn add_wasm_(add_wasm_payload: AddWasm) -> AddWasmResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow_mut().add_wasm(add_wasm_payload))
}

#[export_name = "canister_query get_wasm"]
fn get_wasm() {
    over(candid_one, get_wasm_)
}

#[candid_method(query, rename = "get_wasm")]
fn get_wasm_(get_wasm_payload: GetWasm) -> GetWasmResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().get_wasm(get_wasm_payload))
}

#[export_name = "canister_update deploy_new_sns"]
fn deploy_new_sns() {
    over_async(candid_one, deploy_new_sns_)
}

#[candid_method(update, rename = "deploy_new_sns")]
async fn deploy_new_sns_(deploy_new_sns: DeployNewSns) -> DeployNewSnsResponse {
    SnsWasmCanister::deploy_new_sns(&SNS_WASM, &canister_api(), deploy_new_sns).await
}

#[export_name = "canister_query list_deployed_snses"]
fn list_deployed_snses() {
    over(candid_one, list_deployed_snses_)
}

#[candid_method(query, rename = "list_deployed_snses")]
fn list_deployed_snses_(request: ListDeployedSnses) -> ListDeployedSnsesResponse {
    SNS_WASM.with(|sns_wasm| sns_wasm.borrow().list_deployed_snses(request))
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
    let governance_did =
        String::from_utf8(std::fs::read("canister/sns-wasm.did").unwrap()).unwrap();

    // See comments in main above
    candid::export_service!();
    let expected = __export_service();

    if governance_did != expected {
        panic!(
            "Generated candid definition does not match canister/sns-wasm.did. \
            Run `cargo run --bin sns-wasm-canister > canister/sns-wasm.did` in \
            rs/nns/sns-wasm to update canister/sns-wasm.did."
        )
    }
}
