use std::cell::RefCell;
use std::time::SystemTime;

use async_trait::async_trait;
use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{api::now, call, over, over_async, over_init};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::stable_mem_utils::{
    BufferedStableMemReader, BufferedStableMemWriter,
};
use ic_nervous_system_root::{ChangeCanisterProposal, LOG_PREFIX};
use ic_sns_root::{
    pb::v1::{
        CanisterCallError, ListSnsCanistersRequest, ListSnsCanistersResponse,
        RegisterDappCanisterRequest, RegisterDappCanisterResponse, SetDappControllersRequest,
        SetDappControllersResponse, SnsRootCanister,
    },
    CanisterIdRecord, CanisterStatusResultV2, EmptyBlob, GetSnsCanistersSummaryRequest,
    GetSnsCanistersSummaryResponse, LedgerCanisterClient, ManagementCanisterClient,
    UpdateSettingsArgs,
};

use dfn_core::api::{call_bytes_with_cleanup, Funds};
use prost::Message;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_ic00_types::IC_00;
use ic_icrc1::endpoints::ArchiveInfo;
use ic_sns_root::types::Environment;

const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB

/// An implementation of the ManagementCanisterClient trait that is suitable for
/// production use.
struct RealManagementCanisterClient {}

impl RealManagementCanisterClient {
    fn new() -> Self {
        Self {}
    }
}

struct CanisterEnvironment {}

#[async_trait]
impl Environment for CanisterEnvironment {
    fn now(&self) -> u64 {
        now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get the duration")
            .as_secs()
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        call_bytes_with_cleanup(canister_id, method_name, &arg, Funds::zero()).await
    }

    fn canister_id(&self) -> CanisterId {
        dfn_core::api::id()
    }
}

#[async_trait]
impl ManagementCanisterClient for RealManagementCanisterClient {
    async fn canister_status(
        &mut self,
        canister_id_record: &CanisterIdRecord,
    ) -> Result<CanisterStatusResultV2, CanisterCallError> {
        call(IC_00, "canister_status", candid_one, canister_id_record)
            .await
            .map_err(CanisterCallError::from)
    }

    async fn update_settings(
        &mut self,
        request: &UpdateSettingsArgs,
    ) -> Result<EmptyBlob, CanisterCallError> {
        call(IC_00, "update_settings", candid_one, request)
            .await
            .map_err(CanisterCallError::from)
    }
}

/// An implementation of the LedgerCanisterClient trait that is suitable for
/// production use.
struct RealLedgerCanisterClient {
    ledger_canister_id: CanisterId,
}

impl RealLedgerCanisterClient {
    fn new(ledger_canister_id: CanisterId) -> Self {
        Self { ledger_canister_id }
    }
}

#[async_trait]
impl LedgerCanisterClient for RealLedgerCanisterClient {
    async fn archives(&mut self) -> Result<Vec<ArchiveInfo>, CanisterCallError> {
        call(self.ledger_canister_id, "archives", candid_one, ())
            .await
            .map_err(CanisterCallError::from)
    }
}

/// Create a RealLedgerCanisterClient with ledger_canister_id from STATE.
fn create_ledger_client() -> RealLedgerCanisterClient {
    let ledger_canister_id = STATE
        .with(|state| state.borrow().ledger_canister_id())
        .try_into()
        .expect("Expected the ledger_canister_id to be convertable to a CanisterId");

    RealLedgerCanisterClient::new(ledger_canister_id)
}

thread_local! {
    static STATE: RefCell<SnsRootCanister> = RefCell::new(Default::default());
}

#[export_name = "canister_init"]
fn canister_init() {
    over_init(|CandidOne(arg)| canister_init_(arg))
}

#[candid_method(init)]
fn canister_init_(init_payload: SnsRootCanister) {
    dfn_core::printer::hook();
    println!("{}canister_init: Begin...", LOG_PREFIX);

    assert_state_is_valid(&init_payload);

    STATE.with(move |state| {
        let mut state = state.borrow_mut();
        *state = init_payload;
    });

    println!("{}canister_init: Done!", LOG_PREFIX);
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_pre_upgrade: Begin...", LOG_PREFIX);

    STATE.with(move |state| {
        let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);
        let state = state.borrow();
        state
            .encode(&mut writer)
            .expect("Error. Couldn't serialize canister pre-upgrade.");
        writer.flush();
    });

    println!("{}canister_pre_upgrade: Done!", LOG_PREFIX);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_POST_upgrade: Begin...", LOG_PREFIX);

    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);

    let state = SnsRootCanister::decode(reader).expect(
        "Couldn't upgrade canister, due to state deserialization \
         failure during post-upgrade.",
    );
    canister_init_(state);

    println!("{}canister_post_upgrade: Done!", LOG_PREFIX);
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

#[export_name = "canister_update canister_status"]
fn canister_status() {
    println!("{}canister_status", LOG_PREFIX);
    over_async(candid_one, canister_status_);
}

#[candid_method(update, rename = "canister_status")]
async fn canister_status_(
    id: ic_nervous_system_root::CanisterIdRecord,
) -> ic_nervous_system_root::CanisterStatusResult {
    ic_nervous_system_root::canister_status(id).await
}

/// Return the canister status of all SNS canisters that this root canister
/// is part of, as well as of all registered dapp canisters (See
/// SnsRootCanister::register_dapp_canister).
#[export_name = "canister_update get_sns_canisters_summary"]
fn get_sns_canisters_summary() {
    println!("{}get_sns_canisters_summary", LOG_PREFIX);
    over_async(candid_one, get_sns_canisters_summary_)
}

#[candid_method(update, rename = "get_sns_canisters_summary")]
async fn get_sns_canisters_summary_(
    request: GetSnsCanistersSummaryRequest,
) -> GetSnsCanistersSummaryResponse {
    let update_canister_list = request.update_canister_list.unwrap_or(false);
    // Only governance can set this parameter to true
    if update_canister_list {
        assert_eq_governance_canister_id(dfn_core::api::caller());
    }

    let canister_env = CanisterEnvironment {};
    SnsRootCanister::get_sns_canisters_summary(
        &STATE,
        &mut RealManagementCanisterClient::new(),
        &mut create_ledger_client(),
        &canister_env,
        update_canister_list,
    )
    .await
}

/// Return the `PrincipalId`s of all SNS canisters that this root canister
/// is part of, as well as of all registered dapp canisters (See
/// SnsRootCanister::register_dapp_canister).
#[export_name = "canister_query list_sns_canisters"]
fn list_sns_canisters() {
    println!("{}list_sns_canisters", LOG_PREFIX);
    over(candid_one, list_sns_canisters_)
}

#[candid_method(query, rename = "list_sns_canisters")]
fn list_sns_canisters_(_request: ListSnsCanistersRequest) -> ListSnsCanistersResponse {
    STATE.with(|sns_root_canister| {
        sns_root_canister
            .borrow()
            .list_sns_canisters(dfn_core::api::id())
    })
}

#[export_name = "canister_update change_canister"]
fn change_canister() {
    println!("{}change_canister", LOG_PREFIX);
    assert_eq_governance_canister_id(dfn_core::api::caller());

    // We do not want the reply to the Candid change_canister method call to be
    // blocked on performing the canister change, because that could cause a
    // deadlock. Specifically, deadlock would occur when upgrading governance,
    // because one of the steps that we (root) would take when trying to upgrade
    // governance is wait for governance to reach the "stopped" state, but that
    // transition will never take place while the current Candid change_canister
    // method call is outstanding.
    //
    // The reply should then be considered merely an acknowledgement that the
    // command has been accepted and will be executed, but has not actually
    // completed yet. This is pretty unusual for Candid method calls.
    //
    // To implement "acknowledge without actually completing the work", we use
    // spawn to do the real work in the background.
    over(candid_one, |proposal: ChangeCanisterProposal| {
        assert_change_canister_proposal_is_valid(&proposal);
        dfn_core::api::futures::spawn(ic_nervous_system_root::change_canister(proposal));
    });
}

/// Tells this canister (SNS root) about a dapp canister that it controls.
///
/// The canister must not be one of the distinguished SNS canisters
/// (i.e. root, governance, ledger). Furthermore, the canister must be
/// exclusively be controlled by this canister (i.e. SNS root). Otherwise,
/// the request will be rejected.
///
/// Registered dapp canisters are used by at least two methods:
///   1. get_sns_canisters_summary
///   2. set_dapp_controllers (currently in review).
#[export_name = "canister_update register_dapp_canister"]
fn register_dapp_canister() {
    println!("{}register_dapp_canister", LOG_PREFIX);
    over_async(candid_one, register_dapp_canister_);
}

#[candid_method(update, rename = "register_dapp_canister")]
async fn register_dapp_canister_(
    request: RegisterDappCanisterRequest,
) -> RegisterDappCanisterResponse {
    SnsRootCanister::register_dapp_canister(
        &STATE,
        &mut RealManagementCanisterClient::new(),
        dfn_core::api::id(),
        request,
    )
    .await
}

/// Sets the controllers of registered dapp canisters.
///
/// Dapp canisters can be registered via the register_dapp_canister method.
///
/// Caller must be the swap canister. Otherwise, the request will be
/// rejected.
///
/// Registered dapp canisters must not have disappeared prior to this being
/// called. Otherwise, request will be rejected. Some precautions are taken
/// to avoid a partially completed operation, but this cannot be guaranteed.
#[export_name = "canister_update set_dapp_controllers"]
fn set_dapp_controllers() {
    println!("{}set_dapp_controllers", LOG_PREFIX);
    over_async(candid_one, set_dapp_controllers_);
}

#[candid_method(update, rename = "set_dapp_controllers")]
async fn set_dapp_controllers_(request: SetDappControllersRequest) -> SetDappControllersResponse {
    SnsRootCanister::set_dapp_controllers(
        &STATE,
        &mut RealManagementCanisterClient::new(),
        dfn_core::api::id(),
        dfn_core::api::caller(),
        &request,
    )
    .await
}

fn assert_state_is_valid(state: &SnsRootCanister) {
    assert!(state.governance_canister_id.is_some());
    assert!(state.ledger_canister_id.is_some());
    assert!(state.swap_canister_id.is_some());
}

fn assert_change_canister_proposal_is_valid(proposal: &ChangeCanisterProposal) {
    assert!(
        proposal.authz_changes.is_empty(),
        "Invalid ChangeCanisterProposal: the authz_changes field is not supported \
         and should be left empty, but was not. proposal: {:?}",
        proposal
    );
}

fn assert_eq_governance_canister_id(id: PrincipalId) {
    STATE.with(|state: &RefCell<SnsRootCanister>| {
        let state = state.borrow();
        let governance_canister_id = state
            .governance_canister_id
            .expect("STATE.governance_canister_id is not populated");
        assert_eq!(id, governance_canister_id);
    });
}

/// The canister's heartbeat.
#[export_name = "canister_heartbeat"]
fn canister_heartbeat() {
    let future = canister_heartbeat_();

    // The canister_heartbeat must be synchronous, so it cannot .await the future.
    dfn_core::api::futures::spawn(future);
}

/// Asynchronous method called for the canister_heartbeat that injects dependencies
/// to run_periodic_tasks.
async fn canister_heartbeat_() {
    let now = CanisterEnvironment {}.now();
    let mut ledger_client = create_ledger_client();

    SnsRootCanister::run_periodic_tasks(&STATE, &mut ledger_client, now).await
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
    over(candid, |_: ()| include_str!("root.did").to_string())
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_nervous_system_common::MethodAuthzChange;

    /// A test that fails if the API was updated but the candid definition was not.
    #[test]
    fn check_candid_interface_definition_file() {
        let did_path = std::path::PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined"),
        )
        .join("canister/root.did");

        let did_contents = String::from_utf8(std::fs::read(&did_path).unwrap()).unwrap();

        // See comments in main above
        candid::export_service!();
        let expected = __export_service();

        if did_contents != expected {
            panic!(
                "Generated candid definition does not match canister/root.did. \
                 Run `bazel run :generate_did > canister/root.did` (no nix and/or direnv) or \
                 `cargo run --bin sns-root-canister > canister/root.did` in \
                 rs/sns/root to update canister/root.did."
            )
        }
    }

    #[test]
    #[should_panic]
    fn no_authz() {
        let canister_id = dfn_core::api::CanisterId::from(1);

        let mut proposal = ChangeCanisterProposal::new(
            false, // stop before_installing
            ic_ic00_types::CanisterInstallMode::Upgrade,
            canister_id,
        );

        proposal.authz_changes.push(MethodAuthzChange {
            canister: canister_id,
            method_name: "foo".to_string(),
            principal: None,
            operation: ic_nervous_system_common::AuthzChangeOp::Deauthorize,
        });

        // This should panic.
        assert_change_canister_proposal_is_valid(&proposal);
    }
}
