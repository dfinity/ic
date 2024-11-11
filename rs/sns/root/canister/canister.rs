use async_trait::async_trait;
use candid::candid_method;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::println;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
    management_canister_client::ManagementCanisterClientImpl,
};
use ic_nervous_system_common::{
    dfn_core_stable_mem_utils::{BufferedStableMemReader, BufferedStableMemWriter},
    serve_logs, serve_logs_v2, serve_metrics, NANO_SECONDS_PER_SECOND,
};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_sns_root::{
    logs::{ERROR, INFO},
    pb::v1::{
        CanisterCallError, ListSnsCanistersRequest, ListSnsCanistersResponse,
        ManageDappCanisterSettingsRequest, ManageDappCanisterSettingsResponse,
        RegisterDappCanisterRequest, RegisterDappCanisterResponse, RegisterDappCanistersRequest,
        RegisterDappCanistersResponse, SetDappControllersRequest, SetDappControllersResponse,
        SnsRootCanister,
    },
    types::Environment,
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse, LedgerCanisterClient,
};
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use prost::Message;
use std::{cell::RefCell, time::Duration};

type CanisterRuntime = CdkRuntime;
const STABLE_MEM_BUFFER_SIZE: u32 = 100 * 1024 * 1024; // 100MiB
const POLL_FOR_NEW_ARCHIVES_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24); // one day

thread_local! {
    static STATE: RefCell<SnsRootCanister> = RefCell::new(Default::default());
}

struct CanisterEnvironment {}

#[async_trait]
impl Environment for CanisterEnvironment {
    fn now(&self) -> u64 {
        ic_cdk::api::time() / NANO_SECONDS_PER_SECOND
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, (i32, String)> {
        CanisterRuntime::call_bytes_with_cleanup(canister_id, method_name, &arg).await
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
    async fn archives(&self) -> Result<Vec<ArchiveInfo>, CanisterCallError> {
        CanisterRuntime::call_with_cleanup(self.ledger_canister_id, "archives", ())
            .await
            .map(|(archives,): (Vec<ArchiveInfo>,)| archives)
            .map_err(CanisterCallError::from)
    }
}

/// Create a RealLedgerCanisterClient with ledger_canister_id from STATE.
fn create_ledger_client() -> RealLedgerCanisterClient {
    let ledger_canister_id = STATE
        .with(|state| state.borrow().ledger_canister_id())
        .try_into()
        .expect("Expected the ledger_canister_id to be convertible to a CanisterId");

    RealLedgerCanisterClient::new(ledger_canister_id)
}

#[candid_method(init)]
#[init]
fn init(args: SnsRootCanister) {
    canister_init(args);
}

fn canister_init(init_payload: SnsRootCanister) {
    log!(INFO, "canister_init: Begin...");

    assert_state_is_valid(&init_payload);

    STATE.with(move |state| {
        let mut state = state.borrow_mut();
        *state = init_payload;
    });

    init_timers();

    log!(INFO, "canister_init: Done!");
}

#[pre_upgrade]
fn canister_pre_upgrade() {
    log!(INFO, "canister_pre_upgrade: Begin...");

    STATE.with(move |state| {
        let mut writer = BufferedStableMemWriter::new(STABLE_MEM_BUFFER_SIZE);
        let state = state.borrow();
        state
            .encode(&mut writer)
            .expect("Error. Couldn't serialize canister pre-upgrade.");
        writer.flush();
    });

    log!(INFO, "canister_pre_upgrade: Done!");
}

#[post_upgrade]
fn canister_post_upgrade() {
    log!(INFO, "canister_POST_upgrade: Begin...");

    let reader = BufferedStableMemReader::new(STABLE_MEM_BUFFER_SIZE);

    let state = SnsRootCanister::decode(reader).expect(
        "Couldn't upgrade canister, due to state deserialization \
         failure during post-upgrade.",
    );
    canister_init(state);

    log!(INFO, "canister_post_upgrade: Done!");
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

#[candid_method(update)]
#[update]
async fn canister_status(id: CanisterIdRecord) -> CanisterStatusResult {
    log!(INFO, "canister_status");
    ic_nervous_system_clients::canister_status::canister_status::<CanisterRuntime>(id)
        .await
        .map(CanisterStatusResult::from)
        .unwrap()
}

/// Return the canister status of all SNS canisters that this root canister
/// is part of, as well as of all registered dapp canisters (See
/// SnsRootCanister::register_dapp_canister).
#[candid_method(update)]
#[update]
async fn get_sns_canisters_summary(
    request: GetSnsCanistersSummaryRequest,
) -> GetSnsCanistersSummaryResponse {
    log!(INFO, "get_sns_canisters_summary");
    let update_canister_list = request.update_canister_list.unwrap_or(false);
    // Only governance can set this parameter to true
    if update_canister_list {
        assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));
    }

    let canister_env = CanisterEnvironment {};
    SnsRootCanister::get_sns_canisters_summary(
        &STATE,
        &ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        &create_ledger_client(),
        &canister_env,
        update_canister_list,
        PrincipalId(ic_cdk::api::id()),
    )
    .await
}

/// Return the `PrincipalId`s of all SNS canisters that this root canister
/// is part of, as well as of all registered dapp canisters (See
/// SnsRootCanister::register_dapp_canister).
#[candid_method(query)]
#[query]
fn list_sns_canisters(_request: ListSnsCanistersRequest) -> ListSnsCanistersResponse {
    log!(INFO, "list_sns_canisters");
    STATE.with(|sns_root_canister| {
        sns_root_canister
            .borrow()
            .list_sns_canisters(ic_cdk::api::id())
    })
}

/// This function will return immediately, and the actual upgrade will be performed in the background.
#[candid_method(update)]
#[update]
fn change_canister(request: ChangeCanisterRequest) {
    log!(INFO, "change_canister");
    assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));

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
    CanisterRuntime::spawn_future(async move {
        let change_canister_result =
            ic_nervous_system_root::change_canister::change_canister::<CanisterRuntime>(request)
                .await;
        // We don't want to panic in here, or the log messages will be lost when
        // the state rolls back.
        match change_canister_result {
            Ok(()) => {
                log!(
                    INFO,
                    "change_canister: Canister change completed successfully."
                );
            }
            Err(err) => {
                log!(ERROR, "change_canister: Canister change failed: {err}");
            }
        };
    });
}

/// This function is deprecated, and `register_dapp_canisters` should be used
/// instead. (NNS1-1991)
///
/// Tells this canister (SNS root) about a list of dapp canister that it controls.
///
/// The canisters must not be one of the distinguished SNS canisters
/// (i.e. root, governance, ledger). Furthermore, the canisters must be
/// controlled by this canister (i.e. SNS root). Otherwise, the request will be
/// rejected.
///
/// If there are any controllers on the canister besides root, they will be
/// removed.
///
/// Registered dapp canisters are used by at least two methods:
///   1. get_sns_canisters_summary
///   2. set_dapp_controllers.
#[candid_method(update)]
#[update]
async fn register_dapp_canister(
    request: RegisterDappCanisterRequest,
) -> RegisterDappCanisterResponse {
    log!(INFO, "register_dapp_canister");
    assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));
    let request = RegisterDappCanistersRequest {
        canister_ids: request.canister_id.into_iter().collect(),
    };
    let RegisterDappCanistersResponse {} = SnsRootCanister::register_dapp_canisters(
        &STATE,
        &ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        ic_cdk::api::id(),
        request,
    )
    .await;
    RegisterDappCanisterResponse {}
}

/// Tells this canister (SNS root) about a list of dapp canister that it controls.
///
/// The canisters must not be one of the distinguished SNS canisters
/// (i.e. root, governance, ledger). Furthermore, the canisters must be
/// exclusively be controlled by this canister (i.e. SNS root). Otherwise,
/// the request will be rejected.
///
/// Registered dapp canisters are used by at least two methods:
///   1. get_sns_canisters_summary
///   2. set_dapp_controllers.
#[candid_method(update)]
#[update]
async fn register_dapp_canisters(
    request: RegisterDappCanistersRequest,
) -> RegisterDappCanistersResponse {
    log!(INFO, "register_dapp_canisters");
    assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));
    SnsRootCanister::register_dapp_canisters(
        &STATE,
        &ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        ic_cdk::api::id(),
        request,
    )
    .await
}

/// Sets the controllers of registered dapp canisters.
///
/// Dapp canisters can be registered via the register_dapp_canisters method.
///
/// Caller must be the Governance or Sale canister. Otherwise, the request will
/// be rejected.
///
/// Registered dapp canisters must not have disappeared prior to this being
/// called. Otherwise, request will be rejected. Some precautions are taken
/// to avoid a partially completed operation, but this cannot be guaranteed.
///
/// If `request.canister_ids` is `None`, controllers of all registered dapps
/// will be set. This may lead to confusing behavior if a new controller is
/// added after the message is sent but before it is processed. This
/// functionality may be removed in the future: see NNS1-1989. Only the Sale
/// canister can use this functionality.
#[candid_method(update)]
#[update]
async fn set_dapp_controllers(request: SetDappControllersRequest) -> SetDappControllersResponse {
    log!(INFO, "set_dapp_controllers");
    SnsRootCanister::set_dapp_controllers(
        &STATE,
        &ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        ic_cdk::api::id(),
        PrincipalId(ic_cdk::api::caller()),
        &request,
    )
    .await
}

#[candid_method(update)]
#[update]
async fn manage_dapp_canister_settings(
    request: ManageDappCanisterSettingsRequest,
) -> ManageDappCanisterSettingsResponse {
    log!(INFO, "manage_dapp_canister_settings");
    assert_eq_governance_canister_id(PrincipalId(ic_cdk::api::caller()));

    STATE.with_borrow(|state| {
        state.manage_dapp_canister_settings(
            request,
            ManagementCanisterClientImpl::<CanisterRuntime>::new(None),
        )
    })
}

fn assert_state_is_valid(state: &SnsRootCanister) {
    assert!(state.governance_canister_id.is_some());
    assert!(state.ledger_canister_id.is_some());
    assert!(state.swap_canister_id.is_some());
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

// Resources to serve for a given http_request
#[query(hidden = true, decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs_v2(request, &INFO, &ERROR),

        // These are obsolete.
        "/log/info" => serve_logs(&INFO),
        "/log/error" => serve_logs(&ERROR),

        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn init_timers() {
    ic_cdk_timers::set_timer_interval(POLL_FOR_NEW_ARCHIVES_INTERVAL, || {
        ic_cdk::spawn(poll_for_new_archive_canisters())
    });
}

async fn poll_for_new_archive_canisters() {
    let ledger_client = create_ledger_client();
    SnsRootCanister::poll_for_new_archive_canisters(&STATE, &ledger_client).await
}

/// Encode the metrics in a format that can be understood by Prometheus.
fn encode_metrics(_w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    Ok(())
}

/// This makes this Candid service self-describing, so that for example Candid
/// UI, but also other tools, can seamlessly integrate with it.
/// The concrete interface (__get_candid_interface_tmp_hack) is provisional, but
/// works.
///
/// We include the .did file as committed, which means it is included verbatim in
/// the .wasm; using `candid::export_service` here would involve unnecessary
/// runtime computation.
#[query(hidden = true)]
fn __get_candid_interface_tmp_hack() -> String {
    include_str!("root.did").to_string()
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
