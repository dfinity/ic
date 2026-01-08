use ic_base_types::{CanisterId, PrincipalId};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::CanisterStatusResult,
    management_canister_client::{
        LimitedOutstandingCallsManagementCanisterClient, ManagementCanisterClient,
        ManagementCanisterClientImpl,
    },
};
use ic_nervous_system_common::serve_metrics;
use ic_nervous_system_root::{
    LOG_PREFIX,
    change_canister::{
        AddCanisterRequest, CanisterAction, ChangeCanisterRequest, StopOrStartCanisterRequest,
        change_canister,
    },
};
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_common::{
    access_control::{check_caller_is_governance, check_caller_is_sns_w},
    types::CallCanisterRequest,
};
use ic_nns_constants::{
    ALL_NNS_CANISTER_IDS, GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_handler_root::{
    PROXIED_CANISTER_CALLS_TRACKER, canister_management, encode_metrics,
    root_proposals::{GovernanceUpgradeRootProposal, RootProposalBallot},
};
use ic_nns_handler_root_interface::{
    ChangeCanisterControllersRequest, ChangeCanisterControllersResponse,
    LoadCanisterSnapshotRequest, LoadCanisterSnapshotResponse, TakeCanisterSnapshotRequest,
    TakeCanisterSnapshotResponse, UpdateCanisterSettingsRequest, UpdateCanisterSettingsResponse,
};
use std::cell::RefCell;

use ic_cdk::futures::spawn_017_compat;
use ic_cdk::println;
use ic_cdk::{init, post_upgrade, query, update};

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::api::msg_caller())
}

thread_local! {
    // How this value was chosen: queues become full at 500. This is 1/3 of that, which seems to be
    // a reasonable balance.
    static AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT: RefCell<u64> = const { RefCell::new(167) };
}

fn new_management_canister_client() -> impl ManagementCanisterClient {
    let client =
        ManagementCanisterClientImpl::<CdkRuntime>::new(Some(&PROXIED_CANISTER_CALLS_TRACKER));

    // Here, VIP = is an NNS canister
    let is_caller_vip = CanisterId::try_from(caller())
        .map(|caller| ALL_NNS_CANISTER_IDS.contains(&&caller))
        .unwrap_or(false);

    LimitedOutstandingCallsManagementCanisterClient::new(
        client,
        &AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT,
        is_caller_vip,
    )
}

#[init]
fn canister_init() {
    println!("{LOG_PREFIX}canister_init");
}

#[post_upgrade]
fn canister_post_upgrade() {
    println!("{LOG_PREFIX}canister_post_upgrade");
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

/// Returns the status of the canister specified in the input.
///
/// The status of NNS canisters should be public information: anyone can get the
/// status of any NNS canister.
///
/// This must be an update, not a query, because an inter-canister call to the
/// management canister is required.
#[update]
async fn canister_status(canister_id_record: CanisterIdRecord) -> CanisterStatusResult {
    let client = new_management_canister_client();

    let canister_status_response = client
        .canister_status(canister_id_record)
        .await
        .map(CanisterStatusResult::from);

    canister_status_response.unwrap()
}

#[update(hidden = true)]
async fn submit_root_proposal_to_upgrade_governance_canister(
    expected_governance_wasm_sha: serde_bytes::ByteBuf,
    proposal: ChangeCanisterRequest,
) -> Result<(), String> {
    ic_nns_handler_root::root_proposals::submit_root_proposal_to_upgrade_governance_canister(
        caller(),
        expected_governance_wasm_sha.to_vec(),
        proposal,
    )
    .await
}

#[update(hidden = true)]
async fn vote_on_root_proposal_to_upgrade_governance_canister(
    proposer: PrincipalId,
    wasm_sha256: serde_bytes::ByteBuf,
    ballot: RootProposalBallot,
) -> Result<(), String> {
    ic_nns_handler_root::root_proposals::vote_on_root_proposal_to_upgrade_governance_canister(
        caller(),
        proposer,
        wasm_sha256.to_vec(),
        ballot,
    )
    .await
}

#[update(hidden = true)]
fn get_pending_root_proposals_to_upgrade_governance_canister() -> Vec<GovernanceUpgradeRootProposal>
{
    ic_nns_handler_root::root_proposals::get_pending_root_proposals_to_upgrade_governance_canister()
}

/// Executes a proposal to change an NNS canister.
#[update]
fn change_nns_canister(request: ChangeCanisterRequest) {
    check_caller_is_governance();
    // We want to reply first, so that in the case that we want to upgrade the
    // governance canister, the root canister no longer holds a pending callback
    // to it -- and therefore does not prevent the governance canister from being
    // stopped.
    //
    // To do so, we use `over` instead of the more common `over_async`.
    //
    // This will effectively reply synchronously with the first call to the
    // management canister in change_canister.

    // Because change_canister is async, and because we can't directly use
    // `await`, we need to use the `spawn` trick.
    let future = async move {
        let change_canister_result = change_canister::<CdkRuntime>(request).await;
        match change_canister_result {
            Ok(()) => {
                println!("{LOG_PREFIX}change_canister: Canister change completed successfully.");
            }
            Err(err) => {
                println!("{LOG_PREFIX}change_canister: Canister change failed: {err}");
            }
        };
    };

    // Starts the proposal execution, which will continue after this function has
    // returned.
    spawn_017_compat(future);
}

#[update]
async fn add_nns_canister(request: AddCanisterRequest) {
    check_caller_is_governance();
    canister_management::do_add_nns_canister(request).await;
}

// Executes a proposal to stop/start an nns canister.
#[update]
async fn stop_or_start_nns_canister(request: StopOrStartCanisterRequest) {
    check_caller_is_governance();
    // It is a mistake to stop the root or governance canister, because if either of them is
    // stopped, there is no way to restore them to the running state. That would require executing a
    // proposal, but executing such proposals requires both of those canisters. Lifelife plays a
    // similar critical role in NNS, so we disallow stopping that too.
    let is_canister_disallowed_to_stop = [
        GOVERNANCE_CANISTER_ID,
        ROOT_CANISTER_ID,
        LIFELINE_CANISTER_ID,
    ]
    .contains(&request.canister_id);
    if request.action == CanisterAction::Stop && is_canister_disallowed_to_stop {
        panic!("Stopping the governance, root, or lifeline canister is not allowed.");
    }

    canister_management::stop_or_start_nns_canister(request)
        .await
        .unwrap() // For compatibility.
}

#[update]
fn call_canister(proposal: CallCanisterRequest) {
    check_caller_is_governance();
    // Starts the proposal execution, which will continue after this function has returned.
    let future = canister_management::call_canister(proposal);
    spawn_017_compat(future);
}

/// Change the controllers of a canister controlled by NNS Root. Only callable
/// by SNS-W.
#[update]
async fn change_canister_controllers(
    change_canister_controllers_request: ChangeCanisterControllersRequest,
) -> ChangeCanisterControllersResponse {
    check_caller_is_sns_w();
    canister_management::change_canister_controllers(
        change_canister_controllers_request,
        &mut new_management_canister_client(),
    )
    .await
}

/// Updates the canister settings of a canister controlled by NNS Root. Only callable by NNS
/// Governance.
#[update]
async fn update_canister_settings(
    update_settings: UpdateCanisterSettingsRequest,
) -> UpdateCanisterSettingsResponse {
    check_caller_is_governance();
    canister_management::update_canister_settings(
        update_settings,
        &mut new_management_canister_client(),
    )
    .await
}

/// Takes a snapshot of a canister controlled by NNS Root. Only callable by NNS
/// Governance.
#[update]
async fn take_canister_snapshot(
    take_canister_snapshot_request: TakeCanisterSnapshotRequest,
) -> TakeCanisterSnapshotResponse {
    check_caller_is_governance();
    canister_management::take_canister_snapshot(
        take_canister_snapshot_request,
        &mut new_management_canister_client(),
    )
    .await
}

/// Loads a snapshot of a canister controlled by NNS Root. Only callable by NNS
/// Governance.
#[update]
async fn load_canister_snapshot(
    load_canister_snapshot_request: LoadCanisterSnapshotRequest,
) -> LoadCanisterSnapshotResponse {
    check_caller_is_governance();
    canister_management::load_canister_snapshot(
        load_canister_snapshot_request,
        &mut new_management_canister_client(),
    )
    .await
}

/// Resources to serve for a given http_request
/// Serve an HttpRequest made to this canister
#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
pub fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(encode_metrics),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

// When run on native this prints the candid service definition of this
// canister, from the methods annotated with `candid_method` above.
//
// Note that `cargo test` calls `main`, and `export_service` (which defines
// `__export_service` in the current scope) needs to be called exactly once. So
// in addition to `not(target_arch = "wasm32")` we have a `not(test)` guard here
// to avoid calling `export_service`, which we need to call in the test below.
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

#[cfg(test)]
mod tests;
