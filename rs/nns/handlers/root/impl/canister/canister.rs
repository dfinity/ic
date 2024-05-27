use candid::candid_method;
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::caller,
    endpoint::{over, over_async},
    stable,
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
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
    change_canister::{
        change_canister, AddCanisterRequest, CanisterAction, ChangeCanisterRequest,
        StopOrStartCanisterRequest,
    },
    LOG_PREFIX,
};
use ic_nervous_system_runtime::DfnRuntime;
use ic_nns_common::{
    access_control::{check_caller_is_governance, check_caller_is_sns_w},
    types::CallCanisterProposal,
};
use ic_nns_constants::{
    ALL_NNS_CANISTER_IDS, GOVERNANCE_CANISTER_ID, LIFELINE_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_handler_root::{
    canister_management, encode_metrics,
    root_proposals::{GovernanceUpgradeRootProposal, RootProposalBallot},
    PROXIED_CANISTER_CALLS_TRACKER,
};
use ic_nns_handler_root_interface::{
    ChangeCanisterControllersRequest, ChangeCanisterControllersResponse,
};
use std::cell::RefCell;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

thread_local! {
    // How this value was chosen: queues become full at 500. This is 1/3 of that, which seems to be
    // a reasonable balance.
    static AVAILABLE_MANAGEMENT_CANISTER_CALL_SLOT_COUNT: RefCell<u64> = const { RefCell::new(167) };
}

fn new_management_canister_client() -> impl ManagementCanisterClient {
    let client =
        ManagementCanisterClientImpl::<DfnRuntime>::new(Some(&PROXIED_CANISTER_CALLS_TRACKER));

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

// canister_init and canister_post_upgrade are needed here
// to ensure that printer hook is set up, otherwise error
// messages are quite obscure.
#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();
    println!("{}canister_init", LOG_PREFIX);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade", LOG_PREFIX);
    // Wipe out stable memory, because earlier version of this canister were
    // stateful. This minimizes risk of future misinterpretation of data.
    stable::set(&[]);
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

/// Returns the status of the canister specified in the input.
///
/// The status of NNS canisters should be public information: anyone can get the
/// status of any NNS canister.
///
/// This must be an update, not a query, because an inter-canister call to the
/// management canister is required.
#[export_name = "canister_update canister_status"]
fn canister_status() {
    over_async(candid_one, canister_status_)
}

#[candid_method(update, rename = "canister_status")]
async fn canister_status_(canister_id_record: CanisterIdRecord) -> CanisterStatusResult {
    let client = new_management_canister_client();

    let canister_status_response = client
        .canister_status(canister_id_record)
        .await
        .map(CanisterStatusResult::from);

    canister_status_response.unwrap()
}

#[export_name = "canister_update submit_root_proposal_to_upgrade_governance_canister"]
fn submit_root_proposal_to_upgrade_governance_canister() {
    over_async(
        candid,
        |(expected_governance_wasm_sha, proposal): (
            serde_bytes::ByteBuf,
            ChangeCanisterRequest,
        )| {
            ic_nns_handler_root::root_proposals::submit_root_proposal_to_upgrade_governance_canister(
                caller(),
                expected_governance_wasm_sha.to_vec(),
                proposal,
            )
        },
    );
}

#[export_name = "canister_update vote_on_root_proposal_to_upgrade_governance_canister"]
fn vote_on_root_proposal_to_upgrade_governance_canister() {
    over_async(
        candid,
        |(proposer, wasm_sha256, ballot): (
            PrincipalId,
            serde_bytes::ByteBuf,
            RootProposalBallot,
        )| {
            ic_nns_handler_root::root_proposals::vote_on_root_proposal_to_upgrade_governance_canister(
                caller(),
                proposer,
                wasm_sha256.to_vec(),
                ballot,
            )
        },
    );
}

#[export_name = "canister_update get_pending_root_proposals_to_upgrade_governance_canister"]
fn get_pending_root_proposals_to_upgrade_governance_canister() {
    over(candid, |()| -> Vec<GovernanceUpgradeRootProposal> {
        ic_nns_handler_root::root_proposals::get_pending_root_proposals_to_upgrade_governance_canister()
    })
}

/// Executes a proposal to change an NNS canister.
#[export_name = "canister_update change_nns_canister"]
fn change_nns_canister() {
    check_caller_is_governance();
    over(candid_one, change_nns_canister_);
}

#[candid_method(update, rename = "change_nns_canister")]
fn change_nns_canister_(request: ChangeCanisterRequest) {
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
    let future = change_canister::<DfnRuntime>(request);

    // Starts the proposal execution, which will continue after this function has
    // returned.
    dfn_core::api::futures::spawn(future);
}

#[export_name = "canister_update add_nns_canister"]
fn add_nns_canister() {
    check_caller_is_governance();
    over_async(candid_one, add_nns_canister_)
}

#[candid_method(update, rename = "add_nns_canister")]
async fn add_nns_canister_(request: AddCanisterRequest) {
    canister_management::do_add_nns_canister(request).await;
}

// Executes a proposal to stop/start an nns canister.
#[export_name = "canister_update stop_or_start_nns_canister"]
fn stop_or_start_nns_canister() {
    check_caller_is_governance();
    over_async(candid_one, stop_or_start_nns_canister_)
}

#[candid_method(update, rename = "stop_or_start_nns_canister")]
async fn stop_or_start_nns_canister_(request: StopOrStartCanisterRequest) {
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

#[export_name = "canister_update call_canister"]
fn call_canister() {
    check_caller_is_governance();
    over_async(candid, |(proposal,): (CallCanisterProposal,)| async move {
        // Starts the proposal execution, which will continue after this function has returned.
        let future = canister_management::call_canister(proposal);
        dfn_core::api::futures::spawn(future);
    });
}

/// Change the controllers of a canister controlled by NNS Root. Only callable
/// by SNS-W.
#[export_name = "canister_update change_canister_controllers"]
fn change_canister_controllers() {
    check_caller_is_sns_w();
    over_async(candid_one, change_canister_controllers_)
}

/// Change the controllers of a canister controlled by NNS Root. Only callable
/// by SNS-W.
#[candid_method(update, rename = "change_canister_controllers")]
async fn change_canister_controllers_(
    change_canister_controllers_request: ChangeCanisterControllersRequest,
) -> ChangeCanisterControllersResponse {
    canister_management::change_canister_controllers(
        change_canister_controllers_request,
        &mut new_management_canister_client(),
    )
    .await
}

/// Resources to serve for a given http_request
#[export_name = "canister_query http_request"]
fn http_request() {
    over(candid_one, serve_http)
}

/// Serve an HttpRequest made to this canister
pub fn serve_http(request: HttpRequest) -> HttpResponse {
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
mod tests {
    use super::*;
    use candid_parser::utils::{service_equal, CandidSource};
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;
    use std::{env::var_os, path::PathBuf};

    lazy_static! {
        static ref DECLARED_INTERFACE: String = {
            let cargo_manifest_dir =
                var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var undefined");

            let path = PathBuf::from(cargo_manifest_dir).join("canister/root.did");

            let contents = std::fs::read(path).unwrap();
            String::from_utf8(contents).unwrap()
        };
        static ref IMPLEMENTED_INTERFACE: String = {
            candid::export_service!();
            __export_service()
        };
    }

    /// Makes sure that ./root.did is up to date with the implementation.
    #[test]
    fn check_candid_interface_definition_file() {
        assert_eq!(
            *DECLARED_INTERFACE, *IMPLEMENTED_INTERFACE,
            "Generated candid definition does not match canister/root.did. \
             Run `bazel run :generate_did > canister/root.did` (no nix and/or direnv) in \
             rs/nns/handlers/root/impl/ to update canister/root.did."
        );
    }

    /// This is redundant vs. the previous test. The purpose of this is to show
    /// what the world would look like if we adopted the recommendation that [we
    /// use .did files as our source of truth][use-did-file], instead of
    /// generating them (what we do now).
    ///
    ///   [use-did-file]: https://mmapped.blog/posts/01-effective-rust-canisters.html#canister-interfaces
    #[test]
    fn test_implementation_conforms_to_declared_interface() {
        let result = service_equal(
            CandidSource::Text(&IMPLEMENTED_INTERFACE),
            CandidSource::Text(&DECLARED_INTERFACE),
        );

        if let Err(err) = result {
            panic!(
                "Implemented interface:\n\
                 {}\n\
                 \n\
                 Declared interface:\n\
                 {}\n\
                 \n\
                 Error:\n\
                 {}n\
                 \n\
                 The Candid service implementation does not comply with the declared interface.",
                *IMPLEMENTED_INTERFACE, *DECLARED_INTERFACE, err,
            );
        }
    }
}
