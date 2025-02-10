use ic_base_types::PrincipalId;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::init;
use ic_nervous_system_common::serve_metrics;

use ic_cdk::{post_upgrade, query, update};
use ic_nns_handler_recovery::{
    metrics::encode_metrics,
    node_operator_sync::{
        get_node_operators_in_nns, set_initial_node_operators, sync_node_operators,
    },
    print_with_prefix,
    recovery_proposal::{get_recovery_proposals, submit_recovery_proposal, vote_on_proposal_inner},
};
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryProposal, VoteOnRecoveryProposal},
    recovery_init::RecoveryInitArgs,
    simple_node_operator_record::SimpleNodeOperatorRecord,
};

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::caller())
}

#[post_upgrade]
fn canister_post_upgrade(arg: RecoveryInitArgs) {
    println!("canister_post_upgrade");
    init(arg);
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

#[update]
async fn submit_new_recovery_proposal(
    new_recovery_proposal: NewRecoveryProposal,
) -> Result<(), String> {
    submit_recovery_proposal(new_recovery_proposal, caller())
}

#[update]
async fn vote_on_proposal(vote: VoteOnRecoveryProposal) -> Result<(), String> {
    vote_on_proposal_inner(caller(), vote)
}

#[query]
fn get_pending_recovery_proposals() -> Vec<RecoveryProposal> {
    get_recovery_proposals()
}

#[query]
fn get_current_nns_node_operators() -> Vec<SimpleNodeOperatorRecord> {
    get_node_operators_in_nns()
}

/// Resources to serve for a given http_request
/// Serve an HttpRequest made to this canister
#[query(hidden = true, decoding_quota = 10000)]
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

#[init]
fn init(arg: RecoveryInitArgs) {
    ic_cdk_timers::set_timer(std::time::Duration::from_secs(0), || {
        ic_cdk::spawn(setup_node_operator_update(Some(arg)));
    });
    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(60 * 60 * 24), || {
        ic_cdk::spawn(setup_node_operator_update(None));
    });
}

async fn setup_node_operator_update(args: Option<RecoveryInitArgs>) {
    if let Some(args) = args {
        set_initial_node_operators(args.initial_node_operator_records);
    }

    print_with_prefix("Started Sync for new node operators on NNS");
    if let Err(e) = sync_node_operators().await {
        print_with_prefix(e);
    }
    print_with_prefix("Sync completed");
}

#[cfg(test)]
mod tests;

ic_cdk::export_candid!();
