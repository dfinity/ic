use ic_base_types::{PrincipalId, SubnetId};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::init;
use ic_nervous_system_common::serve_metrics;

#[cfg(target_arch = "wasm32")]
use ic_cdk::println;

use ic_cdk::{post_upgrade, query, update};
use ic_nns_handler_recovery::{
    metrics::encode_metrics,
    node_operator_sync::{get_node_operators_in_nns, sync_node_operators, SimpleNodeRecord},
};

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::caller())
}

#[post_upgrade]
fn canister_post_upgrade() {
    println!("canister_post_upgrade");
    init();
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

#[update(hidden = true)]
async fn submit_root_proposal_to_change_subnet_halt_status(
    _subnet_id: SubnetId,
    _halt: bool,
) -> Result<(), String> {
    //TODO: Create a separate thing that polls nns for node operators and store them in memory
    // If nns is down we won't be able to call registry canister
    // ic_nns_handler_root::backup_root_proposals::submit_root_proposal_to_change_subnet_halt_status(
    //     caller(),
    //     subnet_id,
    //     halt,
    // )
    // .await
    Ok(())
}

#[update(hidden = true)]
async fn vote_on_root_proposal_to_change_subnet_halt_status(
    _proposer: PrincipalId,
) -> Result<(), String> {
    // ic_nns_handler_root::backup_root_proposals::vote_on_root_proposal_to_change_subnet_halt_status(
    //     caller(),
    //     proposer,
    //     ballot,
    // )
    Ok(())
}

#[update(hidden = true)]
fn get_pending_root_proposals_to_change_subnet_halt_status() -> Vec<u8> {
    // ic_nns_handler_root::backup_root_proposals::get_pending_root_proposals_to_change_subnet_halt_status()
    vec![]
}

#[query]
fn get_current_nns_node_operators() -> Vec<SimpleNodeRecord> {
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
fn init() {
    ic_cdk_timers::set_timer(std::time::Duration::from_secs(0), || {
        ic_cdk::spawn(setup_node_operator_update());
    });
    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(60 * 60 * 24), || {
        ic_cdk::spawn(setup_node_operator_update());
    });
}

async fn setup_node_operator_update() {
    ic_cdk::println!("Started Sync for new node operators on NNS");
    if let Err(e) = sync_node_operators().await {
        ic_cdk::println!("{}", e);
    }
    ic_cdk::println!("Sync completed")
}

#[cfg(test)]
mod tests;
