use ic_base_types::{PrincipalId, SubnetId};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_common::serve_metrics;
use ic_nns_handler_root::{
    backup_root_proposals::ChangeSubnetHaltStatus, encode_metrics,
    root_proposals::RootProposalBallot,
};

#[cfg(target_arch = "wasm32")]
use ic_cdk::println;

use ic_cdk::{post_upgrade, query, update};

fn caller() -> PrincipalId {
    PrincipalId::from(ic_cdk::caller())
}

// canister_init and canister_post_upgrade are needed here
// to ensure that printer hook is set up, otherwise error
// messages are quite obscure.
#[export_name = "canister_init"]
fn canister_init() {
    println!("canister_init");
}

#[post_upgrade]
fn canister_post_upgrade() {
    println!("canister_post_upgrade");
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method_cdk! {}

#[update(hidden = true)]
async fn submit_root_proposal_to_change_subnet_halt_status(
    subnet_id: SubnetId,
    halt: bool,
) -> Result<(), String> {
    //TODO: Create a separate thing that polls nns for node operators and store them in memory
    // If nns is down we won't be able to call registry canister
    ic_nns_handler_root::backup_root_proposals::submit_root_proposal_to_change_subnet_halt_status(
        caller(),
        subnet_id,
        halt,
    )
    .await
}

#[update(hidden = true)]
async fn vote_on_root_proposal_to_change_subnet_halt_status(
    proposer: PrincipalId,
    ballot: RootProposalBallot,
) -> Result<(), String> {
    ic_nns_handler_root::backup_root_proposals::vote_on_root_proposal_to_change_subnet_halt_status(
        caller(),
        proposer,
        ballot,
    )
}

#[update(hidden = true)]
fn get_pending_root_proposals_to_change_subnet_halt_status() -> Vec<ChangeSubnetHaltStatus> {
    ic_nns_handler_root::backup_root_proposals::get_pending_root_proposals_to_change_subnet_halt_status()
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

#[cfg(test)]
mod tests;
