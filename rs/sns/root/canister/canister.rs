use std::cell::RefCell;

use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{over, over_async, over_init};
use ic_base_types::PrincipalId;

#[macro_use]
extern crate ic_nervous_system_common;
#[cfg(test)]
use ic_nervous_system_common::MethodAuthzChange;

use ic_nervous_system_root::{ChangeCanisterProposal, LOG_PREFIX};
use ic_sns_root::pb::v1::SnsRootCanister;

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_ic00_types::CanisterStatusResultV2;

thread_local! {
    static STATE: RefCell<SnsRootCanister> = RefCell::new(Default::default());
}

fn main() {}

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

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade: Done!", LOG_PREFIX);
}

expose_build_metadata! {}

#[export_name = "canister_update canister_status"]
fn canister_status() {
    println!("{}canister_status", LOG_PREFIX);
    over_async(candid, ic_nervous_system_root::canister_status)
}

#[export_name = "canister_update get_sns_canisters_summary"]
fn get_sns_canisters_summary() {
    println!("{}get_sns_canisters_summary", LOG_PREFIX);
    over_async(candid_one, get_sns_canisters_summary_)
}

#[candid_method(update, rename = "get_sns_canisters_summary")]
async fn get_sns_canisters_summary_(
    dapp_canisters: Vec<PrincipalId>,
) -> Vec<(String, PrincipalId, CanisterStatusResultV2)> {
    let root = STATE.with(|service| service.borrow().clone());
    root.get_sns_canisters_summary(dapp_canisters).await
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
    over(candid, |(proposal,): (ChangeCanisterProposal,)| {
        assert_change_canister_proposal_is_valid(&proposal);
        dfn_core::api::futures::spawn(ic_nervous_system_root::change_canister(proposal));
    });
}

fn assert_state_is_valid(state: &SnsRootCanister) {
    assert!(state.governance_canister_id.is_some());
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
