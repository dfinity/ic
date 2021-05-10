use prost::Message;

use candid::Decode;
use dfn_candid::candid;
use dfn_core::{
    api::arg_data,
    endpoint::{over, over_async},
    stable,
};
use ic_nns_common::{
    access_control::{check_caller_is_governance, current_canister_authz, init_canister_authz},
    types::NeuronId,
};
use ic_nns_governance::handler_utils;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_nns_handler_root::{
    canister_management,
    common::{
        AddNnsCanisterProposalPayload, CanisterIdRecord, ChangeNnsCanisterProposalPayload,
        StopOrStartNnsCanisterProposalPayload, LOG_PREFIX,
    },
    init::RootCanisterInitPayload,
    pb::v1::RootCanisterStableStorage,
};

fn main() {}

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_nns_handler_root::canister_management::do_add_nns_canister;

// canister_init and canister_post_upgrade are needed here
// to ensure that printer hook is set up, otherwise error
// messages are quite obscure.
#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();

    let init_payload =
        Decode!(&arg_data(), RootCanisterInitPayload).expect("Failed to decode init arguments");
    println!(
        "{}canister_init: Initializing with: {:?}",
        LOG_PREFIX, init_payload
    );
    init_canister_authz(init_payload.authz_info);
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}canister_pre_upgrade", LOG_PREFIX);
    let mut serialized = Vec::new();
    let ss = RootCanisterStableStorage {
        authz: Some(current_canister_authz()),
    };
    ss.encode(&mut serialized)
        .expect("Error serializing to stable.");
    stable::set(&serialized);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}canister_post_upgrade", LOG_PREFIX);
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.
    let ss = RootCanisterStableStorage::decode(stable::get().as_slice())
        .expect("Error decoding from stable.");
    init_canister_authz(ss.authz.expect("Canister must have authz info in stable"));
}

/// Returns the status of the canister specified in the input.
///
/// The status of NNS canisters should be public information: anyone can get the
/// status of any NNS canister.
///
/// This must be an update, not a query, because an inter-canister call to the
/// management canister is required.
#[export_name = "canister_update canister_status"]
fn canister_status() {
    println!("{}canister_status", LOG_PREFIX);
    over_async(
        candid,
        |(canister_id_record,): (CanisterIdRecord,)| async move {
            canister_management::canister_status(canister_id_record).await
        },
    )
}

#[export_name = "canister_update submit_change_nns_canister_proposal"]
fn submit_change_nns_canister_proposal() {
    over_async(
        candid,
        |(proposer, payload): (NeuronId, ChangeNnsCanisterProposalPayload)| async move {
            println!("{}submit_change_nns_canister_proposal: received a proposal to with a wasm size {:e} B.", LOG_PREFIX, payload.wasm_module.len() as f64);
            handler_utils::submit_proposal(
                &proposer,
                NnsFunction::NnsCanisterUpgrade,
                &payload,
                LOG_PREFIX,
            )
            .await
        },
    );
}

/// Executes a proposal to change an NNS canister.
#[export_name = "canister_update change_nns_canister"]
fn change_nns_canister() {
    check_caller_is_governance();

    // We want to reply first, so that in the case that we want to upgrade the
    // governance canister, the root canister no longer holds a pending callback
    // to it -- and therefore does not prevent the proposals canister from being
    // stopped.
    //
    // To do so, we use `over` instead of the more common `over_async`.
    //
    // This will effectively reply synchronously with the first call to the
    // management canister in do_change_nns_canister.
    over(candid, |(payload,): (ChangeNnsCanisterProposalPayload,)| {
        // Because do_change_nns_canister is async, and because we can't directly use
        // `await`, we need to use the `spawn` trick.
        let future = canister_management::do_change_nns_canister(payload);

        // Starts the proposal execution, which will continue after this function has
        // returned.
        dfn_core::api::futures::spawn(future);
    });
}

#[export_name = "canister_update add_nns_canister"]
fn add_nns_canister() {
    check_caller_is_governance();
    over_async(
        candid,
        |(payload,): (AddNnsCanisterProposalPayload,)| async move {
            do_add_nns_canister(payload).await;
        },
    );
}

// Executes a proposal to stop/start an nns canister.
#[export_name = "canister_update stop_or_start_nns_canister"]
fn stop_or_start_nns_canister() {
    check_caller_is_governance();
    over_async(
        candid,
        |(payload,): (StopOrStartNnsCanisterProposalPayload,)| async move {
            // Can't stop/start the governance canister since that would mean
            // we couldn't submit any more proposals.
            // Since this canister is the only possible caller, it's then safe
            // to call stop/start inline.
            if payload.canister_id == ic_nns_constants::GOVERNANCE_CANISTER_ID
                || payload.canister_id == ic_nns_constants::ROOT_CANISTER_ID
                || payload.canister_id == ic_nns_constants::LIFELINE_CANISTER_ID
            {
                panic!("The governance, root and lifeline canisters can't be stopped or started.")
            }
            canister_management::stop_or_start_nns_canister(payload).await
        },
    );
}
