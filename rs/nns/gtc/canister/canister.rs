use candid::candid_method;
use dfn_candid::{candid, candid_one};
use dfn_core::{
    api::{arg_data, caller, now},
    over, over_async, stable,
};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_gtc::{
    pb::v1::{AccountState, Gtc},
    LOG_PREFIX,
};
use ic_nns_gtc_accounts::FORWARD_WHITELIST;
use prost::Message;
use std::{ptr::addr_of_mut, time::SystemTime};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

static mut GTC: Option<Gtc> = None;

fn gtc() -> &'static Gtc {
    gtc_mut()
}

fn gtc_mut() -> &'static mut Gtc {
    unsafe {
        if let Some(gtc) = &mut *addr_of_mut!(GTC) {
            gtc
        } else {
            GTC = Some(Gtc::default());
            gtc_mut()
        }
    }
}

#[export_name = "canister_init"]
fn canister_init() {
    dfn_core::printer::hook();

    println!("{}canister_init: Initializing", LOG_PREFIX);

    let gtc = gtc_mut();

    gtc.merge(&arg_data()[..])
        .expect("Couldn't initialize canister");

    if gtc.genesis_timestamp_seconds == 0 {
        let now = now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get duration since UNIX_EPOCH")
            .as_secs();

        gtc.genesis_timestamp_seconds = now;
    }
}

#[export_name = "canister_pre_upgrade"]
fn canister_pre_upgrade() {
    println!("{}Executing pre upgrade", LOG_PREFIX);

    let mut serialized = Vec::new();
    gtc()
        .encode(&mut serialized)
        .expect("Error. Couldn't serialize canister pre-upgrade.");

    stable::set(&serialized);
}

#[export_name = "canister_post_upgrade"]
fn canister_post_upgrade() {
    dfn_core::printer::hook();
    println!("{}Executing post upgrade", LOG_PREFIX);

    let serialized = stable::get();
    let gtc = gtc_mut();
    if let Err(err) = gtc.merge(&serialized[..]) {
        panic!(
            "Error deserializing canister state post-upgrade. \
             CANISTER MIGHT HAVE BROKEN STATE!!!!. Error: {:?}",
            err
        )
    }

    // If the set of whitelisted accounts is empty (like it would
    // normally be in production) add the accounts in the
    // FORWARD_WHITELIST array.
    if gtc.whitelisted_accounts_to_forward.is_empty() {
        for gtc_address in FORWARD_WHITELIST {
            gtc.whitelisted_accounts_to_forward
                .push(gtc_address.to_string());
        }
    }
}

ic_nervous_system_common_build_metadata::define_get_build_metadata_candid_method! {}

/// Returns the sum of all token balances in the internal ledger
#[export_name = "canister_query total"]
fn total() {
    println!("{}total", LOG_PREFIX);
    over(candid, |()| -> u32 { total_() })
}

#[candid_method(query, rename = "total")]
fn total_() -> u32 {
    gtc().total_alloc
}

/// Returns the token balance of a given address
#[export_name = "canister_query balance"]
fn balance() {
    over(candid_one, balance_)
}

#[candid_method(query, rename = "balance")]
fn balance_(address: String) -> u32 {
    gtc().accounts.get(&address).map(|a| a.icpts).unwrap_or(0)
}

/// Returns the number of unique addresses present in the ledger
#[export_name = "canister_query len"]
fn len() {
    over(candid, |()| -> u16 { len_() })
}

#[candid_method(query, rename = "len")]
fn len_() -> u16 {
    gtc().accounts.len() as u16
}

/// Return the account state of the given GTC address
#[export_name = "canister_query get_account"]
fn get_account() {
    println!("{}get_account", LOG_PREFIX);
    over(candid_one, get_account_)
}

#[candid_method(query, rename = "get_account")]
fn get_account_(address: String) -> Result<AccountState, String> {
    gtc().get_account(&address)
}

/// Claim the caller's GTC neurons (on behalf of the caller) and return the IDs
/// of these neurons
#[export_name = "canister_update claim_neurons"]
fn claim_neurons() {
    println!("{}claim_neurons", LOG_PREFIX);
    over_async(candid_one, claim_neurons_)
}

#[candid_method(update, rename = "claim_neurons")]
async fn claim_neurons_(hex_pubkey: String) -> Result<Vec<NeuronId>, String> {
    gtc_mut().claim_neurons(&caller(), hex_pubkey).await
}

/// Donate the caller's GTC account funds to the Neuron given by the GTC's
/// `donate_account_recipient_neuron_id`.
///
/// This method may only be called by the owner of the account.
#[export_name = "canister_update donate_account"]
fn donate_account() {
    println!("{}donate_account", LOG_PREFIX);
    over_async(candid_one, donate_account_)
}

#[candid_method(update, rename = "donate_account")]
async fn donate_account_(hex_pubkey: String) -> Result<(), String> {
    gtc_mut().donate_account(&caller(), hex_pubkey).await
}

/// Transfer the funds of whitelisted unclaimed accounts to the Neuron given by
/// the GTC's `forward_whitelisted_unclaimed_accounts_recipient_neuron_id`.
///
/// This method may be called by anyone 6 months after the IC Genesis.
#[export_name = "canister_update forward_whitelisted_unclaimed_accounts"]
fn forward_whitelisted_unclaimed_accounts() {
    println!("{}forward_whitelisted_unclaimed_accounts", LOG_PREFIX);
    over_async(candid_one, forward_whitelisted_unclaimed_accounts_)
}

#[candid_method(update, rename = "forward_whitelisted_unclaimed_accounts")]
async fn forward_whitelisted_unclaimed_accounts_(_: ()) -> Result<(), String> {
    gtc_mut().forward_whitelisted_unclaimed_accounts().await
}

fn main() {
    // This block is intentionally left blank.
}

// In order for some of the test(s) within this mod to work,
// this MUST occur at the end.
#[cfg(test)]
mod tests;
