//! This module contains the public interface of the migration canister.
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade, update};
use serde::Deserialize;

use crate::{start_timers, ValidatonError};

#[init]
fn init() {
    start_timers();
}

#[post_upgrade]
fn post_upgrade() {
    start_timers();
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanisterArgs {
    source: Principal,
    target: Principal,
}

#[update]
fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), ValidatonError> {
    Ok(())
}
