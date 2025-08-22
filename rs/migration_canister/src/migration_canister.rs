//! This module contains the public interface of the migration canister.
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade, println, update};
use serde::Deserialize;

use crate::{
    canister_state::migrations_disabled, rate_limited, start_timers, validate_request,
    ValidatonError,
};

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
    pub source: Principal,
    pub target: Principal,
}

#[update]
fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), ValidatonError> {
    if migrations_disabled() {
        return Err(ValidatonError::MigrationsDisabled);
    }
    if rate_limited() {
        return Err(ValidatonError::RateLimited);
    }
    let caller = ic_cdk::caller();
    match validate_request(args.source, args.target, caller) {
        Err(e) => {
            println!("Failed to validate request {:?}: {:?}", args, e);
            return Err(e);
        }
        Ok(request) => {
            println!("Accepted request {:?}", request);
            // TODO: insert into REQUESTS
        }
    }
    Ok(())
}
