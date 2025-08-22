//! This module contains APIs that only the controllers may call.  
//!
//!

use candid::CandidType;
use ic_cdk::{caller, update};
use serde::Deserialize;

use crate::canister_state::privileged::{set_disabled_flag, set_max_active_requests};

fn check_caller() -> Result<(), MigrationCanisterError> {
    match ic_cdk::api::is_controller(&caller()) {
        true => Ok(()),
        false => Err(MigrationCanisterError::CallerNotController),
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum MigrationCanisterError {
    CallerNotController,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct SetRateLimitArgs {
    pub max_active_requests: u64,
}

#[update]
fn set_rate_limit(args: SetRateLimitArgs) -> Result<(), MigrationCanisterError> {
    check_caller()?;
    set_max_active_requests(args.max_active_requests);
    Ok(())
}

#[update]
fn enable_api() -> Result<(), MigrationCanisterError> {
    check_caller()?;
    set_disabled_flag(false);
    Ok(())
}

#[update]
fn disable_api() -> Result<(), MigrationCanisterError> {
    check_caller()?;
    set_disabled_flag(true);
    Ok(())
}
