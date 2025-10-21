//! This module contains APIs that only the controllers may call.  
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::{api::msg_caller, update};
use serde::Deserialize;

use crate::canister_state::privileged::{set_disabled_flag, set_max_active_requests};

const GOVERNANCE_CANISTER_ID: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";

/// Only controllers and the governance canister are allowed to call privileged endpoints.
fn check_caller() -> Result<(), MigrationCanisterError> {
    let is_controller = ic_cdk::api::is_controller(&msg_caller());
    match is_controller || (msg_caller() == Principal::from_text(GOVERNANCE_CANISTER_ID).unwrap()) {
        true => Ok(()),
        false => Err(MigrationCanisterError::CallerNotAuthorized),
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum MigrationCanisterError {
    CallerNotAuthorized,
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
