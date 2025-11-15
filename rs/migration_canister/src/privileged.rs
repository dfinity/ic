//! This module contains APIs that only the controllers may call.  
//!
//!

use candid::{CandidType, Principal, Reserved};
use ic_cdk::{api::msg_caller, update};
use serde::Deserialize;

use crate::canister_state::privileged::set_disabled_flag;

const GOVERNANCE_CANISTER_ID: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";

/// Only controllers and the governance canister are allowed to call privileged endpoints.
fn check_caller() -> Result<(), Option<MigrationCanisterError>> {
    let is_controller = ic_cdk::api::is_controller(&msg_caller());
    match is_controller || (msg_caller() == Principal::from_text(GOVERNANCE_CANISTER_ID).unwrap()) {
        true => Ok(()),
        false => Err(Some(MigrationCanisterError::CallerNotAuthorized(Reserved))),
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub(crate) enum MigrationCanisterError {
    CallerNotAuthorized(Reserved),
}

#[update]
fn enable_api() -> Result<(), Option<MigrationCanisterError>> {
    check_caller()?;
    set_disabled_flag(false);
    Ok(())
}

#[update]
fn disable_api() -> Result<(), Option<MigrationCanisterError>> {
    check_caller()?;
    set_disabled_flag(true);
    Ok(())
}
