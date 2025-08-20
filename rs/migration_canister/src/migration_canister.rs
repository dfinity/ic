//! This module contains the public interface of the migration canister.
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::update;
use serde::Deserialize;

use crate::ValidatonError;

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanisterArgs {
    source: Principal,
    target: Principal,
}

#[update]
fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), ValidatonError> {
    Ok(())
}
