//! This module contains the public interface of the migration canister.
//!
//!

use candid::{CandidType, Principal};
use ic_cdk::{api::msg_caller, init, post_upgrade, println, update};
use serde::Deserialize;

use crate::{
    RequestState, ValidationError,
    canister_state::{
        migrations_disabled,
        requests::{insert_request, list_by},
    },
    rate_limited, start_timers,
    validation::validate_request,
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
async fn migrate_canister(args: MigrateCanisterArgs) -> Result<(), ValidationError> {
    if migrations_disabled() {
        return Err(ValidationError::MigrationsDisabled);
    }
    if rate_limited() {
        return Err(ValidationError::RateLimited);
    }
    let caller = msg_caller();
    match validate_request(args.source, args.target, caller).await {
        Err(e) => {
            println!("Failed to validate request {:?}: {:?}", args, e);
            return Err(e);
        }
        Ok(request) => {
            println!("Accepted request {:?}", request);
            insert_request(RequestState::Accepted { request });
        }
    }
    Ok(())
}

#[derive(Clone, Debug, CandidType, Deserialize)]
enum MigrationStatus {
    Unknown,
    InProgress { status: String },
    Failed { reason: String },
    Succeeded,
}

#[update]
/// we return a vector.
/// The same (source, target) pair might be present in the `HISTORY`, and valid to process again, so
fn migration_status(_args: MigrateCanisterArgs) -> Vec<MigrationStatus> {
    // TODO
    println!("{:?}", list_by(|_| true));
    vec![MigrationStatus::Unknown]
}

// TODO: history endpoint
