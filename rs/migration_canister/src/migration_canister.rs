//! This module contains the public interface of the migration canister.
//!
//!

use std::fmt::Display;

use candid::{CandidType, Principal};
use ic_cdk::{api::msg_caller, init, post_upgrade, println, update};
use itertools::Itertools;
use serde::Deserialize;
use strum::Display;

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

#[derive(Clone, CandidType, Deserialize)]
struct MigrateCanisterArgs {
    pub source: Principal,
    pub target: Principal,
}

impl Display for MigrateCanisterArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MigrateCanisterArgs {{ source: {}, target: {} }}",
            self.source, self.target
        )
    }
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
            println!("Failed to validate request {}: {}", args, e);
            return Err(e);
        }
        Ok(request) => {
            println!("Accepted request {}", request);
            insert_request(RequestState::Accepted { request });
        }
    }
    Ok(())
}

#[derive(Clone, Display, CandidType, Deserialize)]
enum MigrationStatus {
    Unknown,
    #[strum(to_string = "MigrationStatus::InProgress {{ status: {status} }}")]
    InProgress {
        status: String,
    },
    #[strum(to_string = "MigrationStatus::Failed {{ reason: {reason} }}")]
    Failed {
        reason: String,
    },
    Succeeded,
}

#[update]
/// we return a vector.
/// The same (source, target) pair might be present in the `HISTORY`, and valid to process again, so
fn migration_status(_args: MigrateCanisterArgs) -> Vec<MigrationStatus> {
    // TODO
    println!("[{}]", list_by(|_| true).iter().format(", "));
    vec![MigrationStatus::Unknown]
}

// TODO: history endpoint
