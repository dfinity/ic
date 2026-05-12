#![allow(deprecated)]
use std::{collections::HashSet, time::Duration};

use crate::{
    logs::P0,
    metrics::METRICS,
    storage::{API_BOUNDARY_NODE_PRINCIPALS, SALT, StorableSalt},
    time::delay_till_next_month,
};
use candid::Principal;
use ic_canister_log::log;
use ic_cdk::{api::time, call};
use ic_cdk_timers::{set_timer, set_timer_interval};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use salt_sharing_api::{
    ApiBoundaryNodeIdRecord, GetApiBoundaryNodeIdsRequest, InitArg, SALT_SIZE,
    SaltGenerationStrategy,
};

const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

pub async fn init_async(init_arg: InitArg) {
    if (!is_salt_init() || init_arg.regenerate_now)
        && let Err(err) = try_regenerate_salt().await
    {
        log!(P0, "[init_regenerate_salt_failed]: {err}");
    }
    // Start salt generation schedule based on the argument.
    match init_arg.salt_generation_strategy {
        SaltGenerationStrategy::StartOfMonth => schedule_monthly_salt_generation(),
    }
    // Set up periodical job to get all API boundary node IDs from the registry.
    let period = Duration::from_secs(init_arg.registry_polling_interval_secs);
    set_timer_interval(period, async || poll_api_boundary_nodes().await);
}

// Sets an execution timer (delayed future task) and returns immediately.
pub fn schedule_monthly_salt_generation() {
    let delay = delay_till_next_month(time());
    set_timer(delay, async {
        if let Err(err) = try_regenerate_salt().await {
            log!(P0, "[scheduled_regenerate_salt_failed]: {err}");
        }
        // Function is called recursively to schedule next execution
        schedule_monthly_salt_generation();
    });
}

pub fn is_salt_init() -> bool {
    SALT.with(|cell| cell.borrow().get(&())).is_some()
}

// Regenerate salt and store it in the stable memory
// Can only fail, if the call to management canister fails.
pub async fn try_regenerate_salt() -> Result<(), String> {
    let (salt,): ([u8; SALT_SIZE],) =
        ic_cdk::call(Principal::management_canister(), "raw_rand", ())
            .await
            .map_err(|err| {
                format!(
                    "Call to `raw_rand` of management canister failed: code={:?}, err={}",
                    err.0, err.1
                )
            })?;

    let stored_salt = StorableSalt {
        salt: salt.to_vec(),
        salt_id: time(),
    };

    SALT.with(|cell| {
        cell.borrow_mut().insert((), stored_salt);
    });

    Ok(())
}

pub async fn poll_api_boundary_nodes() {
    let canister_id = Principal::from(REGISTRY_CANISTER_ID);

    let (call_status, message) = match call::<_, (Result<Vec<ApiBoundaryNodeIdRecord>, String>,)>(
        canister_id,
        REGISTRY_CANISTER_METHOD,
        (&GetApiBoundaryNodeIdsRequest {},),
    )
    .await
    {
        Ok((Ok(api_bn_records),)) => {
            // Set authorized readers of salt.
            let principals: HashSet<_> = api_bn_records.into_iter().filter_map(|n| n.id).collect();
            API_BOUNDARY_NODE_PRINCIPALS.with(|cell| *cell.borrow_mut() = principals);
            // Update metric.
            let current_time = time() as i64;
            METRICS.with(|cell| {
                cell.borrow_mut()
                    .last_successful_registry_poll_time
                    .set(current_time);
            });
            ("success", "")
        }
        Ok((Err(err),)) => {
            log!(
                P0,
                "[poll_api_boundary_nodes]: failed to fetch nodes from registry {err:?}",
            );
            ("failure", "calling_canister_method_failed")
        }
        Err(err) => {
            log!(
                P0,
                "[poll_api_boundary_nodes]: failed to fetch nodes from registry {err:?}",
            );
            ("failure", "canister_call_rejected")
        }
    };
    // Update metric.
    METRICS.with(|cell| {
        cell.borrow_mut()
            .registry_poll_calls
            .with_label_values(&[call_status, message])
            .inc();
    });
}

pub fn is_api_boundary_node_principal(principal: &Principal) -> bool {
    API_BOUNDARY_NODE_PRINCIPALS.with(|cell| cell.borrow().contains(principal))
}
