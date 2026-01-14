
use dfn_core::api::CanisterId;
use ic_nervous_system_lock::acquire_for;
use ic_nervous_system_runtime::Runtime;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;

// Thread-local storage for per-canister locks
// Key: CanisterId, Value: String description of the operation
thread_local! {
    pub(crate) static CANISTER_LOCKS: RefCell<BTreeMap<CanisterId, String>> =
        const { RefCell::new(BTreeMap::new()) };
}

pub(crate) async fn perform_locked_canister_action<Rt, F, Fut, T>(
    canister_id: CanisterId,
    action_description: String,
    stop_before: bool,
    action: F,
) -> Result<T, String>
where
    Rt: Runtime,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    // Try to acquire lock for this canister - fail immediately if locked
    let _guard = match acquire_for(&CANISTER_LOCKS, canister_id, action_description.clone()) {
        Ok(guard) => guard,
        Err(conflicting_request) => {
            return Err(format!(
                "Canister {canister_id} is currently locked by another change operation. Conflicting request: {conflicting_request:?}"
            ));
        }
    };

    if stop_before {
        let stop_result = crate::change_canister::stop_canister::<Rt>(canister_id).await;
        if let Err((code, msg)) = stop_result {
            println!(
                "{}perform_locked_canister_action: Failed to stop canister, trying to restart...",
                crate::LOG_PREFIX
            );
            return match crate::change_canister::start_canister::<Rt>(canister_id).await {
                Ok(_) => Err(format!(
                    "Failed to stop canister {canister_id}. stop_canister error: {code} {msg}. \
                     After failing to stop, attempted to start it, and succeeded in that."
                )),
                Err((start_code, start_msg)) => {
                    println!(
                        "{}perform_locked_canister_action: Failed to restart canister.",
                        crate::LOG_PREFIX
                    );
                    Err(format!(
                        "Failed to stop canister {canister_id}. stop_canister error: {code} {msg}. \
                         After failing to stop, attempted to start it, and failed in that: {start_code} {start_msg}"
                    ))
                }
            };
        }
    }

    let res = action().await;

    // Restart the canister, if needed
    if stop_before {
        crate::change_canister::start_canister::<Rt>(canister_id)
            .await
            .map_err(|(code, msg)| {
                format!("Failed to start canister {canister_id}: {code} {msg}")
            })?;
    }

    res
}
