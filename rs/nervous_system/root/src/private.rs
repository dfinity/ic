use crate::{
    LOG_PREFIX,
    change_canister::{start_canister, stop_canister},
};
use dfn_core::api::CanisterId;
use ic_cdk::futures::spawn_migratory;
use ic_nervous_system_lock::acquire_for;
use ic_nervous_system_runtime::CdkRuntime;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
    future::Future,
};

// Records the acquisition of locks that protect a canister.
thread_local! {
    pub(crate) static CANISTER_LOCK_ACQUISITIONS: RefCell<BTreeMap<
        // Which canister's lock was acquired.
        CanisterId,
        // (A description of) what operation is being performed on it.
        String,
    >> = const { RefCell::new(BTreeMap::new()) };
}

/// Provides a placeholder "looks ok" value for use when the operation
/// runs in the background and the actual outcome is known before returning
/// the reply from the canister method.
pub(crate) trait Optimistic {
    fn new_optimistic() -> Self;
}

impl<E> Optimistic for Result<(), E> {
    fn new_optimistic() -> Self {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reject {
    pub code: i32,
    pub message: String,
}

impl From<(i32, String)> for Reject {
    fn from(src: (i32, String)) -> Self {
        let (code, message) = src;

        Self { code, message }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // Because all names end with "Failed".
pub(crate) enum OfflineMaintenanceError {
    LockAcquisitionFailed {
        ongoing_operation_description: String,
    },

    StopBeforeMainOperationFailed {
        stop_reject: Reject,
        restart_result: Result<(), Reject>,
    },

    StartAfterMainOperationFailed {
        start_reject: Reject,
        main_operation_result: String,
    },
}

pub(crate) use OfflineMaintenanceError::{
    LockAcquisitionFailed, StartAfterMainOperationFailed, StopBeforeMainOperationFailed,
};

impl Display for OfflineMaintenanceError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let result = match self {
            LockAcquisitionFailed {
                ongoing_operation_description,
            } => {
                format!(
                    "Another operation is currently in progress \
                     (on the same canister): {ongoing_operation_description}.",
                )
            }

            StopBeforeMainOperationFailed {
                stop_reject,
                restart_result,
            } => {
                let main_reason =
                    format!("Failed to stop the canister beforehand: {stop_reject:?}");

                let restart_status = match restart_result {
                    Ok(()) => "fortunately, re-starting the canister succeeded".to_string(),
                    Err(restart_err) => {
                        format!("unfortunately, re-starting the canister failed: {restart_err:?}",)
                    }
                };

                format!("{main_reason}; {restart_status}.")
            }

            StartAfterMainOperationFailed {
                start_reject,
                main_operation_result,
            } => {
                let start_failure = format!(
                    "Unable to start the canister again after the main operation: \
                     {start_reject:?}",
                );

                format!("{start_failure}; main_operation_result: {main_operation_result}.")
            }
        };

        write!(formatter, "{result}")
    }
}

/// Does a couple of things around main_operation:
///
/// * Before: Acquire the canister's lock (hence "exclusive"), and stop the
///   canister (assuming stop_before is true, which it normally would be).
///
/// * After: the reverse: (re-)start the canister, and release the lock.
///
/// If stopping the canister fails, tries to start it again, and return Err
/// WITHOUT proceeding.
///
/// The "after" operations are performed regardless of the outcome of the main
/// operation. Releasing the lock is performed regardless of whether re-starting
/// succeeds.
///
/// # Special Governance Behavior
///
/// To avoid deadlock, when `canister_id` is Governance, everything is done
/// in the background (via spawn_migratory). Furthermore,
/// `Ok(R::new_optimistic())` is returned immediately, i.e. with no .await.
///
/// Without this, deadlock would occur:
///
/// 1. Governance calls some root method, and the implementation of that method
///    uses this function.
/// 2. The first thing this does is stop canister_id, which in this special case,
///    is Governance itself.
///
/// At this point, Governance and Root are waiting for each other before they
/// can proceeed.
pub(crate) async fn perform_offline_canister_maintenance<MainOperation, Fut, R>(
    canister_id: CanisterId,
    operation_description: &str,
    stop_before: bool,
    main_operation: MainOperation,
) -> Result<R, OfflineMaintenanceError>
where
    MainOperation: FnOnce() -> Fut + 'static,
    Fut: Future<Output = R> + 'static,
    R: Debug + Optimistic + 'static,
{
    // These will be moved into the following async blocks.
    let operation_description = operation_description.to_string();
    let operation_description_for_log = operation_description.clone();

    // Compose all work into a single future so it can be either awaited
    // directly or spawned in the background.
    let operation = async move {
        // Try to acquire lock for this canister; fail immediately if the canister
        // is already locked (indicating that some other operation is currently in
        // progress).
        let _release_on_drop = acquire_for(
            &CANISTER_LOCK_ACQUISITIONS,
            canister_id,
            operation_description.clone(),
        )
        .map_err(|ongoing_operation_description| LockAcquisitionFailed {
            ongoing_operation_description,
        })?;

        if stop_before {
            stop_before_main_operation(canister_id, &operation_description).await?;
        }

        let main_operation_result = main_operation().await;

        if stop_before {
            return restart_after_main_operation(
                canister_id,
                &operation_description,
                main_operation_result,
            )
            .await;
        }

        Ok(main_operation_result)
    };

    // Log result.
    let operation = async move {
        let result = operation.await;
        println!(
            "{LOG_PREFIX}Result of {operation_description_for_log} on {canister_id}: {result:?}."
        );
        result
    };

    if canister_id == GOVERNANCE_CANISTER_ID {
        spawn_migratory(async move {
            // Result is discarded here; it is logged above.
            let _: Result<R, OfflineMaintenanceError> = operation.await;
        });

        // Even though we do not yet know that the operation will succeed, we
        // return the optimistic value here, because we also do not know that it
        // will fail. The important thing is that we launched the operation.
        return Ok(R::new_optimistic());
    }

    operation.await
}

async fn stop_before_main_operation(
    canister_id: CanisterId,
    operation_description: &str,
) -> Result<(), OfflineMaintenanceError> {
    let stop_reject = match stop_canister::<CdkRuntime>(canister_id).await {
        Ok(()) => {
            return Ok(());
        }
        Err(err) => Reject::from(err),
    };

    // Recover from failure to stop by (re-)starting the canister.

    println!(
        "{LOG_PREFIX}WARNING: Failed to stop canister {canister_id} \
         ({stop_reject:?}) while preparing to perform {operation_description}, \
         which will now not be attempted. But first, attempting to \
         (re-)start the canister.",
    );

    let restart_result = start_canister::<CdkRuntime>(canister_id)
        .await
        .map_err(|start_err| {
            let start_err = Reject::from(start_err);

            println!(
                "{LOG_PREFIX}WARNING: After failing to stop canister {canister_id} \
                 in preparation to perform {operation_description}, re-starting the canister \
                 ALSO failed: {start_err:?}."
            );

            start_err
        });

    if restart_result.is_ok() {
        println!(
            "{LOG_PREFIX}It's not all bad news for {operation_description}. \
             So, even though stopping canister {canister_id} beforehand \
             did not work, (re-)starting it DID INDEED work. \
             (We will still NOT proceed with the main operation though.)",
        );
    }

    Err(StopBeforeMainOperationFailed {
        stop_reject,
        restart_result,
    })
}

async fn restart_after_main_operation<R>(
    canister_id: CanisterId,
    operation_description: &str,
    main_operation_result: R,
) -> Result<R, OfflineMaintenanceError>
where
    R: Debug,
{
    match start_canister::<CdkRuntime>(canister_id).await {
        Ok(()) => Ok(main_operation_result),

        Err(err) => {
            // This would be pretty terrible, especially if Governance is the
            // target canister...

            let start_reject = Reject::from(err);
            let main_operation_result = format!("{main_operation_result:?}");

            println!(
                "{LOG_PREFIX}ERROR: Failed to re-start canister {canister_id} after \
                 performing {operation_description}: {start_reject:?}."
            );

            Err(StartAfterMainOperationFailed {
                start_reject,
                main_operation_result,
            })
        }
    }
}
