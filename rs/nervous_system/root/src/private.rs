use crate::{
    LOG_PREFIX,
    change_canister::{start_canister, stop_canister},
};
use dfn_core::api::CanisterId;
use ic_nervous_system_lock::acquire_for;
use ic_nervous_system_runtime::CdkRuntime;
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
pub(crate) enum ExclusivelyStopAndStartCanisterError {
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

pub(crate) use ExclusivelyStopAndStartCanisterError::{
    LockAcquisitionFailed, StartAfterMainOperationFailed, StopBeforeMainOperationFailed,
};

impl Display for ExclusivelyStopAndStartCanisterError {
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
pub(crate) async fn exclusively_stop_and_start_canister<MainOperation, Fut, R>(
    canister_id: CanisterId,
    operation_description: &str,
    stop_before: bool,
    main_operation: MainOperation,
) -> Result<R, ExclusivelyStopAndStartCanisterError>
where
    MainOperation: FnOnce() -> Fut,
    Fut: Future<Output = R>,
    R: Debug,
{
    // Try to acquire lock for this canister; fail immediately if the canister
    // is already locked (indicating that some other operation is currently in
    // progress).
    let _release_on_drop = acquire_for(
        &CANISTER_LOCK_ACQUISITIONS,
        canister_id,
        operation_description.to_string(),
    )
    .map_err(|ongoing_operation_description| LockAcquisitionFailed {
        ongoing_operation_description,
    })?;

    if stop_before {
        stop_before_main_operation(canister_id, operation_description).await?;
    }

    let main_operation_result = main_operation().await;

    if stop_before {
        return restart_after_main_operation(
            canister_id,
            operation_description,
            main_operation_result,
        )
        .await;
    }

    Ok(main_operation_result)
}

async fn stop_before_main_operation(
    canister_id: CanisterId,
    operation_description: &str,
) -> Result<(), ExclusivelyStopAndStartCanisterError> {
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
) -> Result<R, ExclusivelyStopAndStartCanisterError>
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
