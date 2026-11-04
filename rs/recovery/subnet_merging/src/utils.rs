use ic_base_types::{RegistryVersion, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    registry_helper::RegistryHelper,
};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use slog::{Logger, info};

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

/// Why a check polled by `wait_for_unless_fatal` did not succeed.
pub(crate) enum CheckError {
    /// The check may succeed when polled again.
    Retry(RecoveryError),
    /// The check cannot succeed any more, so waiting is given up right away.
    Fatal(RecoveryError),
}

/// Errors are retried unless they are explicitly marked as fatal.
impl From<RecoveryError> for CheckError {
    fn from(err: RecoveryError) -> Self {
        CheckError::Retry(err)
    }
}

/// Retries `check` until it succeeds, returning its value, or `timeout`
/// elapses.
pub(crate) fn wait_for<T>(
    what: &str,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
    mut check: impl FnMut() -> RecoveryResult<T>,
) -> RecoveryResult<T> {
    wait_for_unless_fatal(what, timeout, poll_interval, logger, || {
        check().map_err(CheckError::Retry)
    })
}

/// Like `wait_for`, but gives up right away when `check` fails with a
/// `CheckError::Fatal`.
pub(crate) fn wait_for_unless_fatal<T>(
    what: &str,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
    mut check: impl FnMut() -> Result<T, CheckError>,
) -> RecoveryResult<T> {
    let deadline = Instant::now() + timeout;
    loop {
        let err = match check() {
            Ok(value) => return Ok(value),
            Err(CheckError::Fatal(err)) => return Err(err),
            Err(CheckError::Retry(err)) => err,
        };
        info!(logger, "Waiting until {what}: {err}");

        if Instant::now() >= deadline {
            return Err(RecoveryError::UnexpectedError(format!(
                "Gave up waiting until {what} after {timeout:?}: {err}"
            )));
        }
        sleep(poll_interval);
    }
}

/// Returns the record of the given subnet as of `registry_version`, rather
/// than as of the latest version `RegistryHelper::get_subnet_record` reads.
///
/// Polls the `RegistryReplicator` first, as every getter of `RegistryHelper`
/// does: a version the local store has not caught up with yet is not readable,
/// and the merge may well be asking about one that was just created.
pub(crate) fn get_subnet_record_at_version(
    registry_helper: &RegistryHelper,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> RecoveryResult<Option<SubnetRecord>> {
    let _ = registry_helper.latest_registry_version()?;

    registry_helper
        .registry_client()
        .get_subnet_record(subnet_id, registry_version)
        .map_err(|err| {
            RecoveryError::RegistryError(format!(
                "Failed to get the record of subnet {subnet_id} at registry version \
                 {registry_version}: {err}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use slog::o;

    fn logger() -> Logger {
        Logger::root(slog::Discard, o!())
    }

    #[test]
    fn retryable_errors_are_retried_until_the_check_succeeds() {
        let mut polls = 0;
        let result = wait_for_unless_fatal(
            "the third poll",
            Duration::from_secs(60),
            Duration::ZERO,
            &logger(),
            || {
                polls += 1;
                if polls < 3 {
                    Err(CheckError::Retry(RecoveryError::StepSkipped))
                } else {
                    Ok(polls)
                }
            },
        );
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn a_fatal_error_is_returned_without_waiting_any_longer() {
        let mut polls = 0;
        let result: RecoveryResult<()> = wait_for_unless_fatal(
            "nothing",
            Duration::from_secs(60),
            Duration::ZERO,
            &logger(),
            || {
                polls += 1;
                Err(CheckError::Fatal(RecoveryError::ValidationFailed(
                    "fatal".to_string(),
                )))
            },
        );
        assert!(matches!(result, Err(RecoveryError::ValidationFailed(_))));
        assert_eq!(polls, 1);
    }
}
