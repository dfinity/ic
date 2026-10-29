use ic_recovery::error::{RecoveryError, RecoveryResult};
use slog::{Logger, info};

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

/// Retries `check` until it succeeds, returning its value, or `timeout`
/// elapses.
pub(crate) fn wait_for<T>(
    what: &str,
    timeout: Duration,
    poll_interval: Duration,
    logger: &Logger,
    mut check: impl FnMut() -> RecoveryResult<T>,
) -> RecoveryResult<T> {
    let deadline = Instant::now() + timeout;
    loop {
        let err = match check() {
            Ok(value) => return Ok(value),
            Err(err) => err,
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
