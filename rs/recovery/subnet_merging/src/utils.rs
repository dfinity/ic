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
