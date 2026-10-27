use ic_base_types::{RegistryVersion, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
    registry_helper::RegistryHelper,
};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use serde::{Deserialize, Serialize};
use slog::{Logger, info};

use std::{
    path::Path,
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

/// Everything the recovery of the destination subnet needs to know about the
/// merged state, as computed by the step that assembles it.
///
/// Persisted next to the merged state so that the steps proposing the recovery
/// CUP and waiting for it agree on the same values, and so that a resumed run
/// neither re-merges the states nor re-hashes the merged checkpoint.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct MergedStateParams {
    /// The height of the merged checkpoint, i.e. the height the destination
    /// subnet is recovered at.
    pub(crate) height: u64,
    /// The root hash of the manifest of the merged state.
    pub(crate) state_hash: String,
}

impl MergedStateParams {
    pub(crate) fn read(path: &Path) -> RecoveryResult<Self> {
        let contents = read_file(path)?;
        serde_json::from_str(&contents).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to parse the merged state params at {}: {err}",
                path.display()
            ))
        })
    }

    pub(crate) fn write(&self, path: &Path) -> RecoveryResult<()> {
        let contents = serde_json::to_string_pretty(self).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to serialize the merged state params: {err}"
            ))
        })?;
        write_file(path, contents)
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

    use ic_test_utilities_tmpdir::tmpdir;

    #[test]
    fn merged_state_params_round_trip_test() {
        let dir = tmpdir("test_dir");
        let path = dir.as_ref().join("merged_state_params.json");

        let params = MergedStateParams {
            height: 42_000,
            state_hash: "deadbeef".to_string(),
        };
        params.write(&path).unwrap();

        assert_eq!(MergedStateParams::read(&path).unwrap(), params);
    }
}
