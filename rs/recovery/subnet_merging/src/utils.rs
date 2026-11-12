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
/// CUP and waiting for it agree on the same values, also in a run that is
/// resumed after the merged state was assembled.
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
    // Called only to poll the `RegistryReplicator`, so that the local store has
    // caught up with `registry_version`; the latest version itself is not needed.
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

/// Checks that the default initial DKG subnet, if the registry sets one, is
/// neither of the two subnets of the merge.
///
/// The proposal for the recovery CUP of the destination subnet names no subnet
/// to run the DKG for it, which leaves it to that default (and to the NNS
/// subnet if there is none). The registry rejects the proposal if the default
/// is the destination subnet itself, and the source subnet could not run the
/// DKG: its replica is stopped by then.
pub(crate) fn ensure_default_initial_dkg_subnet_is_not_merged(
    registry_helper: &RegistryHelper,
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> RecoveryResult<()> {
    let registry_version = registry_helper.latest_registry_version()?;
    let default_initial_dkg_subnet_id = registry_helper
        .registry_client()
        .get_default_initial_dkg_subnet_id(registry_version)
        .map_err(|err| {
            RecoveryError::RegistryError(format!(
                "Failed to get the default initial DKG subnet at registry version \
                 {registry_version}: {err}"
            ))
        })?;
    check_default_initial_dkg_subnet(
        default_initial_dkg_subnet_id,
        source_subnet_id,
        destination_subnet_id,
    )
}

fn check_default_initial_dkg_subnet(
    default_initial_dkg_subnet_id: Option<SubnetId>,
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> RecoveryResult<()> {
    for (subnet_id, role) in [
        (source_subnet_id, "source"),
        (destination_subnet_id, "destination"),
    ] {
        if default_initial_dkg_subnet_id == Some(subnet_id) {
            return Err(RecoveryError::ValidationFailed(format!(
                "Subnet {subnet_id}: the {role} subnet should not be the default initial DKG \
                 subnet, which runs the DKG for the recovery of the destination subnet. Set \
                 another default initial DKG subnet first."
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initial_dkg_subnet_must_not_be_merged() {
        let subnet_id = |id| SubnetId::from(ic_base_types::PrincipalId::new_subnet_test_id(id));
        let (source, destination, other) = (subnet_id(1), subnet_id(2), subnet_id(3));

        assert!(check_default_initial_dkg_subnet(None, source, destination).is_ok());
        assert!(check_default_initial_dkg_subnet(Some(other), source, destination).is_ok());
        for (default, role) in [(source, "source"), (destination, "destination")] {
            let err = check_default_initial_dkg_subnet(Some(default), source, destination)
                .unwrap_err()
                .to_string();
            assert!(err.contains(role), "{err}");
            assert!(err.contains("default initial DKG subnet"), "{err}");
        }
    }

    #[test]
    fn merged_state_params_round_trip_test() {
        let dir =
            std::env::temp_dir().join(format!("subnet_merging_utils_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("merged_state_params.json");

        let params = MergedStateParams {
            height: 42_000,
            state_hash: "deadbeef".to_string(),
        };
        params.write(&path).unwrap();

        assert_eq!(MergedStateParams::read(&path).unwrap(), params);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
