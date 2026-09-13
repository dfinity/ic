use ic_base_types::RegistryVersion;
use ic_recovery::{
    RECOVERY_DIRECTORY_NAME,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
    registry_helper::RegistryHelper,
};
use serde::{Deserialize, Serialize};

use std::path::Path;

/// Everything the recovery of the destination subnet needs to know about the
/// merged state, as computed by the step that assembles it.
///
/// Persisted next to the merged state so that the steps proposing the recovery
/// CUP and waiting for it agree on the same values, and so that a resumed run
/// neither re-merges the states nor re-hashes the merged checkpoint.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct MergedStateParams {
    /// The height of the merged checkpoint, i.e. the height the destination
    /// subnet is recovered at.
    pub height: u64,
    /// The block time the recovered destination subnet starts from, in
    /// nanoseconds since the Epoch. Larger than the batch times of both
    /// checkpoints the merged state was assembled from.
    pub time_nanos: u64,
    /// The root hash of the manifest of the merged state.
    pub state_hash: String,
}

impl MergedStateParams {
    pub fn read(path: &Path) -> RecoveryResult<Self> {
        let contents = read_file(path)?;
        serde_json::from_str(&contents).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to parse the merged state params at {}: {err}",
                path.display()
            ))
        })
    }

    pub fn write(&self, path: &Path) -> RecoveryResult<()> {
        let contents = serde_json::to_string_pretty(self).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to serialize the merged state params: {err}"
            ))
        })?;
        write_file(path, contents)
    }
}

/// The lowest registry version at which `predicate` holds, in a registry whose
/// history has it hold from some version onwards -- e.g. "the subnet is labeled
/// cooling down" or "the subnet hosts no canister id range anymore", both of
/// which a single proposal of this tool brings about and nothing here undoes.
///
/// Found by binary search, i.e. in a logarithmic number of (local) registry
/// reads rather than by scanning the whole history. Fails if the predicate does
/// not hold at the latest registry version; if the property was turned on and
/// off repeatedly, the version returned is the start of one of the stretches it
/// held in, which is why the callers log it for the operator to confirm.
pub(crate) fn first_registry_version_where(
    registry_helper: &RegistryHelper,
    predicate: impl Fn(RegistryVersion) -> RecoveryResult<bool>,
) -> RecoveryResult<RegistryVersion> {
    let latest = registry_helper.latest_registry_version()?;
    if !predicate(latest)? {
        return Err(RecoveryError::ValidationFailed(format!(
            "The expected registry state has not been reached at the latest registry version \
             {latest}"
        )));
    }

    // Invariant: the predicate does not hold at `low` and holds at `high`. The
    // registry starts at version 1, whose predecessor 0 is the empty registry,
    // where nothing holds.
    let mut low = RegistryVersion::from(0);
    let mut high = latest;
    while high > low + RegistryVersion::from(1) {
        let middle = RegistryVersion::from((low.get() + high.get()) / 2);
        if predicate(middle)? {
            high = middle;
        } else {
            low = middle;
        }
    }

    Ok(high)
}

/// The file the tool records the registry version at which the subnet that is
/// merged away was labeled "cooling down" in, i.e. the `V` of the merge
/// readiness condition.
pub const COOLING_DOWN_REGISTRY_VERSION_FILE: &str = "cooling_down_registry_version";
/// The file the tool records the registry version the merge was applied at in.
pub const MERGE_REGISTRY_VERSION_FILE: &str = "merge_registry_version";

pub fn write_registry_version(path: &Path, version: u64) -> RecoveryResult<()> {
    write_file(path, version.to_string())
}

pub fn read_registry_version(path: &Path) -> RecoveryResult<u64> {
    let contents = read_file(path)?;
    contents.trim().parse().map_err(|err| {
        RecoveryError::UnexpectedError(format!(
            "Failed to parse the registry version {contents:?} at {}: {err}",
            path.display()
        ))
    })
}

/// The registry version at which the subnet that is merged away was labeled
/// "cooling down", as recorded by the tool working in `dir`, i.e. in the
/// directory that was passed to it as `RecoveryArgs::dir`.
pub fn read_cooling_down_registry_version(dir: &Path) -> RecoveryResult<u64> {
    read_registry_version(
        &dir.join(RECOVERY_DIRECTORY_NAME)
            .join(COOLING_DOWN_REGISTRY_VERSION_FILE),
    )
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
            time_nanos: 1_700_000_000_000_000_000,
            state_hash: "deadbeef".to_string(),
        };
        params.write(&path).unwrap();

        assert_eq!(MergedStateParams::read(&path).unwrap(), params);
    }
}
