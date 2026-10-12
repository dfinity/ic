use ic_recovery::{
    Recovery,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
};

use std::path::PathBuf;

/// The file the tool records a registry version at which the subnet that is
/// merged away is labeled "cooling down" in, i.e. the `V` of the merge
/// readiness condition.
const COOLING_DOWN_REGISTRY_VERSION_FILE: &str = "cooling_down_registry_version";

#[derive(Clone)]
/// Describes the layout of the working directory of subnet merging:
///
/// |-- root/
/// |  |-- cooling_down_registry_version
pub(crate) struct Layout {
    cooling_down_registry_version: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            cooling_down_registry_version: recovery
                .recovery_dir
                .join(COOLING_DOWN_REGISTRY_VERSION_FILE),
        }
    }

    /// A registry version at which the subnet that is merged away is labeled
    /// "cooling down", i.e. the `V` of the merge readiness condition.
    pub(crate) fn write_cooling_down_registry_version(&self, version: u64) -> RecoveryResult<()> {
        write_file(&self.cooling_down_registry_version, version.to_string())
    }

    pub(crate) fn read_cooling_down_registry_version(&self) -> RecoveryResult<u64> {
        let path = &self.cooling_down_registry_version;
        let contents = read_file(path)?;
        contents.trim().parse().map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to parse the registry version {contents:?} at {}: {err}",
                path.display()
            ))
        })
    }
}
