use crate::utils::{read_registry_version, write_registry_version};

use ic_recovery::{Recovery, error::RecoveryResult};

use std::path::PathBuf;

/// The file the tool records the registry version at which the subnet that is
/// merged away was labeled "cooling down" in, i.e. the `V` of the merge
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

    /// The registry version at which the subnet that is merged away was
    /// labeled "cooling down", i.e. the `V` of the merge readiness condition.
    pub(crate) fn write_cooling_down_registry_version(&self, version: u64) -> RecoveryResult<()> {
        write_registry_version(&self.cooling_down_registry_version, version)
    }

    pub(crate) fn read_cooling_down_registry_version(&self) -> RecoveryResult<u64> {
        read_registry_version(&self.cooling_down_registry_version)
    }
}
