use crate::target_subnet::TargetSubnet;

use ic_base_types::SubnetId;
use ic_recovery::{error::RecoveryResult, Recovery, CHECKPOINTS, IC_STATE_DIR};

use std::path::{Path, PathBuf};

#[derive(Clone)]
/// Describes the layout of the working directory of subnet splitting:
///
/// |-- root/
/// |  |-- ${source_subnet_id}.manifest
/// |  |-- ${destination_subnet_id}.manifest
/// |  |-- original_source_manifest.data
/// |  |-- expected_manifests.data
/// |  |-- (destination_)work_dir/
/// |  |   |-- data/
/// |  |   |   |-- ic_state/checkpoints/
/// |  |   |   |   |-- 1/
/// |  |   |   |   |-- 2/
pub(crate) struct Layout {
    root: PathBuf,

    original_state_manifest: PathBuf,
    expected_manifests: PathBuf,
    source_working_dir: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            root: recovery.recovery_dir.clone(),
            source_working_dir: recovery.work_dir.clone(),
            original_state_manifest: recovery.recovery_dir.join("original_source_manifest.data"),
            expected_manifests: recovery.recovery_dir.join("expected_manifests.data"),
        }
    }

    pub(crate) fn original_state_manifest_file(&self) -> &Path {
        &self.original_state_manifest
    }

    pub(crate) fn expected_manifests_file(&self) -> &Path {
        &self.expected_manifests
    }

    pub(crate) fn actual_manifest_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{}.manifest", subnet_id))
    }

    pub(crate) fn ic_state_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.work_dir(target_subnet).join(IC_STATE_DIR)
    }

    pub(crate) fn checkpoints_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.ic_state_dir(target_subnet).join(CHECKPOINTS)
    }

    pub(crate) fn work_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        match target_subnet {
            TargetSubnet::Source => self.source_working_dir.clone(),
            TargetSubnet::Destination => self.root.join("destination_working_dir"),
        }
    }

    pub(crate) fn latest_checkpoint_dir(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<PathBuf> {
        let checkpoints_dir = self.checkpoints_dir(target_subnet);

        let (max_name, _) = Recovery::get_latest_checkpoint_name_and_height(&checkpoints_dir)?;

        Ok(checkpoints_dir.join(max_name))
    }
}
