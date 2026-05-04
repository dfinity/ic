use crate::target_subnet::TargetSubnet;

use ic_base_types::SubnetId;
use ic_recovery::{CHECKPOINTS, CUPS_DIR, IC_STATE, Recovery, error::RecoveryResult};

use std::path::{Path, PathBuf};

#[derive(Clone)]
/// Describes the layout of the working directory of subnet splitting:
///
/// |-- root/
/// |  |-- ${destination_subnet_id}.manifest
/// |  |-- ${source_subnet_id}.manifest
/// |  |-- ${source_subnet_id}.pem
/// |  |-- expected_manifests.data
/// |  |-- original_source_manifest.data
/// |  |-- nns.pem
/// |  |-- pruned_state_tree.cbor
/// |  |-- (destination_)work_dir/
/// |  |   |-- data/
/// |  |   |   |-- cups/cup.types.v1.CatchUpPackage.pb
/// |  |   |   |-- ic_state/checkpoints/
/// |  |   |   |   |-- 1/
/// |  |   |   |   |-- 2/
pub(crate) struct Layout {
    root: PathBuf,

    nns_public_key: PathBuf,
    pruned_state_tree: PathBuf,
    original_state_manifest: PathBuf,
    expected_manifests: PathBuf,
    source_working_dir: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            root: recovery.recovery_dir.clone(),
            nns_public_key: recovery.recovery_dir.join("nns.pem"),
            pruned_state_tree: recovery.recovery_dir.join("pruned_state_tree.cbor"),
            source_working_dir: recovery.work_dir.clone(),
            original_state_manifest: recovery.recovery_dir.join("original_source_manifest.data"),
            expected_manifests: recovery.recovery_dir.join("expected_manifests.data"),
        }
    }

    pub(crate) fn nns_public_key_file(&self) -> &Path {
        &self.nns_public_key
    }

    pub(crate) fn pruned_state_tree_file(&self) -> &Path {
        &self.pruned_state_tree
    }

    pub(crate) fn original_state_manifest_file(&self) -> &Path {
        &self.original_state_manifest
    }

    pub(crate) fn expected_manifests_file(&self) -> &Path {
        &self.expected_manifests
    }

    pub(crate) fn actual_manifest_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{subnet_id}.manifest"))
    }

    pub(crate) fn subnet_public_key_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{subnet_id}.pem"))
    }

    pub(crate) fn data_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.work_dir(target_subnet).join("data")
    }

    pub(crate) fn ic_state_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.data_dir(target_subnet).join(IC_STATE)
    }

    pub(crate) fn checkpoints_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.ic_state_dir(target_subnet).join(CHECKPOINTS)
    }

    pub(crate) fn pre_split_source_cup_file(&self) -> PathBuf {
        self.data_dir(TargetSubnet::Source)
            .join(CUPS_DIR)
            .join("cup.types.v1.CatchUpPackage.pb")
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
