use crate::{
    target_subnet::TargetSubnet,
    utils::{
        COOLING_DOWN_REGISTRY_VERSION_FILE, MERGE_REGISTRY_VERSION_FILE, read_registry_version,
        write_registry_version,
    },
};

use ic_base_types::SubnetId;
use ic_recovery::{
    CHECKPOINTS, CUPS_DIR, IC_STATE, Recovery, error::RecoveryResult, file_sync_helper::create_dir,
};
use ic_state_layout::StateLayout;
use ic_types::Height;

use std::path::{Path, PathBuf};

/// The name the orchestrator stores the latest CUP of a subnet under.
pub(crate) const CUP_FILE_NAME: &str = "cup.types.v1.CatchUpPackage.pb";

#[derive(Clone)]
/// Describes the layout of the working directory of subnet merging:
///
/// |-- root/
/// |  |-- ${destination_subnet_id}.manifest
/// |  |-- ${source_subnet_id}.manifest
/// |  |-- ${source_subnet_id}.pem
/// |  |-- ${destination_subnet_id}.pem
/// |  |-- merged.manifest
/// |  |-- merged_state_params.json
/// |  |-- cooling_down_registry_version
/// |  |-- merge_registry_version
/// |  |-- nns.pem
/// |  |-- ${source_subnet_id}.pruned_state_tree.cbor
/// |  |-- ${destination_subnet_id}.pruned_state_tree.cbor
/// |  |-- ${source_subnet_id}.halting_cup.pb
/// |  |-- ${destination_subnet_id}.halting_cup.pb
/// |  |-- (destination_|merged_)work_dir/
/// |  |   |-- data/
/// |  |   |   |-- cups/cup.types.v1.CatchUpPackage.pb
/// |  |   |   |-- ic_state/states_metadata.pbuf
/// |  |   |   |-- ic_state/checkpoints/
/// |  |   |   |   |-- 1/
pub(crate) struct Layout {
    root: PathBuf,
    source_working_dir: PathBuf,

    nns_public_key: PathBuf,
    merged_state_manifest: PathBuf,
    merged_state_params: PathBuf,
    cooling_down_registry_version: PathBuf,
    merge_registry_version: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            root: recovery.recovery_dir.clone(),
            source_working_dir: recovery.work_dir.clone(),
            nns_public_key: recovery.recovery_dir.join("nns.pem"),
            merged_state_manifest: recovery.recovery_dir.join("merged.manifest"),
            merged_state_params: recovery.recovery_dir.join("merged_state_params.json"),
            cooling_down_registry_version: recovery
                .recovery_dir
                .join(COOLING_DOWN_REGISTRY_VERSION_FILE),
            merge_registry_version: recovery.recovery_dir.join(MERGE_REGISTRY_VERSION_FILE),
        }
    }

    /// Creates the working directories of the two subnets being merged and of
    /// the merged state. `Recovery` only creates the one working directory a
    /// recovery has, which is the source subnet's here.
    pub(crate) fn create_dirs(&self) -> RecoveryResult<()> {
        for target_subnet in [
            TargetSubnet::Source,
            TargetSubnet::Destination,
            TargetSubnet::Merged,
        ] {
            create_dir(&self.data_dir(target_subnet))?;
        }

        Ok(())
    }

    pub(crate) fn nns_public_key_file(&self) -> &Path {
        &self.nns_public_key
    }

    pub(crate) fn merged_state_manifest_file(&self) -> &Path {
        &self.merged_state_manifest
    }

    pub(crate) fn merged_state_params_file(&self) -> &Path {
        &self.merged_state_params
    }

    /// The registry version at which the subnet that is merged away was
    /// labeled "cooling down", i.e. the `V` of the merge readiness condition.
    pub(crate) fn write_cooling_down_registry_version(&self, version: u64) -> RecoveryResult<()> {
        write_registry_version(&self.cooling_down_registry_version, version)
    }

    pub(crate) fn read_cooling_down_registry_version(&self) -> RecoveryResult<u64> {
        read_registry_version(&self.cooling_down_registry_version)
    }

    /// The registry version the merge was applied at, i.e. the one every other
    /// subnet has to have reached before the merged subnet may be deleted.
    pub(crate) fn write_merge_registry_version(&self, version: u64) -> RecoveryResult<()> {
        write_registry_version(&self.merge_registry_version, version)
    }

    pub(crate) fn read_merge_registry_version(&self) -> RecoveryResult<u64> {
        read_registry_version(&self.merge_registry_version)
    }

    pub(crate) fn actual_manifest_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{subnet_id}.manifest"))
    }

    pub(crate) fn subnet_public_key_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{subnet_id}.pem"))
    }

    pub(crate) fn pruned_state_tree_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root
            .join(format!("{subnet_id}.pruned_state_tree.cbor"))
    }

    /// The copy of the CUP a subnet halted at that is pulled off its node while
    /// waiting for the halt, before the state is downloaded.
    pub(crate) fn halting_cup_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("{subnet_id}.halting_cup.pb"))
    }

    /// The CUP that came with the downloaded state, i.e. the one the validation
    /// of the downloaded state checks against.
    pub(crate) fn downloaded_cup_file(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.data_dir(target_subnet)
            .join(CUPS_DIR)
            .join(CUP_FILE_NAME)
    }

    pub(crate) fn work_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        match target_subnet {
            TargetSubnet::Source => self.source_working_dir.clone(),
            TargetSubnet::Destination => self.root.join("destination_working_dir"),
            TargetSubnet::Merged => self.root.join("merged_working_dir"),
        }
    }

    /// Where the state of a subnet is downloaded to when the downloaded state
    /// is to be kept, before it is copied into the working directory.
    pub(crate) fn original_data_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.work_dir(target_subnet).join("original_data")
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

    pub(crate) fn checkpoint_dir(&self, target_subnet: TargetSubnet, height: Height) -> PathBuf {
        self.checkpoints_dir(target_subnet)
            .join(StateLayout::checkpoint_name(height))
    }

    pub(crate) fn latest_checkpoint_dir(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<PathBuf> {
        let checkpoints_dir = self.checkpoints_dir(target_subnet);

        let (max_name, _) = Recovery::get_latest_checkpoint_name_and_height(&checkpoints_dir)?;

        Ok(checkpoints_dir.join(max_name))
    }

    pub(crate) fn latest_checkpoint_height(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<Height> {
        Recovery::get_latest_checkpoint_name_and_height(&self.checkpoints_dir(target_subnet))
            .map(|(_, height)| height)
    }
}
