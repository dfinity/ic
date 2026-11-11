use crate::target_subnet::TargetSubnet;

use ic_base_types::SubnetId;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    CHECKPOINTS, IC_STATE, Recovery,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{create_dir, read_file, write_bytes, write_file},
};
use prost::Message;
use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

/// The file in which the tool records a registry version at which the subnet
/// that is merged away is labeled "cooling down", i.e. the `V` of the merge
/// readiness condition, together with the id of that subnet.
const COOLING_DOWN_REGISTRY_VERSION_FILE: &str = "cooling_down_registry_version.json";

/// The contents of `COOLING_DOWN_REGISTRY_VERSION_FILE`.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct CoolingDownRegistryVersion {
    source_subnet_id: SubnetId,
    registry_version: u64,
}

#[derive(Clone)]
/// Describes the layout of the working directory of subnet merging:
///
/// |-- root/
/// |  |-- ${source_subnet_id}.manifest
/// |  |-- ${destination_subnet_id}.manifest
/// |  |-- ${source_subnet_id}.pem
/// |  |-- ${destination_subnet_id}.pem
/// |  |-- cooling_down_registry_version.json
/// |  |-- nns.pem
/// |  |-- ${source_subnet_id}.pruned_state_tree.cbor
/// |  |-- ${destination_subnet_id}.pruned_state_tree.cbor
/// |  |-- halting_cup_${source_subnet_id}.pb
/// |  |-- halting_cup_${destination_subnet_id}.pb
/// |  |-- (destination_)work_dir/
/// |  |   |-- data/
/// |  |   |   |-- ic_state/states_metadata.pbuf
/// |  |   |   |-- ic_state/checkpoints/
/// |  |   |   |   |-- 1/
pub(crate) struct Layout {
    root: PathBuf,
    source_working_dir: PathBuf,
    nns_public_key: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            root: recovery.recovery_dir.clone(),
            source_working_dir: recovery.work_dir.clone(),
            nns_public_key: recovery.recovery_dir.join("nns.pem"),
        }
    }

    /// Creates the working directories of the two subnets being merged.
    /// `Recovery` only creates the one working directory a recovery has, which
    /// is the source subnet's here.
    pub(crate) fn create_dirs(&self) -> RecoveryResult<()> {
        for target_subnet in [TargetSubnet::Source, TargetSubnet::Destination] {
            create_dir(&self.data_dir(target_subnet))?;
        }

        Ok(())
    }

    pub(crate) fn nns_public_key_file(&self) -> &Path {
        &self.nns_public_key
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

    pub(crate) fn work_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        match target_subnet {
            TargetSubnet::Source => self.source_working_dir.clone(),
            TargetSubnet::Destination => self.root.join("destination_working_dir"),
        }
    }

    pub(crate) fn data_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.work_dir(target_subnet).join("data")
    }

    pub(crate) fn checkpoints_dir(&self, target_subnet: TargetSubnet) -> PathBuf {
        self.data_dir(target_subnet)
            .join(IC_STATE)
            .join(CHECKPOINTS)
    }

    pub(crate) fn latest_checkpoint_dir(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<PathBuf> {
        let checkpoints_dir = self.checkpoints_dir(target_subnet);

        let (max_name, _) = Recovery::get_latest_checkpoint_name_and_height(&checkpoints_dir)?;

        Ok(checkpoints_dir.join(max_name))
    }

    fn cooling_down_registry_version_file(&self) -> PathBuf {
        self.root.join(COOLING_DOWN_REGISTRY_VERSION_FILE)
    }

    /// A registry version at which the subnet that is merged away is labeled
    /// "cooling down", i.e. the `V` of the merge readiness condition.
    ///
    /// The version is recorded together with the id of the subnet, so that a
    /// run resumed with a different subnet to merge away does not evaluate the
    /// readiness condition against a version that says nothing about it.
    pub(crate) fn write_cooling_down_registry_version(
        &self,
        source_subnet_id: SubnetId,
        version: u64,
    ) -> RecoveryResult<()> {
        write_file(
            &self.cooling_down_registry_version_file(),
            encode_cooling_down_registry_version(source_subnet_id, version),
        )
    }

    /// Reads the registry version recorded for `source_subnet_id`, failing if
    /// it was recorded for a different subnet.
    pub(crate) fn read_cooling_down_registry_version(
        &self,
        source_subnet_id: SubnetId,
    ) -> RecoveryResult<u64> {
        let path = self.cooling_down_registry_version_file();
        decode_cooling_down_registry_version(&read_file(&path)?, source_subnet_id).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to read the registry version at {}: {err}",
                path.display()
            ))
        })
    }

    /// The file holding the CUP `subnet_id` halts at, as a
    /// `types.v1.CatchUpPackage` protobuf, i.e. in the format of the CUP file
    /// of a replica.
    pub(crate) fn halting_cup_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("halting_cup_{subnet_id}.pb"))
    }

    /// Records the CUP `subnet_id` halts at, as served by a node of the
    /// subnet, so that the state downloaded later can be validated against it
    /// without downloading the CUP again.
    pub(crate) fn write_halting_cup(
        &self,
        subnet_id: SubnetId,
        cup: &pb::CatchUpPackage,
    ) -> RecoveryResult<()> {
        write_bytes(&self.halting_cup_file(subnet_id), cup.encode_to_vec())
    }
}

fn encode_cooling_down_registry_version(source_subnet_id: SubnetId, version: u64) -> String {
    serde_json::to_string_pretty(&CoolingDownRegistryVersion {
        source_subnet_id,
        registry_version: version,
    })
    .expect("Failed to serialize the cooling down registry version")
}

fn decode_cooling_down_registry_version(
    contents: &str,
    source_subnet_id: SubnetId,
) -> Result<u64, String> {
    let recorded: CoolingDownRegistryVersion =
        serde_json::from_str(contents).map_err(|err| err.to_string())?;
    if recorded.source_subnet_id != source_subnet_id {
        return Err(format!(
            "the registry version was recorded for subnet {}, not for subnet {source_subnet_id}",
            recorded.source_subnet_id
        ));
    }
    Ok(recorded.registry_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_base_types::PrincipalId;

    fn subnet_id(id: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(id))
    }

    #[test]
    fn cooling_down_registry_version_round_trips() {
        let contents = encode_cooling_down_registry_version(subnet_id(1), 42);
        assert_eq!(
            decode_cooling_down_registry_version(&contents, subnet_id(1)),
            Ok(42)
        );
    }

    #[test]
    fn cooling_down_registry_version_of_another_subnet_is_rejected() {
        let contents = encode_cooling_down_registry_version(subnet_id(1), 42);
        let err = decode_cooling_down_registry_version(&contents, subnet_id(2)).unwrap_err();
        assert!(err.contains("not for subnet"), "{err}");
    }

    #[test]
    fn halting_cup_round_trips() {
        let root =
            std::env::temp_dir().join(format!("subnet_merging_layout_test_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let layout = Layout {
            root: root.clone(),
            source_working_dir: root.join("work_dir"),
            nns_public_key: root.join("nns.pem"),
        };
        let cup = pb::CatchUpPackage {
            content: vec![1, 2, 3],
            signature: vec![4, 5],
            signer: None,
        };

        layout.write_halting_cup(subnet_id(1), &cup).unwrap();

        assert_eq!(
            pb::CatchUpPackage::read_from_file(layout.halting_cup_file(subnet_id(1))).unwrap(),
            cup
        );
        assert!(pb::CatchUpPackage::read_from_file(layout.halting_cup_file(subnet_id(2))).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_cooling_down_registry_version_is_rejected() {
        assert!(decode_cooling_down_registry_version("42", subnet_id(1)).is_err());
    }
}
