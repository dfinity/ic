use ic_base_types::SubnetId;
use ic_recovery::{
    Recovery,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
};
use serde::{Deserialize, Serialize};

use std::path::PathBuf;

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

/// The contents of the file in which the tool records the height, registry
/// version and state hash of the CUP a subnet halts at.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct HaltingCup {
    pub(crate) height: u64,
    pub(crate) registry_version: u64,
    /// Hex-encoded.
    pub(crate) state_hash: String,
}

#[derive(Clone)]
/// Describes the layout of the working directory of subnet merging:
///
/// |-- root/
/// |  |-- cooling_down_registry_version.json
/// |  |-- halting_cup_<subnet_id>.json
pub(crate) struct Layout {
    root: PathBuf,
}

impl Layout {
    pub(crate) fn new(recovery: &Recovery) -> Self {
        Self {
            root: recovery.recovery_dir.clone(),
        }
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

    fn halting_cup_file(&self, subnet_id: SubnetId) -> PathBuf {
        self.root.join(format!("halting_cup_{subnet_id}.json"))
    }

    /// Records the height, registry version and state hash of the CUP
    /// `subnet_id` halts at, so that the step downloading its state can check that the CUP it
    /// downloads is that same CUP.
    pub(crate) fn write_halting_cup(
        &self,
        subnet_id: SubnetId,
        halting_cup: &HaltingCup,
    ) -> RecoveryResult<()> {
        write_file(
            &self.halting_cup_file(subnet_id),
            serde_json::to_string_pretty(halting_cup).expect("Failed to serialize the halting CUP"),
        )
    }

    /// Reads the height, registry version and state hash of the CUP
    /// `subnet_id` halts at.
    // Read by the step downloading the state, added in a follow-up.
    #[allow(dead_code)]
    pub(crate) fn read_halting_cup(&self, subnet_id: SubnetId) -> RecoveryResult<HaltingCup> {
        let path = self.halting_cup_file(subnet_id);
        serde_json::from_str(&read_file(&path)?).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to read the halting CUP at {}: {err}",
                path.display()
            ))
        })
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
        let layout = Layout { root: root.clone() };
        let halting_cup = HaltingCup {
            height: 500,
            registry_version: 42,
            state_hash: "0123abcd".to_string(),
        };

        layout
            .write_halting_cup(subnet_id(1), &halting_cup)
            .unwrap();

        assert_eq!(layout.read_halting_cup(subnet_id(1)).unwrap(), halting_cup);
        assert!(layout.read_halting_cup(subnet_id(2)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_cooling_down_registry_version_is_rejected() {
        assert!(decode_cooling_down_registry_version("42", subnet_id(1)).is_err());
    }
}
