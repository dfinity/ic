use ic_base_types::SubnetId;
use ic_recovery::{
    Recovery,
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::{read_file, write_file},
    util::subnet_id_from_str,
};

use std::path::PathBuf;

/// The file the tool records a registry version at which the subnet that is
/// merged away is labeled "cooling down" in, i.e. the `V` of the merge
/// readiness condition, together with the id of that subnet.
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
            &self.cooling_down_registry_version,
            encode_cooling_down_registry_version(source_subnet_id, version),
        )
    }

    /// Reads the registry version recorded for `source_subnet_id`, failing if
    /// it was recorded for a different subnet.
    pub(crate) fn read_cooling_down_registry_version(
        &self,
        source_subnet_id: SubnetId,
    ) -> RecoveryResult<u64> {
        let path = &self.cooling_down_registry_version;
        decode_cooling_down_registry_version(&read_file(path)?, source_subnet_id).map_err(|err| {
            RecoveryError::UnexpectedError(format!(
                "Failed to read the registry version at {}: {err}",
                path.display()
            ))
        })
    }
}

fn encode_cooling_down_registry_version(source_subnet_id: SubnetId, version: u64) -> String {
    format!("{source_subnet_id} {version}")
}

fn decode_cooling_down_registry_version(
    contents: &str,
    source_subnet_id: SubnetId,
) -> Result<u64, String> {
    let Some((subnet_id, version)) = contents.trim().split_once(' ') else {
        return Err(format!(
            "expected a subnet id and a registry version, got {contents:?}"
        ));
    };
    let subnet_id = subnet_id_from_str(subnet_id).map_err(|err| err.to_string())?;
    if subnet_id != source_subnet_id {
        return Err(format!(
            "the registry version was recorded for subnet {subnet_id}, not for subnet \
             {source_subnet_id}"
        ));
    }
    version
        .parse()
        .map_err(|err| format!("failed to parse the registry version {version:?}: {err}"))
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
    fn cooling_down_registry_version_without_subnet_id_is_rejected() {
        assert!(decode_cooling_down_registry_version("42", subnet_id(1)).is_err());
    }
}
