use ic_base_types::SubnetId;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::read_file,
    util::subnet_id_from_str,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_manager::manifest::{manifest_from_path, manifest_hash};
use ic_types::{Time, consensus::CatchUpPackage};

use std::{fmt::Display, path::Path};

pub(crate) fn get_batch_time_from_cup(cup_path: &Path) -> RecoveryResult<Time> {
    get_cup(cup_path).map(|cup| cup.content.block.as_ref().context.time)
}

pub(crate) fn get_cup(cup_path: &Path) -> RecoveryResult<CatchUpPackage> {
    let cup_proto = pb::CatchUpPackage::read_from_file(cup_path)
        .map_err(|err| cup_error("Failed to decode the CUP file", cup_path, err))?;

    CatchUpPackage::try_from(&cup_proto)
        .map_err(|err| cup_error("Failed to deserialize the CUP file", cup_path, err))
}

fn cup_error(message: impl Display, cup_path: &Path, error: impl Display) -> RecoveryError {
    RecoveryError::UnexpectedError(format!("{} ({}): {}", message, cup_path.display(), error))
}

pub(crate) fn canister_id_range_to_string(canister_id_range: &CanisterIdRange) -> String {
    format!("{}:{}", canister_id_range.start, canister_id_range.end)
}

pub fn canister_id_ranges_to_strings(canister_id_ranges: &[CanisterIdRange]) -> Vec<String> {
    canister_id_ranges
        .iter()
        .map(canister_id_range_to_string)
        .collect::<Vec<_>>()
}

/// Computes the state hash of the given checkpoint.
pub(crate) fn get_state_hash(checkpoint_dir: impl AsRef<Path>) -> RecoveryResult<String> {
    let manifest = manifest_from_path(checkpoint_dir.as_ref()).map_err(|e| {
        RecoveryError::CheckpointError(
            format!(
                "Failed to read the manifest from path {}",
                checkpoint_dir.as_ref().display()
            ),
            e,
        )
    })?;

    Ok(hex::encode(manifest_hash(&manifest)))
}

/// Parses the output of `state-tool split-manifests` and finds the expected root hash of the split
/// state for the given subnet.
///
/// The output of the `state-tool` has the following format
///
/// Subnet $subnet_1
/// -------
/// MANIFEST VERSION: V3
/// FILE TABLE
/// (...)
/// ROOT HASH: $root_hash_1
/// =======
/// SUBNET $subnet_2
/// -------
/// MANIFEST VERSION: V3
/// FILE TABLE
/// (...)
/// ROOT HASH: $root_hash_2
/// =======
pub(crate) fn find_expected_state_hash_for_subnet_id(
    path: &Path,
    subnet_id: SubnetId,
) -> RecoveryResult<String> {
    let expected_manifests_content = read_file(path)?;
    let mut is_the_right_section = false;

    for line in expected_manifests_content.lines() {
        if let Some(subnet_id_str) = line.strip_prefix("Subnet ") {
            is_the_right_section = subnet_id == subnet_id_from_str(subnet_id_str)?;
        }

        if let Some(root_hash) = line.strip_prefix("ROOT HASH: ")
            && is_the_right_section
        {
            return Ok(root_hash.to_string());
        }
    }

    Err(RecoveryError::OutputError(
        "Couldn't get the expected state hash".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_recovery::file_sync_helper::write_file;
    use ic_test_utilities_tmpdir::tmpdir;

    #[test]
    fn find_expected_state_hash_for_subnet_id_test() {
        let fake_expected_manifest = include_str!("../test_data/fake_expected_manifests.data");
        let dir = tmpdir("test_dir");
        let path = dir.as_ref().join("expected_manifest.data");

        write_file(&path, fake_expected_manifest.to_string()).unwrap();

        let subnet_id_1 =
            subnet_id_from_str("amug5-wmzps-orth4-td26p-ic6on-bvn7u-nc3up-xu66v-djtcx-oghso-2ae")
                .unwrap();

        let expected_state_hash = find_expected_state_hash_for_subnet_id(&path, subnet_id_1)
            .expect("Failed to find the expected state hash");
        assert_eq!(
            expected_state_hash,
            "18ede3b7ebd377bda19e406a41d3e1b6de1a626ae0b65afb3e2b6ef7f4ea4d46"
        );

        let subnet_id_2 =
            subnet_id_from_str("4heh6-kgou6-qsxov-psrhm-l3pi6-6cc45-c6oyl-pbayl-vayfm-hmxx2-vae")
                .unwrap();

        let expected_state_hash = find_expected_state_hash_for_subnet_id(&path, subnet_id_2)
            .expect("Failed to find the expected state hash");
        assert_eq!(
            expected_state_hash,
            "88953b62a72559bfe1e1647793a61beb81ac6266081628b35133f0c55e0deb46"
        );

        let subnet_id_3 =
            subnet_id_from_str("gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe")
                .unwrap();
        assert!(find_expected_state_hash_for_subnet_id(&path, subnet_id_3).is_err());
    }
}
