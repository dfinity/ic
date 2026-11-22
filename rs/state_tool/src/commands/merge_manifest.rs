//! Computes the manifest expected of the state resulting from a subnet merge.

use super::verify_manifest::parse_manifest;
use ic_state_manager::manifest::merge::merge_manifests;
use ic_state_manager::manifest::{manifest_hash, validate_manifest};
use ic_state_manager::state_sync::types::Manifest;
use ic_types::CryptoHashOfState;
use ic_types::crypto::CryptoHash;
use std::fs::File;
use std::path::Path;

/// Computes the manifest (chunk hashes, file hashes and root hash) expected of
/// the checkpoint that `merge` assembles from the checkpoints whose manifests
/// are at `destination` and `source`, in the format of `manifest`.
pub fn merge_manifest(destination: &Path, source: &Path) -> Result<String, String> {
    let merged = merge_manifests(&read_manifest(destination)?, &read_manifest(source)?)
        .map_err(|err| format!("Failed to merge the manifests: {err}"))?;

    Ok(format!(
        "{}\n\nROOT HASH: {}",
        merged,
        hex::encode(manifest_hash(&merged))
    ))
}

/// Parses the manifest at `path`, checking that it is internally consistent
/// and matches the root hash it states.
fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let (version, files, chunks, hash) = parse_manifest(
        File::open(path)
            .map_err(|err| format!("Failed to open the manifest at {}: {err}", path.display()))?,
    )
    .map_err(|err| format!("Failed to parse the manifest at {}: {err}", path.display()))?;
    let manifest = Manifest::new(version, files, chunks);

    validate_manifest(
        &manifest,
        &CryptoHashOfState::from(CryptoHash(hash.to_vec())),
    )
    .map_err(|err| format!("Invalid manifest at {}: {err}", path.display()))?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::manifest::compute_manifest;
    use crate::commands::merge::do_merge;
    use ic_protobuf::state::system_metadata::v1 as pb_metadata;
    use ic_state_layout::{
        CANISTER_FILE, CANISTER_STATES_DIR, INGRESS_HISTORY_FILE, SNAPSHOT_FILE, SNAPSHOTS_DIR,
        SUBNET_MERGED_FILE, SYSTEM_METADATA_FILE,
    };
    use ic_types::state_sync::CURRENT_STATE_SYNC_VERSION;
    use prost::Message;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Creates a checkpoint under `root` holding system metadata naming
    /// `name`, an ingress history, and the canisters `canisters` with one
    /// snapshot each.
    fn checkpoint(root: &Path, name: &str, canisters: &[&str]) -> PathBuf {
        let checkpoint = root.join(name);
        fs::create_dir_all(&checkpoint).unwrap();
        let system_metadata = pb_metadata::SystemMetadata {
            state_sync_version: CURRENT_STATE_SYNC_VERSION as u32,
            batch_time_nanos: name.len() as u64,
            ..Default::default()
        };
        fs::write(
            checkpoint.join(SYSTEM_METADATA_FILE),
            system_metadata.encode_to_vec(),
        )
        .unwrap();
        fs::write(checkpoint.join(INGRESS_HISTORY_FILE), name).unwrap();
        for canister in canisters {
            let canister_dir = checkpoint.join(CANISTER_STATES_DIR).join(canister);
            fs::create_dir_all(&canister_dir).unwrap();
            fs::write(canister_dir.join(CANISTER_FILE), *canister).unwrap();

            let snapshot_dir = checkpoint
                .join(SNAPSHOTS_DIR)
                .join(canister)
                .join(format!("{canister}0000000000000000"));
            fs::create_dir_all(&snapshot_dir).unwrap();
            fs::write(snapshot_dir.join(SNAPSHOT_FILE), *canister).unwrap();
        }
        checkpoint
    }

    /// Asserts that the manifest of the checkpoint `merge` assembles from
    /// `base` and `source` is the one `merge_manifest` expects from their
    /// manifests.
    fn assert_merged_manifest_is_expected(tmp: &TempDir, base: PathBuf, source: PathBuf) {
        let write_manifest = |checkpoint: &Path, name: &str| {
            let path = tmp.path().join(name);
            fs::write(&path, compute_manifest(checkpoint).unwrap()).unwrap();
            path
        };
        let base_manifest = write_manifest(&base, "base.manifest");
        let source_manifest = write_manifest(&source, "source.manifest");
        let output = tmp.path().join("merged");

        do_merge(base, source, output.clone()).unwrap();

        assert_eq!(
            merge_manifest(&base_manifest, &source_manifest).unwrap(),
            compute_manifest(&output).unwrap()
        );
    }

    // Canister IDs as they name the canister directories of a checkpoint.
    const CANISTER_1: &str = "00000000000000010101";
    const CANISTER_2: &str = "00000000000000020101";
    const CANISTER_3: &str = "00000000000000030101";

    #[test]
    fn merge_manifest_matches_the_merged_checkpoint() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &[CANISTER_1, CANISTER_3]);
        let source = checkpoint(tmp.path(), "source", &[CANISTER_2]);

        assert_merged_manifest_is_expected(&tmp, base, source);
    }

    #[test]
    fn merge_manifest_matches_the_merged_checkpoint_with_entries_not_named_after_canister_ids() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &[CANISTER_1]);
        let source = checkpoint(tmp.path(), "source", &[CANISTER_2]);
        for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
            let entry = source.join(dir).join("other");
            fs::create_dir_all(&entry).unwrap();
            fs::write(entry.join("file"), dir).unwrap();
        }

        assert_merged_manifest_is_expected(&tmp, base, source);
    }

    #[test]
    fn merge_manifest_matches_the_merged_checkpoint_of_a_merged_base() {
        let tmp = TempDir::new().unwrap();
        let base = checkpoint(tmp.path(), "base", &[CANISTER_1]);
        fs::write(
            base.join(SUBNET_MERGED_FILE),
            pb_metadata::SubnetMerged { merged: true }.encode_to_vec(),
        )
        .unwrap();
        let source = checkpoint(tmp.path(), "source", &[CANISTER_2]);

        assert_merged_manifest_is_expected(&tmp, base, source);
    }
}
