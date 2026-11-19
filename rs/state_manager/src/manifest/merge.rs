use super::builder::{ManifestBuilder, files_with_chunks};
use super::{ManifestValidationError, validate_manifest_internal_consistency};
use crate::state_sync::types::{ChunkInfo, FileInfo, MAX_SUPPORTED_STATE_SYNC_VERSION, Manifest};
use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_state_layout::{CANISTER_STATES_DIR, SNAPSHOTS_DIR, SUBNET_MERGED_FILE};
use ic_types::state_sync::StateSyncVersion;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

#[cfg(test)]
mod tests;

/// Merges the manifests of the states of the two subnets of a subnet merge:
/// `destination`, the state the merged state is based on, and `source`, the
/// state of the subnet that is merged away. Returns the manifest of the merged
/// state.
///
/// This is intended to replicate the exact manifest computed from the
/// checkpoint that `ic-state-tool merge` assembles from the two checkpoints:
/// every file of `destination` and every file under `canister_states/` and
/// `snapshots/` of `source`, plus a `subnet_merged.pbuf` marking the result of a
/// merge, which replaces any marker that `destination` holds.
///
/// Only supports manifest versions 3 and up (because earlier versions had
/// position-dependent file hashes and this function for the sake of simplicity
/// does not recompute file hashes).
pub fn merge_manifests(
    destination: &Manifest,
    source: &Manifest,
) -> Result<Manifest, ManifestValidationError> {
    for manifest in [destination, source] {
        if manifest.version > MAX_SUPPORTED_STATE_SYNC_VERSION
            || manifest.version < StateSyncVersion::V3
        {
            return Err(ManifestValidationError::UnsupportedManifestVersion {
                manifest_version: manifest.version,
                max_supported_version: MAX_SUPPORTED_STATE_SYNC_VERSION,
            });
        }
        // Sanity check.
        validate_manifest_internal_consistency(manifest)?;
    }
    if destination.version != source.version {
        return Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "the destination manifest has version {:?} and the source manifest version {:?}",
                destination.version, source.version
            ),
        });
    }

    // The canisters of the two subnets are disjoint, so a collision means these
    // two manifests are not of the same merge.
    let source_canister_dirs = canister_dirs(source);
    if let Some(dir) = canister_dirs(destination)
        .intersection(&source_canister_dirs)
        .next()
    {
        return Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "both manifests hold files in {}",
                dir.iter()
                    .map(|component| component.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/")
            ),
        });
    }

    let merged_files: BTreeMap<&Path, (&FileInfo, &[ChunkInfo])> = files_with_chunks(destination)
        .filter(|(file, _)| file.relative_path != Path::new(SUBNET_MERGED_FILE))
        .chain(
            files_with_chunks(source)
                .filter(|(file, _)| canister_dir(&file.relative_path).is_some()),
        )
        .map(|(file, chunks)| (file.relative_path.as_path(), (file, chunks)))
        .collect();

    let mut builder = ManifestBuilder::new(destination.version);
    let marker_path = Path::new(SUBNET_MERGED_FILE);
    let mut marker_appended = false;
    for (path, (file, chunks)) in merged_files {
        // Insert the marker at the right position.
        if !marker_appended && path > marker_path {
            builder.append_subnet_merged_marker();
            marker_appended = true;
        }
        builder.append(file, chunks);
    }
    if !marker_appended {
        builder.append_subnet_merged_marker();
    }

    builder.build()
}

/// The entries of `canister_states/` and `snapshots/` that `manifest` holds
/// files in, e.g. `canister_states/<canister ID>`.
fn canister_dirs(manifest: &Manifest) -> BTreeSet<[&OsStr; 2]> {
    manifest
        .file_table
        .iter()
        .filter_map(|file| canister_dir(&file.relative_path))
        .collect()
}

/// The entry of `canister_states/` or `snapshots/` that `path` is or is in,
/// e.g. `canister_states/<canister ID>`, if any. A merge takes these entries
/// over from the source as a whole, whatever their names.
fn canister_dir(path: &Path) -> Option<[&OsStr; 2]> {
    let mut components = path.iter();
    let top_level = components.next()?;
    if top_level != OsStr::new(CANISTER_STATES_DIR) && top_level != OsStr::new(SNAPSHOTS_DIR) {
        return None;
    }
    Some([top_level, components.next()?])
}

impl ManifestBuilder {
    /// Appends the marker of a state resulting from a subnet merge.
    fn append_subnet_merged_marker(&mut self) {
        let marker_bytes = pb_metadata::SubnetMerged { merged: true }.encode_to_vec();

        self.append_single_chunk_file(SUBNET_MERGED_FILE, &marker_bytes);
    }
}
