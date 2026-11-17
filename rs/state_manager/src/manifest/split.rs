use super::builder::{ManifestBuilder, files_with_chunks};
use super::{ManifestValidationError, validate_manifest_internal_consistency};
use crate::state_sync::types::{MAX_SUPPORTED_STATE_SYNC_VERSION, Manifest};
use ic_base_types::{SubnetId, subnet_id_into_protobuf};
use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::SystemMetadata;
use ic_state_layout::{
    INGRESS_HISTORY_FILE, SPLIT_MARKER_FILE, STATS_FILE, SUBNET_MERGED_FILE, SUBNET_QUEUES_FILE,
    SYSTEM_METADATA_FILE, canister_id_from_path,
};
use ic_types::Time;
use ic_types::state_sync::StateSyncVersion;
use prost::Message;
use std::path::PathBuf;

#[cfg(test)]
pub(super) mod tests;

/// Splits a manifest, assumed to be that of `subnet_a`, distributing all
/// canister states between `subnet_a` and `subnet_b`, based on the mapping in
/// `routing_table`. Returns the two manifests resulting from the split.
///
/// This is intended to replicate the exact manifests computed from the outputs
/// of calling `ReplicatedState::split()` with the same `RoutingTable` and each
/// of the subnet IDs. This also means, among other things, that both resulting
/// manifests will include a new `split_from.pbuf` file; and that the `subnet_b`
/// manifest will have an empty `subnet_queues.pbuf` and a fresh, minimal
/// `system_metadata.pbuf` (having the `subnet_b` own ID; and the given original
/// state subnet type and batch time).
///
/// Only supports manifest versions 3 and up (because earlier versions had
/// position-dependent file hashes and this function for the sake of simplicity
/// does not recompute file hashes).
pub fn split_manifest(
    manifest: &Manifest,
    subnet_a: SubnetId,
    subnet_b: SubnetId,
    subnet_type: SubnetType,
    batch_time: Time,
    routing_table: &RoutingTable,
) -> Result<(Manifest, Manifest), ManifestValidationError> {
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

    let mut manifest_a = ManifestBuilder::new(manifest.version);
    let mut manifest_b = ManifestBuilder::new(manifest.version);

    let split_marker_path = PathBuf::from(SPLIT_MARKER_FILE);
    let mut split_marker_appended = false;
    for (file, chunks) in files_with_chunks(manifest) {
        let path = file.relative_path.as_path();

        // Insert split marker at the right position.
        if !split_marker_appended && path > split_marker_path {
            manifest_a.append_split_marker(subnet_a);
            manifest_b.append_split_marker(subnet_a);
            split_marker_appended = true;
        }

        if let Some(canister_id) = canister_id_from_path(path) {
            // Part of a canister state.
            let subnet = routing_table
                .lookup_entry(canister_id)
                .map(|(_range, subnet_id)| subnet_id);
            if subnet == Some(subnet_a) {
                // Retained on subnet A'.
                manifest_a.append(file, chunks);
            } else if subnet == Some(subnet_b) {
                // Migrated to subnet B.
                manifest_b.append(file, chunks);
            } else {
                return Err(ManifestValidationError::InconsistentManifest {
                    reason: format!(
                        "canister {canister_id} is mapped to neither subnet A' ({subnet_a}) nor subnet B ({subnet_b})"
                    ),
                });
            }
        } else {
            match path.to_str() {
                Some(INGRESS_HISTORY_FILE) => {
                    // Ingress history is preserved unmodified on both sides.
                    manifest_a.append(file, chunks);
                    manifest_b.append(file, chunks);
                }
                Some(SPLIT_MARKER_FILE) => {
                    return Err(ManifestValidationError::InconsistentManifest {
                        reason: "state is already undergoing a split".into(),
                    });
                }
                Some(SUBNET_MERGED_FILE) => {
                    // `SystemMetadata::split()` asserts that the state was not just
                    // merged, so this manifest cannot be the input of a split.
                    return Err(ManifestValidationError::InconsistentManifest {
                        reason: "state was just merged".into(),
                    });
                }
                Some(SUBNET_QUEUES_FILE) => {
                    // Preserve on subnet A'.
                    manifest_a.append(file, chunks);

                    // Replace with empty file on subnet B.
                    manifest_b.append_single_chunk_file(SUBNET_QUEUES_FILE, &[])
                }
                Some(SYSTEM_METADATA_FILE) => {
                    manifest_a.append(file, chunks);

                    // Replace with default on subnet B.
                    manifest_b.append_system_metadata(subnet_b, subnet_type, batch_time);
                }
                Some(STATS_FILE) => {
                    // Append empty stats file
                    let empty_stats = ic_protobuf::state::stats::v1::Stats { query_stats: None };
                    let as_protobuf = empty_stats.encode_to_vec();

                    // Don't write the file if it's empty. This is an optimization done by MR
                    // If the serialized protobuf will ever not be empty, need to write the
                    // file via append_single_chunk_file
                    assert_eq!(as_protobuf.len(), 0);
                }
                _ => {
                    return Err(ManifestValidationError::InconsistentManifest {
                        reason: format!("unknown file in manifest: {}", path.display()),
                    });
                }
            }
        }
    }
    if !split_marker_appended {
        manifest_a.append_split_marker(subnet_a);
        manifest_b.append_split_marker(subnet_a);
    }

    Ok((manifest_a.build()?, manifest_b.build()?))
}

impl ManifestBuilder {
    /// Appends a `SystemMetadata` consisting of only the provided `own_subnet_id`,
    /// `own_subnet_type` and `batch_time`.
    fn append_system_metadata(
        &mut self,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        batch_time: Time,
    ) {
        let mut system_metadata = SystemMetadata::new(subnet_id, subnet_type);
        system_metadata.batch_time = batch_time;
        let mut system_metadata_bytes = Vec::new();
        pb_metadata::SystemMetadata::from(&system_metadata)
            .encode(&mut system_metadata_bytes)
            .unwrap();

        self.append_single_chunk_file(SYSTEM_METADATA_FILE, system_metadata_bytes.as_slice())
    }

    fn append_split_marker(&mut self, from_subnet: SubnetId) {
        let mut split_marker_bytes = Vec::new();
        pb_metadata::SplitFrom {
            subnet_id: Some(subnet_id_into_protobuf(from_subnet)),
        }
        .encode(&mut split_marker_bytes)
        .unwrap();

        self.append_single_chunk_file(SPLIT_MARKER_FILE, split_marker_bytes.as_slice());
    }
}
