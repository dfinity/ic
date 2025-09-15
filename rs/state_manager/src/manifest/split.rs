use super::hash::{ManifestHash, chunk_hasher, file_hasher};
use super::{ManifestValidationError, validate_manifest_internal_consistency, write_chunk_hash};
use crate::state_sync::types::{
    ChunkInfo, DEFAULT_CHUNK_SIZE, FileInfo, MAX_SUPPORTED_STATE_SYNC_VERSION, Manifest,
    ManifestData,
};
use ic_base_types::{SubnetId, subnet_id_into_protobuf};
use ic_protobuf::state::system_metadata::v1 as pb_metadata;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::SystemMetadata;
use ic_state_layout::{
    INGRESS_HISTORY_FILE, SPLIT_MARKER_FILE, STATS_FILE, SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE,
    canister_id_from_path,
};
use ic_types::Time;
use ic_types::state_sync::StateSyncVersion;
use prost::Message;
use std::path::PathBuf;

#[cfg(test)]
mod tests;

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

    let mut chunk_start: usize = 0;
    let split_marker_path = PathBuf::from(SPLIT_MARKER_FILE);
    let mut split_marker_appended = false;
    for (file_index, file) in manifest.file_table.iter().enumerate() {
        let path = file.relative_path.as_path();

        // Insert split marker at the right position.
        if !split_marker_appended && path > split_marker_path {
            manifest_a.append_split_marker(subnet_a);
            manifest_b.append_split_marker(subnet_a);
            split_marker_appended = true;
        }

        let chunk_count: usize = manifest.chunk_table[chunk_start..]
            .iter()
            .take_while(|chunk| chunk.file_index as usize == file_index)
            .count();
        let chunks = &manifest.chunk_table[chunk_start..chunk_start + chunk_count];

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

        chunk_start += chunk_count;
    }
    if !split_marker_appended {
        manifest_a.append_split_marker(subnet_a);
        manifest_b.append_split_marker(subnet_a);
    }

    Ok((manifest_a.build()?, manifest_b.build()?))
}

struct ManifestBuilder {
    manifest: ManifestData,
}

impl ManifestBuilder {
    fn new(version: StateSyncVersion) -> Self {
        Self {
            manifest: ManifestData {
                version,
                file_table: vec![],
                chunk_table: vec![],
            },
        }
    }

    fn build(self) -> Result<Manifest, ManifestValidationError> {
        let manifest = Manifest::new(
            self.manifest.version,
            self.manifest.file_table,
            self.manifest.chunk_table,
        );

        // Sanity check.
        validate_manifest_internal_consistency(&manifest)?;

        Ok(manifest)
    }

    /// Appends `file_info` and `chunks` to `manifest`, adjusting chunk file indices
    /// as necessary.
    fn append(&mut self, file_info: &FileInfo, chunks: &[ChunkInfo]) {
        for mut chunk_info in chunks.iter().cloned() {
            // Set the correct file index.
            chunk_info.file_index = self.manifest.file_table.len() as u32;
            self.manifest.chunk_table.push(chunk_info);
        }

        self.manifest.file_table.push(file_info.clone());
    }

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

    /// Appends a single-chunk file to the manifest.
    fn append_single_chunk_file(&mut self, path: &str, data: &[u8]) {
        assert!(data.len() <= DEFAULT_CHUNK_SIZE as usize);
        let mut file_hasher = file_hasher();

        if data.is_empty() {
            // File has zero chunks.
            0u32.update_hash(&mut file_hasher);
        } else {
            let mut chunk_hasher = chunk_hasher();
            chunk_hasher.write(data);
            let chunk_info = ChunkInfo {
                file_index: self.manifest.file_table.len() as u32,
                size_bytes: data.len() as u32,
                offset: 0,
                hash: chunk_hasher.finish(),
            };

            // File has one chunk.
            1u32.update_hash(&mut file_hasher);
            write_chunk_hash(&mut file_hasher, &chunk_info, self.manifest.version);

            self.manifest.chunk_table.push(chunk_info);
        };

        self.manifest.file_table.push(FileInfo {
            relative_path: PathBuf::from(path),
            size_bytes: data.len() as u64,
            hash: file_hasher.finish(),
        });
    }
}
