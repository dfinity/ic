//! Assembles a manifest file by file, as the manifests of the states resulting
//! from a subnet split or merge are derived from the manifests of their inputs.

use super::hash::{ManifestHash, chunk_hasher, file_hasher};
use super::{ManifestValidationError, validate_manifest_internal_consistency, write_chunk_hash};
use crate::state_sync::types::{ChunkInfo, DEFAULT_CHUNK_SIZE, FileInfo, Manifest, ManifestData};
use ic_types::state_sync::StateSyncVersion;
use std::path::PathBuf;

pub(super) struct ManifestBuilder {
    manifest: ManifestData,
}

impl ManifestBuilder {
    pub(super) fn new(version: StateSyncVersion) -> Self {
        Self {
            manifest: ManifestData {
                version,
                file_table: vec![],
                chunk_table: vec![],
            },
        }
    }

    /// Builds the manifest, checking that it is internally consistent, e.g.
    /// that its files were appended in the order of their paths.
    pub(super) fn build(self) -> Result<Manifest, ManifestValidationError> {
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
    pub(super) fn append(&mut self, file_info: &FileInfo, chunks: &[ChunkInfo]) {
        for mut chunk_info in chunks.iter().cloned() {
            // Set the correct file index.
            chunk_info.file_index = self.manifest.file_table.len() as u32;
            self.manifest.chunk_table.push(chunk_info);
        }

        self.manifest.file_table.push(file_info.clone());
    }

    /// Appends a single-chunk file to the manifest.
    pub(super) fn append_single_chunk_file(&mut self, path: &str, data: &[u8]) {
        assert!(data.len() <= DEFAULT_CHUNK_SIZE as usize);
        let mut file_hasher = file_hasher();

        if data.is_empty() {
            // File has zero chunks.
            0_u32.update_hash(&mut file_hasher);
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
            1_u32.update_hash(&mut file_hasher);
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

/// The files of `manifest`, each with its chunks, in the order of the file
/// table. Assumes that `manifest` is internally consistent.
pub(super) fn files_with_chunks(
    manifest: &Manifest,
) -> impl Iterator<Item = (&FileInfo, &[ChunkInfo])> {
    let mut chunk_start = 0;
    manifest
        .file_table
        .iter()
        .enumerate()
        .map(move |(file_index, file)| {
            let chunk_count = manifest.chunk_table[chunk_start..]
                .iter()
                .take_while(|chunk| chunk.file_index as usize == file_index)
                .count();
            let chunks = &manifest.chunk_table[chunk_start..chunk_start + chunk_count];
            chunk_start += chunk_count;
            (file, chunks)
        })
}
