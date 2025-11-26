//! Conversions from Rust to proto structs and back for `StateSync`.
use crate::state_sync::types::{ChunkInfo, FileInfo, Manifest, MetaManifest};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::proxy::try_decode_hash;
use ic_protobuf::state::sync::v1 as pb;
use std::convert::TryFrom;

impl From<FileInfo> for pb::FileInfo {
    fn from(file_info: FileInfo) -> Self {
        Self {
            relative_path: file_info.relative_path.to_string_lossy().to_string(),
            size_bytes: file_info.size_bytes,
            hash: file_info.hash.to_vec(),
        }
    }
}

impl From<ChunkInfo> for pb::ChunkInfo {
    fn from(chunk_info: ChunkInfo) -> Self {
        Self {
            file_index: chunk_info.file_index,
            size_bytes: chunk_info.size_bytes,
            offset: chunk_info.offset,
            hash: chunk_info.hash.to_vec(),
        }
    }
}

impl From<Manifest> for pb::Manifest {
    fn from(manifest: Manifest) -> Self {
        Self {
            version: manifest.version as u32,
            file_table: manifest
                .file_table
                .iter()
                .cloned()
                .map(|entry| entry.into())
                .collect(),
            chunk_table: manifest
                .chunk_table
                .iter()
                .cloned()
                .map(|entry| entry.into())
                .collect(),
        }
    }
}

impl From<MetaManifest> for pb::MetaManifest {
    fn from(meta_manifest: MetaManifest) -> Self {
        Self {
            version: meta_manifest.version as u32,
            sub_manifest_hashes: meta_manifest
                .sub_manifest_hashes
                .iter()
                .map(|hash| hash.to_vec())
                .collect(),
        }
    }
}

impl TryFrom<pb::FileInfo> for FileInfo {
    type Error = ProxyDecodeError;

    fn try_from(file_info: pb::FileInfo) -> Result<Self, ProxyDecodeError> {
        Ok(Self {
            relative_path: file_info.relative_path.into(),
            size_bytes: file_info.size_bytes,
            hash: try_decode_hash(file_info.hash)?,
        })
    }
}

impl TryFrom<pb::ChunkInfo> for ChunkInfo {
    type Error = ProxyDecodeError;

    fn try_from(chunk_info: pb::ChunkInfo) -> Result<Self, ProxyDecodeError> {
        Ok(Self {
            file_index: chunk_info.file_index,
            size_bytes: chunk_info.size_bytes,
            offset: chunk_info.offset,
            hash: try_decode_hash(chunk_info.hash)?,
        })
    }
}

impl TryFrom<pb::Manifest> for Manifest {
    type Error = ProxyDecodeError;

    fn try_from(manifest: pb::Manifest) -> Result<Self, ProxyDecodeError> {
        Ok(Self::new(
            manifest
                .version
                .try_into()
                .map_err(ProxyDecodeError::UnknownStateSyncVersion)?,
            manifest
                .file_table
                .into_iter()
                .map(FileInfo::try_from)
                .collect::<Result<_, _>>()?,
            manifest
                .chunk_table
                .into_iter()
                .map(ChunkInfo::try_from)
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl TryFrom<pb::MetaManifest> for MetaManifest {
    type Error = ProxyDecodeError;

    fn try_from(meta_manifest: pb::MetaManifest) -> Result<Self, ProxyDecodeError> {
        Ok(Self {
            version: meta_manifest
                .version
                .try_into()
                .map_err(ProxyDecodeError::UnknownStateSyncVersion)?,
            sub_manifest_hashes: meta_manifest
                .sub_manifest_hashes
                .into_iter()
                .map(try_decode_hash)
                .collect::<Result<_, _>>()?,
        })
    }
}
