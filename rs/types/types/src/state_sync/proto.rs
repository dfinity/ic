//! Conversions from Rust to proto structs and back for `StateSync`.
use crate::state_sync::{ChunkInfo, FileInfo, Manifest};
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::sync::v1 as pb;
use std::convert::{AsRef, TryFrom, TryInto};

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
            version: manifest.version,
            file_table: manifest
                .file_table
                .into_iter()
                .map(|entry| entry.into())
                .collect(),
            chunk_table: manifest
                .chunk_table
                .into_iter()
                .map(|entry| entry.into())
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
        Ok(Self {
            version: manifest.version,
            file_table: manifest
                .file_table
                .into_iter()
                .map(FileInfo::try_from)
                .collect::<Result<_, _>>()?,
            chunk_table: manifest
                .chunk_table
                .into_iter()
                .map(ChunkInfo::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

fn try_decode_hash(bytes: impl AsRef<[u8]>) -> Result<[u8; 32], ProxyDecodeError> {
    let slice = bytes.as_ref();
    let array: [u8; 32] = slice
        .try_into()
        .map_err(|_| ProxyDecodeError::InvalidDigestLength {
            expected: 32,
            actual: slice.len(),
        })?;
    Ok(array)
}
