//! State sync types.
//!
//! Note [Manifest Hash]
//! ====================
//!
//! This note describes how hashes included into the manifest are computed.
//!
//! All integers are hashed using their Big-Endian representation.  E.g., u64
//! occupies 8 bytes and 1 is encoded as 0000_0000_0000_0001, and u32 occupies 4
//! bytes and 1 is encoded as 0000_0001.
//!
//! All the variable-size values (paths, arrays) are prefixed with their length
//! to get a unique encoding. If it wasn't the case, it would be possible to
//! interpret 2 file table entries
//!
//! ```text
//! [ "path1" size1 hash1 ]
//! [ "path2" size2 hash2 ]
//! ```
//!
//! as a single file table entry:
//!
//! ```text
//! [ "path1 size1 hash1 path2" size2 hash2 ]
//! ```
//!
//! and get the same manifest hash.
//!
//! Below are the rules for computing hashes of table entries and the root hash
//! of a manifest:
//!
//! * The hash in the chunk table is simply the hash of the raw chunk content.
//! ```text
//!   chunk_hash := hash(dsep("ic-state-chunk") · file[offset:offset + size_bytes])
//! ```
//!
//! * The hash in the file table is the hash of the slice of the chunk table
//!   corresponding to this file:
//! ```text
//!   file_hash   := hash(dsep("ic-state-file") · len(slice) as u32 · chunk_entry*)
//!   chunk_entry := file_index as u32
//!                  · size_bytes as u32
//!                  · offset as u64
//!                  · chunk_hash
//! ```
//!
//! * When the manifest version is less than or equal to `STATE_SYNC_V1`,
//!   the hash of the whole manifest is computed by hashing the file table:
//! ```text
//!   manifest_hash := hash(dsep("ic-state-manifest")
//!                    · version as u32
//!                    · len(file_table) as u32
//!                    · file_entry*
//!                    · len(chunk_table) as u32
//!                    · chunk_entry*
//!                    )
//!   file_entry    := len(relative_path) as u32
//!                    · relative_path
//!                    · size_bytes as u64
//!                    · file_hash
//! ```
//! where
//! ```text
//! dsep(seq) = byte(len(seq)) · seq
//! ```
//! * When the manifest version is greater than or equal to `STATE_SYNC_V2`,
//!   the hash of the meta-manifest functions as the manifest hash.
pub mod proto;

use crate::chunkable::ChunkId;
use ic_protobuf::state::sync::v1 as pb;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    ops::{Deref, Range},
    sync::Arc,
};

/// Id of the manifest chunk in StateSync artifact.
pub const MANIFEST_CHUNK: ChunkId = ChunkId::new(0);

/// Some small files are grouped into chunks during state sync and
/// they need to use a separate range of chunk id to avoid conflicts with normal chunks.
//
// The value of `FILE_GROUP_CHUNK_ID_OFFSET` is set as 1 << 30 (1_073_741_824).
// It is within the whole chunk id range and also large enough to avoid conflicts as shown in the calculations below.
// Every subnet starts off with an allocation of 1 << 20 canister IDs. Suppose a subnet ends up with 10 * 1 << 20 canisters and 100 TiB state.
// Given that each canister has fewer than 10 files in a checkpoint and 1 TiB of state has approximately 1 << 20 chunks,
// the length of chunk table will be smaller than 10 * 10 * 1 << 20 + 100 * 1 << 20 = 209_715_200.
// The real number of canisters and size of state are not even close to the assumption so the value of `FILE_GROUP_CHUNK_ID_OFFSET` is chosen safely.
pub const FILE_GROUP_CHUNK_ID_OFFSET: u32 = 1 << 30;

/// An entry of the file table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    /// Path relative to the checkpoint root.
    pub relative_path: std::path::PathBuf,
    /// Total size of the file in bytes.
    pub size_bytes: u64,
    /// SHA-256 hash of the file metadata and all entries from the chunk table.
    /// See note [Manifest Hash].
    pub hash: [u8; 32],
}

/// An entry of the chunk table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChunkInfo {
    /// Index of the file in the file table.
    pub file_index: u32,
    /// Total size of this chunk in bytes.
    pub size_bytes: u32,
    /// Offset of the chunk within the file.
    pub offset: u64,
    /// SHA-256 hash of the chunk content.
    /// See note [Manifest Hash].
    pub hash: [u8; 32],
}

impl ChunkInfo {
    /// Returns the range of bytes belonging to this chunk.
    pub fn byte_range(&self) -> Range<usize> {
        self.offset as usize..(self.offset as usize + self.size_bytes as usize)
    }
}

/// We wrap the actual Manifest (ManifestData) in an Arc, in order to
/// make Manifest both immutable and cheap to copy
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Manifest(
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    Arc<ManifestData>,
);

impl Manifest {
    pub fn new(version: u32, file_table: Vec<FileInfo>, chunk_table: Vec<ChunkInfo>) -> Self {
        Self(Arc::new(ManifestData {
            version,
            file_table,
            chunk_table,
        }))
    }
}

impl Deref for Manifest {
    type Target = ManifestData;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Manifest is a short description of the checkpoint contents.
///
/// The manifest is structured as 2 tables: a file table and a chunk table,
/// where chunks point to the files they come from.  Such a structure allows us
/// to explicitly enumerate all the chunks in a space-efficient manner.
///
/// The logical structure of the manifest is the following:
/// ```text
/// -- FILES
/// [0]: ("system_metadata.cbor", 1500, <hash>)
/// ...
/// [8]: ("canister_states/00..11/software.wasm", 93000, <hash>)
/// -- CHUNKS
/// -- chunk indices start from 1 because 0 is the ID of the manifest chunk.
/// [ 1]: (0, 1500, 0, <hash>)
/// ...
/// [45]: (8, 93000, 0, <hash>)
/// ```
#[derive(Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ManifestData {
    /// Which version of the hashing procedure should be used.
    #[serde(default)]
    pub version: u32,
    pub file_table: Vec<FileInfo>,
    pub chunk_table: Vec<ChunkInfo>,
}

/// MetaManifest describes how the manifest is encoded, split and hashed.
///
/// The meta-manifest is built in the following way:
///     1. Use protobuf to encode the manifest into raw bytes
///     2. Split the encoded manifest into chunks of `DEFAULT_CHUNK_SIZE` bytes, called sub-manifests.
///     3. Hash each sub-manifest and collect their hashes
///
/// The hash of meta-manifest is computed by hashing the version, the length and `sub_manifest_hashes`:
/// ```text
///   meta_manifest_hash := hash(dsep("ic-state-meta-manifest")
///                         · version as u32
///                         · len(sub_manifest_hashes) as u32
///                         · sub_manifest_hashes
///                         )
///   sub_manifest_hash  := hash(dsep("ic-state-sub-manifest") · encoded_manifest[offset:offset + size_bytes])
/// ```
///
/// The `meta_manifest_hash` is used as the manifest hash when the manifest version is greater than or equal to `STATE_SYNC_V2`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MetaManifest {
    pub version: u32,
    pub sub_manifest_hashes: Vec<[u8; 32]>,
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn write_header(f: &mut fmt::Formatter<'_>, spec: &[(&'static str, usize)]) -> fmt::Result {
            for (idx, (field, width)) in spec.iter().enumerate() {
                write!(
                    f,
                    "{}{:^width$}",
                    if idx > 0 { "|" } else { "" },
                    field,
                    width = width
                )?;
            }
            writeln!(f)?;
            for (idx, (_, width)) in spec.iter().enumerate() {
                write!(
                    f,
                    "{}{:-^width$}",
                    if idx > 0 { "+" } else { "" },
                    "",
                    width = width
                )?;
            }
            writeln!(f)?;
            Ok(())
        }

        let max_path_len = self
            .file_table
            .iter()
            .map(|f| f.relative_path.as_os_str().len())
            .max()
            .unwrap_or(6);

        writeln!(f, "MANIFEST VERSION: {}", self.version)?;
        writeln!(f, "FILE TABLE")?;
        write_header(
            f,
            &[
                ("idx", 12),
                ("size", 12),
                ("hash", 66),
                ("path", max_path_len),
            ],
        )?;
        for (idx, file_info) in self.file_table.iter().enumerate() {
            writeln!(
                f,
                " {:>10} | {:>10} | {:64} | {}",
                idx,
                file_info.size_bytes,
                hex::encode(file_info.hash),
                file_info.relative_path.display()
            )?;
        }
        writeln!(f, "CHUNK TABLE")?;
        write_header(
            f,
            &[
                ("idx", 12),
                ("file_idx", 12),
                ("offset", 12),
                ("size", 12),
                ("hash", 66),
            ],
        )?;
        for (idx, chunk_info) in self.chunk_table.iter().enumerate() {
            writeln!(
                f,
                " {:>10} | {:>10} | {:>10} | {:>10} | {}",
                idx,
                chunk_info.file_index,
                chunk_info.offset,
                chunk_info.size_bytes,
                hex::encode(chunk_info.hash),
            )?;
        }
        Ok(())
    }
}

/// Serializes the manifest into a byte array.
pub fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    use prost::Message;

    let pb_manifest = pb::Manifest::from(manifest.clone());
    let mut buf = vec![];
    pb_manifest
        .encode(&mut buf)
        .expect("failed to encode manifest to protobuf");
    buf
}

/// Deserializes the manifest from a byte array.
pub fn decode_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    use prost::Message;

    let pb_manifest = pb::Manifest::decode(bytes)
        .map_err(|err| format!("failed to decode Manifest proto {}", err))?;
    pb_manifest
        .try_into()
        .map_err(|err| format!("failed to convert Manifest proto into an object: {}", err))
}

type P2PChunkId = u32;
type ManifestChunkTableIndex = u32;

/// A chunk id from the P2P level is mapped to a group of indices from the manifest chunk table.
/// `FileGroupChunks` stores the mapping and can be used to assemble or split the file group chunk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileGroupChunks(BTreeMap<P2PChunkId, Vec<ManifestChunkTableIndex>>);

impl FileGroupChunks {
    pub fn new(value: BTreeMap<P2PChunkId, Vec<ManifestChunkTableIndex>>) -> Self {
        FileGroupChunks(value)
    }

    pub fn keys(&self) -> impl Iterator<Item = &ManifestChunkTableIndex> {
        self.0.keys()
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&ManifestChunkTableIndex, &Vec<ManifestChunkTableIndex>)> {
        self.0.iter()
    }

    pub fn get(&self, chunk_id: &P2PChunkId) -> Option<&Vec<ManifestChunkTableIndex>> {
        self.0.get(chunk_id)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
