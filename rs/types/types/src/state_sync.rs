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
//! * The hash of the whole manifest is computed by hashing the file table:
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
//! ``
pub mod proto;

use crate::chunkable::ChunkId;
use ic_protobuf::state::sync::v1 as pb;
use std::fmt;

/// Id of the manifest chunk in StateSync artifact.
pub const MANIFEST_CHUNK: ChunkId = ChunkId::new(0);

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// Which version of the hashing procedure should be used.
    #[serde(default)]
    pub version: u32,
    pub file_table: Vec<FileInfo>,
    pub chunk_table: Vec<ChunkInfo>,
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
    use std::convert::TryInto;

    let pb_manifest = pb::Manifest::decode(bytes)
        .map_err(|err| format!("failed to decode Manifest proto {}", err))?;
    pb_manifest
        .try_into()
        .map_err(|err| format!("failed to convert Manifest proto into an object: {}", err))
}
