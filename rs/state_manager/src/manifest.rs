pub mod hash;

#[cfg(test)]
mod tests;

use super::CheckpointError;
use hash::{
    chunk_hasher, cow_chunk_hasher, cow_file_hasher, file_hasher, manifest_hasher, ManifestHash,
};
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState};
use ic_crypto_sha256::Sha256;
use ic_sys::mmap::ScopedMmap;
use ic_types::{
    state_sync::{ChunkInfo, FileInfo, Manifest},
    CryptoHashOfState,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

pub const STATE_SYNC_V1: u32 = 1;

/// The version of StateSync protocol that should be used for all newly produced
/// states.
pub const CURRENT_STATE_SYNC_VERSION: u32 = STATE_SYNC_V1;

pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20; // 1 MiB.

#[derive(Debug, PartialEq)]
pub enum ManifestValidationError {
    InvalidRootHash {
        expected_hash: Vec<u8>,
        actual_hash: Vec<u8>,
    },
    InvalidFileHash {
        relative_path: PathBuf,
        expected_hash: Vec<u8>,
        actual_hash: Vec<u8>,
    },
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRootHash {
                expected_hash,
                actual_hash,
            } => write!(
                f,
                "manifest root hash mismatch, expected {}, got {}",
                hex::encode(&expected_hash[..]),
                hex::encode(&actual_hash[..])
            ),
            Self::InvalidFileHash {
                relative_path,
                expected_hash,
                actual_hash,
            } => write!(
                f,
                "file {} hash mismatch, expected {}, got {}",
                relative_path.display(),
                hex::encode(&expected_hash[..]),
                hex::encode(&actual_hash[..])
            ),
        }
    }
}

impl std::error::Error for ManifestValidationError {}

#[derive(Debug, PartialEq)]
pub enum ChunkValidationError {
    InvalidChunkHash {
        chunk_ix: usize,
        expected_hash: Vec<u8>,
        actual_hash: Vec<u8>,
    },
    InvalidChunkSize {
        chunk_ix: usize,
        expected_size: usize,
        actual_size: usize,
    },
}

impl fmt::Display for ChunkValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChunkHash {
                chunk_ix,
                expected_hash,
                actual_hash,
            } => write!(
                f,
                "chunk {} hash mismatch, expected {}, got {}",
                chunk_ix,
                hex::encode(&expected_hash[..]),
                hex::encode(&actual_hash[..])
            ),
            Self::InvalidChunkSize {
                chunk_ix,
                expected_size,
                actual_size,
            } => write!(
                f,
                "chunk {} size mismatch, expected {}, got {}",
                chunk_ix, expected_size, actual_size
            ),
        }
    }
}

impl std::error::Error for ChunkValidationError {}

/// Relative path to a file and the size of the file.
struct FileWithSize(PathBuf, u64);

// An index into some table in the _new_ manifest file.
pub type NewIndex = usize;
// An index into some table in the _old_ manifest file.
pub type OldIndex = usize;

/// A script describing how to turn an old state into a new state.
#[derive(Debug, PartialEq, Eq)]
pub struct DiffScript {
    /// Copy some files from the old state.
    /// Keys are indices of the file table in the new manifest file,
    /// values are indices of the file table in the old manifest file.
    pub(crate) copy_files: HashMap<NewIndex, OldIndex>,

    /// Re-use existing chunks from the old state.
    /// Chunks that belong to the `copy_files` key space are excluded.
    /// Keys are indices of the chunk table in the new manifest file,
    /// values are indices of the chunk table in the old manifest file.
    pub(crate) copy_chunks: HashMap<NewIndex, OldIndex>,

    /// Fetch this set of chunks from the peers and apply them.
    pub(crate) fetch_chunks: HashSet<NewIndex>,

    /// Number of all-zero chunks used for metrics.
    pub(crate) zeros_chunks: u32,
}

fn write_chunk_hash(hasher: &mut Sha256, chunk_info: &ChunkInfo) {
    chunk_info.file_index.update_hash(hasher);
    chunk_info.size_bytes.update_hash(hasher);
    chunk_info.offset.update_hash(hasher);
    chunk_info.hash.update_hash(hasher);
}

/// Build a chunk table from the file table.
fn build_chunk_table(
    root: &Path,
    files: Vec<FileWithSize>,
    max_chunk_size: u32,
) -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    let mut chunk_table = Vec::new();
    let mut file_table = Vec::new();

    for (file_index, FileWithSize(relative_path, size_bytes)) in files.into_iter().enumerate() {
        let mut file_hash = if relative_path.ends_with("state_file") {
            cow_file_hasher()
        } else {
            file_hasher()
        };

        let mut bytes_left = size_bytes;

        let num_chunks =
            size_bytes / max_chunk_size as u64 + 1.min(size_bytes % max_chunk_size as u64);

        (num_chunks as u32).update_hash(&mut file_hash);

        let compute_file_chunk_hashes = |data: &[u8]| {
            // It's OK to not have any chunks for 0-sized files (though it's unlikely that
            // we have any).
            while bytes_left > 0 {
                let chunk_size = bytes_left.min(max_chunk_size as u64);
                let offset = size_bytes - bytes_left;

                let mut hasher = if relative_path.ends_with("state_file") {
                    cow_chunk_hasher()
                } else {
                    chunk_hasher()
                };
                hasher.write(&data[offset as usize..(offset + chunk_size) as usize]);

                let chunk_info = ChunkInfo {
                    file_index: file_index as u32,
                    size_bytes: chunk_size as u32,
                    offset: offset as u64,
                    hash: hasher.finish(),
                };

                write_chunk_hash(&mut file_hash, &chunk_info);

                chunk_table.push(chunk_info);

                bytes_left -= chunk_size;
            }

            file_table.push(FileInfo {
                relative_path: relative_path.clone(),
                size_bytes,
                hash: file_hash.finish(),
            });
        };

        if relative_path.ends_with("state_file") {
            let absolute_path = root.join(&relative_path);
            let cow_base_dir = absolute_path.parent().unwrap();
            let cow_mgr = CowMemoryManagerImpl::open_readonly(cow_base_dir.to_path_buf());
            let mapped_state = cow_mgr.get_map();
            mapped_state.make_heap_accessible();
            let data = unsafe {
                std::slice::from_raw_parts(mapped_state.get_heap_base(), size_bytes as usize)
            };
            compute_file_chunk_hashes(data);
        } else {
            let mmap =
                ScopedMmap::from_path(root.join(&relative_path)).expect("failed to open file");
            let data = mmap.as_slice();
            compute_file_chunk_hashes(data);
        };
    }

    (file_table, chunk_table)
}

/// Traverses root recursively and populates the `files` vector with entries of
/// the form `(relative_file_name, file_len)`.
fn files_with_sizes(
    root: &Path,
    relative_path: PathBuf,
    files: &mut Vec<FileWithSize>,
) -> Result<(), CheckpointError> {
    let absolute_path = root.join(&relative_path);
    let metadata = absolute_path
        .metadata()
        .map_err(|io_err| CheckpointError::IoError {
            path: absolute_path.clone(),
            message: "failed to get metadata".to_string(),
            io_err: io_err.to_string(),
        })?;

    if metadata.is_file() {
        let len = if relative_path.ends_with("state_file") {
            let cow_base_dir = absolute_path.parent().unwrap();
            let cow_mgr = CowMemoryManagerImpl::open_readonly(cow_base_dir.to_path_buf());
            let map = cow_mgr.get_map();
            map.get_heap_len() as u64
        } else {
            metadata.len()
        };

        files.push(FileWithSize(relative_path, len))
    } else {
        if relative_path.ends_with("slot_db") {
            return Ok(());
        }
        assert!(
            metadata.is_dir(),
            "Checkpoints must not contain special files, found one at {}",
            absolute_path.display()
        );
        for entry_result in absolute_path
            .read_dir()
            .map_err(|io_err| CheckpointError::IoError {
                path: absolute_path.clone(),
                message: "failed to read dir".to_string(),
                io_err: io_err.to_string(),
            })?
        {
            let entry = entry_result.map_err(|io_err| CheckpointError::IoError {
                path: absolute_path.clone(),
                message: "failed to read dir entry".to_string(),
                io_err: io_err.to_string(),
            })?;
            files_with_sizes(root, relative_path.join(entry.file_name()), files)?;
        }
    }
    Ok(())
}

/// Computes manifest for the checkpoint located at `checkpoint_root_path`.
pub fn compute_manifest(
    version: u32,
    checkpoint_root_path: &Path,
    max_chunk_size: u32,
) -> Result<Manifest, CheckpointError> {
    let mut files = Vec::new();
    files_with_sizes(checkpoint_root_path, "".into(), &mut files)?;
    // We sort the table to make sure that the table is the same on all replicas
    files.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    let (file_table, chunk_table) = build_chunk_table(checkpoint_root_path, files, max_chunk_size);

    Ok(Manifest {
        version,
        file_table,
        chunk_table,
    })
}

/// Validates manifest contents and checks that the hash of the manifest matches
/// the expected root hash.
pub fn validate_manifest(
    manifest: &Manifest,
    root_hash: &CryptoHashOfState,
) -> Result<(), ManifestValidationError> {
    let mut chunk_start: usize = 0;

    for (file_index, f) in manifest.file_table.iter().enumerate() {
        let mut hasher = if f.relative_path.ends_with("state_file") {
            cow_file_hasher()
        } else {
            file_hasher()
        };

        let chunk_count: usize = manifest.chunk_table[chunk_start..]
            .iter()
            .take_while(|chunk| chunk.file_index as usize == file_index)
            .count();

        (chunk_count as u32).update_hash(&mut hasher);

        for chunk_info in manifest.chunk_table[chunk_start..chunk_start + chunk_count].iter() {
            assert_eq!(chunk_info.file_index, file_index as u32);
            write_chunk_hash(&mut hasher, chunk_info);
        }

        chunk_start += chunk_count;

        let hash = hasher.finish();

        if hash != f.hash {
            return Err(ManifestValidationError::InvalidFileHash {
                relative_path: f.relative_path.clone(),
                expected_hash: f.hash.to_vec(),
                actual_hash: hash.to_vec(),
            });
        }
    }

    let hash = manifest_hash(&manifest);

    if root_hash.get_ref().0 != hash {
        return Err(ManifestValidationError::InvalidRootHash {
            expected_hash: root_hash.get_ref().0.clone(),
            actual_hash: hash.to_vec(),
        });
    }

    Ok(())
}

/// Checks that the size and hash of the received chunk match the chunk table of
/// the manifest.
pub fn validate_chunk(
    ix: usize,
    bytes: &[u8],
    manifest: &Manifest,
) -> Result<(), ChunkValidationError> {
    let chunk = &manifest.chunk_table[ix];
    let expected_size = chunk.size_bytes as usize;
    if bytes.len() != expected_size {
        return Err(ChunkValidationError::InvalidChunkSize {
            chunk_ix: ix,
            expected_size,
            actual_size: bytes.len(),
        });
    }
    let mut hasher = if manifest.file_table[chunk.file_index as usize]
        .relative_path
        .ends_with("state_file")
    {
        cow_chunk_hasher()
    } else {
        chunk_hasher()
    };

    let hash = {
        hasher.write(bytes);
        hasher.finish()
    };
    if hash != chunk.hash {
        return Err(ChunkValidationError::InvalidChunkHash {
            chunk_ix: ix,
            expected_hash: chunk.hash.to_vec(),
            actual_hash: hash.to_vec(),
        });
    }
    Ok(())
}

/// Computes root hash of the manifest.
/// See note [Manifest Hash].
pub fn manifest_hash(manifest: &Manifest) -> [u8; 32] {
    let mut hash = manifest_hasher();

    if manifest.version >= STATE_SYNC_V1 {
        manifest.version.update_hash(&mut hash);
    }

    (manifest.file_table.len() as u32).update_hash(&mut hash);

    for f in manifest.file_table.iter() {
        let path = f
            .relative_path
            .to_str()
            .expect("failed to convert path to a str");

        path.update_hash(&mut hash);
        f.size_bytes.update_hash(&mut hash);
        f.hash.update_hash(&mut hash);
    }

    if manifest.version >= STATE_SYNC_V1 {
        (manifest.chunk_table.len() as u32).update_hash(&mut hash);

        for c in manifest.chunk_table.iter() {
            write_chunk_hash(&mut hash, c);
        }
    }

    hash.finish()
}

/// Computes diff between two manifests and get DiffScript.
pub fn diff_manifest(manifest_old: &Manifest, manifest_new: &Manifest) -> DiffScript {
    let mut copy_files: HashMap<NewIndex, OldIndex> = Default::default();
    let mut copy_chunks: HashMap<NewIndex, OldIndex> = Default::default();
    let mut fetch_chunks: HashSet<NewIndex> = Default::default();

    let mut hasher = chunk_hasher();
    let mut bytes_left = DEFAULT_CHUNK_SIZE as i64;
    let zeros_1kib: [u8; 1024] = [0; 1024];

    while bytes_left > 0 {
        let n = 1024.min(bytes_left);
        hasher.write(&zeros_1kib[0..n as usize]);
        bytes_left -= n;
    }
    let zeros_hash = hasher.finish();

    let mut zeros_chunks: u32 = 0;

    let file_hash_to_index: HashMap<[u8; 32], OldIndex> = manifest_old
        .file_table
        .iter()
        .enumerate()
        .map(|(file_index, file_info)| (file_info.hash, file_index))
        .collect();

    for (file_index, file_info) in manifest_new.file_table.iter().enumerate() {
        if let Some(index) = file_hash_to_index.get(&file_info.hash) {
            copy_files.insert(file_index, *index);
        }
    }

    let chunk_hash_to_index: HashMap<[u8; 32], OldIndex> = manifest_old
        .chunk_table
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk_info)| (chunk_info.hash, chunk_index))
        .collect();

    for (chunk_index, chunk_info) in manifest_new.chunk_table.iter().enumerate() {
        if copy_files.contains_key(&(chunk_info.file_index as usize)) {
            continue;
        }

        // All-zero chunks do not need to be explicitly persisted as pre-allocation
        // already truncates the file to all zeros.
        if chunk_info.hash == zeros_hash {
            zeros_chunks += 1;
            continue;
        }

        if let Some(index) = chunk_hash_to_index.get(&chunk_info.hash) {
            copy_chunks.insert(chunk_index, *index);
        } else {
            fetch_chunks.insert(chunk_index);
        }
    }

    DiffScript {
        copy_files,
        copy_chunks,
        fetch_chunks,
        zeros_chunks,
    }
}

/// Filters out all-zero chunks in the manifest chunk table and returns the set
/// of remaining chunks indices.
pub fn filter_out_zero_chunks(manifest: &Manifest) -> HashSet<usize> {
    let mut hasher = chunk_hasher();
    let mut bytes_left = DEFAULT_CHUNK_SIZE as i64;
    let zeros_1kib: [u8; 1024] = [0; 1024];

    while bytes_left > 0 {
        let n = 1024.min(bytes_left);
        hasher.write(&zeros_1kib[0..n as usize]);
        bytes_left -= n;
    }
    let zeros_hash = hasher.finish();

    let fetch_chunks: HashSet<usize> = manifest
        .chunk_table
        .iter()
        .enumerate()
        .filter(|(_index, chunk_info)| chunk_info.hash != zeros_hash)
        .map(|(index, _chunk_info)| index)
        .collect();
    fetch_chunks
}
