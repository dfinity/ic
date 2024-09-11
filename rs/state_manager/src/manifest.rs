pub mod hash;
pub mod split;

#[cfg(test)]
mod tests {
    mod compatibility;
    mod computation;
}

use super::CheckpointError;
use crate::{
    manifest::hash::{meta_manifest_hasher, sub_manifest_hasher},
    state_sync::types::{
        encode_manifest, ChunkInfo, FileGroupChunks, FileInfo, Manifest, MetaManifest,
        DEFAULT_CHUNK_SIZE, FILE_CHUNK_ID_OFFSET, FILE_GROUP_CHUNK_ID_OFFSET,
        MAX_SUPPORTED_STATE_SYNC_VERSION,
    },
    BundledManifest, DirtyPages, ManifestMetrics, CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS,
    CRITICAL_ERROR_REUSED_CHUNK_HASH, LABEL_VALUE_HASHED, LABEL_VALUE_HASHED_AND_COMPARED,
    LABEL_VALUE_REUSED, NUMBER_OF_CHECKPOINT_THREADS,
};
use bit_vec::BitVec;
use hash::{chunk_hasher, file_hasher, manifest_hasher, ManifestHash};
use ic_config::flag_status::FlagStatus;
use ic_crypto_sha2::Sha256;
use ic_logger::{error, fatal, replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::page_map::StorageLayout;
use ic_replicated_state::PageIndex;
use ic_state_layout::{CheckpointLayout, ReadOnly, CANISTER_FILE, UNVERIFIED_CHECKPOINT_MARKER};
use ic_sys::{mmap::ScopedMmap, PAGE_SIZE};
use ic_types::{crypto::CryptoHash, state_sync::StateSyncVersion, CryptoHashOfState, Height};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

/// When computing a manifest, we recompute the hash of every
/// `REHASH_EVERY_NTH_CHUNK` chunk, even if we know it to be unchanged and
/// have a hash computed earlier by this replica process.
const REHASH_EVERY_NTH_CHUNK: u64 = 10;

/// During the downloading phase of state sync, We group certain files together
/// which have filenames ending with `FILE_TO_GROUP`.
///
/// We make the decision to group `canister.pbuf` files for two main reasons:
///     1. They are small in general, usually less than 1 KiB.
///     2. They change between checkpoints, so we always have to fetch them.
const FILE_TO_GROUP: &str = CANISTER_FILE;

/// The size of files to group should be less or equal to the `FILE_GROUP_SIZE_LIMIT`
/// to guarantee the efficiency of grouping.
///
/// The number is chosen heuristically for two reasons:
///     1. It will cover most of `canister.pbuf` files if not all of them.
///     2. `DEFAULT_CHUNK_SIZE` is 128 times of it. It means the number of chunks
///     will decrease by at least two orders of magnitude, which is significant enough.
const MAX_FILE_SIZE_TO_GROUP: u32 = 1 << 13; // 8 KiB

#[derive(Eq, PartialEq, Debug)]
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
    UnsupportedManifestVersion {
        manifest_version: StateSyncVersion,
        max_supported_version: StateSyncVersion,
    },
    InconsistentManifest {
        reason: String,
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
            Self::UnsupportedManifestVersion {
                manifest_version,
                max_supported_version,
            } => write!(
                f,
                "manifest version {} not supported, maximum supported version {}",
                manifest_version, max_supported_version,
            ),
            Self::InconsistentManifest { reason } => write!(f, "inconsistent manifest: {}", reason),
        }
    }
}

impl std::error::Error for ManifestValidationError {}

#[derive(Eq, PartialEq, Debug)]
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
    InvalidChunkIndex {
        chunk_ix: usize,
        actual_length: usize,
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
            Self::InvalidChunkIndex {
                chunk_ix,
                actual_length,
            } => write!(
                f,
                "chunk index {} is out of the vector length {}",
                chunk_ix, actual_length
            ),
        }
    }
}

impl std::error::Error for ChunkValidationError {}

/// Relative path to a file and the size of the file.
#[derive(Clone, PartialEq, Debug)]
struct FileWithSize(PathBuf, u64);

#[derive(Clone, Eq, PartialEq, Debug)]
enum ChunkAction {
    /// Recompute the hash of the chunk, as no previously computed hash is
    /// available
    Recompute,
    /// There is a previously computed hash for this chunk, but recompute it
    /// anyway and record an error metric if there is a mismatch
    RecomputeAndCompare([u8; 32]),
    /// Use the previously computed hash for this chunk
    UseHash([u8; 32]),
}

// An index into some table in the _new_ manifest file.
pub type NewIndex = usize;
// An index into some table in the _old_ manifest file.
pub type OldIndex = usize;

/// A script describing how to turn an old state into a new state.
#[derive(Eq, PartialEq, Debug)]
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

/// ManifestDelta contains a manifest of an old state and indices of all the
/// memory pages that changed (became "dirty") since that state.
///
/// This data allows us to speed up manifest computation: we can map dirty page
/// indices back to chunks and avoid re-computing chunks that haven't changed
/// since the previous manifest computation.
pub struct ManifestDelta {
    /// Manifest of the state at `base_height`.
    pub(crate) base_manifest: Manifest,
    /// Height of the base state.
    pub(crate) base_height: Height,
    /// Current height
    pub(crate) target_height: Height,
    /// Wasm memory and stable memory pages that might have changed since the
    /// state at `base_height`.
    pub(crate) dirty_memory_pages: DirtyPages,
    pub(crate) base_checkpoint: CheckpointLayout<ReadOnly>,
    pub(crate) lsmt_status: FlagStatus,
}

/// Groups small files into larger chunks.
///
/// Builds the grouping of how files should be put together into a single chunk and
/// returns the mapping from chunk id to the grouped chunk indices.
/// The grouping is deterministic to ensure that the sender assembles the file
/// in such a way that the receiver can split it back just by looking at the manifest.
pub(crate) fn build_file_group_chunks(manifest: &Manifest) -> FileGroupChunks {
    let mut file_group_chunks: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut chunk_id_p2p = FILE_GROUP_CHUNK_ID_OFFSET;
    let mut chunk_table_indices: Vec<u32> = Vec::new();

    let mut bytes_left = DEFAULT_CHUNK_SIZE as u64;

    for (file_index, f) in manifest.file_table.iter().enumerate() {
        if !f.relative_path.ends_with(FILE_TO_GROUP)
            || f.size_bytes > MAX_FILE_SIZE_TO_GROUP as u64
            || f.size_bytes >= DEFAULT_CHUNK_SIZE as u64
        {
            continue;
        }

        if bytes_left < f.size_bytes {
            file_group_chunks.insert(chunk_id_p2p, std::mem::take(&mut chunk_table_indices));
            chunk_id_p2p += 1;
            bytes_left = DEFAULT_CHUNK_SIZE as u64;
        }

        bytes_left -= f.size_bytes;
        let chunk_range = file_chunk_range(&manifest.chunk_table, file_index);
        chunk_table_indices.extend(chunk_range.map(|i| i as u32));
    }

    if !chunk_table_indices.is_empty() {
        file_group_chunks.insert(chunk_id_p2p, chunk_table_indices);
    }
    FileGroupChunks::new(file_group_chunks)
}

fn write_chunk_hash(hasher: &mut Sha256, chunk_info: &ChunkInfo, version: StateSyncVersion) {
    // Starting with `V3`, no longer include file index in chunk/file hash.
    if version < StateSyncVersion::V3 {
        chunk_info.file_index.update_hash(hasher);
    }
    chunk_info.size_bytes.update_hash(hasher);
    chunk_info.offset.update_hash(hasher);
    chunk_info.hash.update_hash(hasher);
}

/// Returns the number of chunks of size `max_chunk_size` required to cover a
/// file of size `size_bytes`.
fn count_chunks(size_bytes: u64, max_chunk_size: u32) -> usize {
    (size_bytes as usize + max_chunk_size as usize - 1) / max_chunk_size as usize
}

/// Checks if the manifest was computed using specified max_chunk_size.
fn uses_chunk_size(manifest: &Manifest, max_chunk_size: u32) -> bool {
    manifest.chunk_table.iter().all(|chunk| {
        chunk.size_bytes == max_chunk_size
            || chunk.size_bytes as u64 + chunk.offset
                == manifest.file_table[chunk.file_index as usize].size_bytes
    })
}

// Computes file_table and chunk_table of a manifest using a parallel algorithm.
// All the parallel work is spawned in the specified thread pool.
fn build_chunk_table_parallel(
    thread_pool: &mut scoped_threadpool::Pool,
    metrics: &ManifestMetrics,
    log: &ReplicaLogger,
    root: &Path,
    files: Vec<FileWithSize>,
    max_chunk_size: u32,
    chunk_actions: Vec<ChunkAction>,
    version: StateSyncVersion,
) -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    // Build a chunk table and file table filled with blank hashes.
    let mut chunk_table: Vec<ChunkInfo> = {
        let mut chunks = Vec::with_capacity(chunk_actions.len());
        for (file_index, FileWithSize(_, size_bytes)) in files.iter().enumerate() {
            let n = count_chunks(*size_bytes, max_chunk_size);
            for i in 0..n {
                let offset = i as u64 * max_chunk_size as u64;
                let size_bytes = (size_bytes - offset).min(max_chunk_size as u64) as u32;
                chunks.push(ChunkInfo {
                    file_index: file_index as u32,
                    offset,
                    size_bytes,
                    hash: [0; 32],
                });
            }
        }
        chunks
    };

    assert_eq!(chunk_table.len(), chunk_actions.len());

    let mut file_table: Vec<FileInfo> = files
        .into_iter()
        .map(|FileWithSize(relative_path, size_bytes)| FileInfo {
            relative_path,
            size_bytes,
            hash: [0; 32],
        })
        .collect();

    // We cache the files that are currently being hashed to avoid opening them
    // individually for each chunk. The values in the cache are weak references,
    // so the last thread that has a strong reference will release the value
    // and close the corresponding file.
    // This way we keep the number of files opened at the same time
    // low (it doesn't exceed the number of the threads).
    let file_cache: Arc<Mutex<HashMap<u32, Weak<ScopedMmap>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Compute real chunk hashes in parallel.
    // NB. We must populate hashes of all the chunks in a file before we compute
    // file hashes.
    thread_pool.scoped(|scope| {
        for (chunk_idx, chunk_info) in chunk_table.iter_mut().enumerate() {
            let chunk_action = chunk_actions[chunk_idx].clone();
            let file_path = root.join(&file_table[chunk_info.file_index as usize].relative_path);
            let file_size = file_table[chunk_info.file_index as usize].size_bytes;
            let file_cache = Arc::clone(&file_cache);
            scope.execute(move || {
                let recompute_chunk_hash = || {
                    let mmap: Arc<ScopedMmap> = if file_size > max_chunk_size as u64 {
                        // We only use the file cache if there is more than one chunk in the file,
                        // otherwise the synchronization cost is unnecessary.
                        let mut cache = file_cache.lock().unwrap();
                        match cache.get(&chunk_info.file_index).and_then(Weak::upgrade) {
                            Some(mmap) => mmap,
                            None => {
                                let mmap = Arc::new(
                                    ScopedMmap::from_path(&file_path)
                                        .unwrap_or_else(|e| fatal!(log, "failed to mmap file {}: {}", file_path.display(), e)),
                                );
                                cache.insert(chunk_info.file_index, Arc::downgrade(&mmap));
                                mmap
                            }
                        }
                    } else {
                        Arc::new(
                            ScopedMmap::from_path(&file_path)
                                .unwrap_or_else(|e| fatal!(log, "failed to mmap file {}: {}", file_path.display(), e))
                        )
                    };
                    let data = mmap.as_slice();

                    let mut hasher = chunk_hasher();
                    let chunk_start = chunk_info.offset as usize;
                    let chunk_end = chunk_start + chunk_info.size_bytes as usize;
                    hasher.write(&data[chunk_start..chunk_end]);
                    hasher.finish()
                };

                chunk_info.hash = match chunk_action {
                    ChunkAction::Recompute => {
                        metrics.chunk_bytes.with_label_values(&[LABEL_VALUE_HASHED]).inc_by(chunk_info.size_bytes as u64);
                        recompute_chunk_hash()
                    },
                    ChunkAction::RecomputeAndCompare(precomputed_hash) => {
                        metrics.chunk_bytes.with_label_values(&[LABEL_VALUE_HASHED_AND_COMPARED]).inc_by(chunk_info.size_bytes as u64);

                        let recomputed_hash = recompute_chunk_hash();
                        debug_assert_eq!(recomputed_hash, precomputed_hash);
                        if recomputed_hash != precomputed_hash {
                            metrics.reused_chunk_hash_error_count.inc();
                            error!(
                                log,
                                "{}: Hash mismatch in chunk with index {} in file {}, recomputed hash {:?}, reused hash {:?}",
                                CRITICAL_ERROR_REUSED_CHUNK_HASH,
                                chunk_idx,
                                file_path.display(),
                                chunk_info.hash,
                                precomputed_hash
                            );
                        }
                        recomputed_hash
                    }
                    ChunkAction::UseHash(precomputed_hash) => {
                        metrics.chunk_bytes.with_label_values(&[LABEL_VALUE_REUSED]).inc_by(chunk_info.size_bytes as u64);
                        precomputed_hash
                    },
                };
            });
        }
    });

    // After we computed all the chunk hashes, we can finally compute file hashes.
    for (file_index, file_info) in file_table.iter_mut().enumerate() {
        let mut hasher = file_hasher();
        let chunk_range = file_chunk_range(&chunk_table, file_index);
        (chunk_range.len() as u32).update_hash(&mut hasher);
        for chunk_idx in chunk_range {
            write_chunk_hash(&mut hasher, &chunk_table[chunk_idx], version);
        }
        file_info.hash = hasher.finish();
    }

    (file_table, chunk_table)
}

/// Build a chunk table from the file table.
#[cfg(debug_assertions)]
fn build_chunk_table_sequential(
    metrics: &ManifestMetrics,
    log: &ReplicaLogger,
    root: &Path,
    files: Vec<FileWithSize>,
    max_chunk_size: u32,
    chunk_actions: Vec<ChunkAction>,
    version: StateSyncVersion,
) -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    let mut chunk_table = Vec::new();
    let mut file_table = Vec::new();
    let mut chunk_index: usize = 0;

    for (file_index, FileWithSize(relative_path, size_bytes)) in files.into_iter().enumerate() {
        let mut file_hash = file_hasher();

        let mut bytes_left = size_bytes;

        let num_chunks = count_chunks(size_bytes, max_chunk_size);

        (num_chunks as u32).update_hash(&mut file_hash);

        let compute_file_chunk_hashes = |data: &[u8]| {
            // It's OK to not have any chunks for 0-sized files (though it's unlikely that
            // we have any).
            while bytes_left > 0 {
                let chunk_size = bytes_left.min(max_chunk_size as u64);
                let offset = size_bytes - bytes_left;

                let recompute_chunk_hash = || {
                    let mut hasher = chunk_hasher();
                    hasher.write(&data[offset as usize..(offset + chunk_size) as usize]);
                    hasher.finish()
                };

                assert!(chunk_index < chunk_actions.len());

                let chunk_hash = match chunk_actions[chunk_index] {
                    ChunkAction::RecomputeAndCompare(reused_chunk_hash) => {
                        metrics
                            .chunk_bytes
                            .with_label_values(&[LABEL_VALUE_HASHED_AND_COMPARED])
                            .inc_by(chunk_size);

                        // We have both a reused and a recomputed hash, so we can compare them to
                        // monitor for issues
                        let recomputed_chunk_hash = recompute_chunk_hash();
                        debug_assert_eq!(recomputed_chunk_hash, reused_chunk_hash);
                        if recomputed_chunk_hash != reused_chunk_hash {
                            metrics.reused_chunk_hash_error_count.inc();
                            error!(
                                log,
                                "{}: Hash mismatch in chunk with index {} in file {}, recomputed hash {:?}, reused hash {:?}",
                                CRITICAL_ERROR_REUSED_CHUNK_HASH,
                                chunk_index,
                                relative_path.display(),
                                recomputed_chunk_hash,
                                reused_chunk_hash
                            );
                        }
                        recomputed_chunk_hash
                    }
                    ChunkAction::UseHash(reused_chunk_hash) => {
                        metrics
                            .chunk_bytes
                            .with_label_values(&[LABEL_VALUE_REUSED])
                            .inc_by(chunk_size);
                        reused_chunk_hash
                    }
                    ChunkAction::Recompute => {
                        metrics
                            .chunk_bytes
                            .with_label_values(&[LABEL_VALUE_REUSED])
                            .inc_by(chunk_size);
                        recompute_chunk_hash()
                    }
                };

                let chunk_info = ChunkInfo {
                    file_index: file_index as u32,
                    size_bytes: chunk_size as u32,
                    offset,
                    hash: chunk_hash,
                };

                write_chunk_hash(&mut file_hash, &chunk_info, version);

                chunk_table.push(chunk_info);

                bytes_left -= chunk_size;
                chunk_index += 1;
            }

            file_table.push(FileInfo {
                relative_path: relative_path.clone(),
                size_bytes,
                hash: file_hash.finish(),
            });
        };

        let mmap = ScopedMmap::from_path(root.join(&relative_path)).expect("failed to open file");
        let data = mmap.as_slice();
        compute_file_chunk_hashes(data);
    }

    assert_eq!(chunk_table.len(), chunk_actions.len());

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
        files.push(FileWithSize(relative_path, metadata.len()))
    } else {
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

/// Returns the range of chunks belonging to the file with the specified index.
///
/// If the file is empty and doesn't have any chunks, returns an empty range.
pub fn file_chunk_range(chunk_table: &[ChunkInfo], file_index: usize) -> Range<usize> {
    let start = chunk_table.partition_point(|c| (c.file_index as usize) < file_index);
    let end = chunk_table.partition_point(|c| (c.file_index as usize) < file_index + 1);
    start..end
}

/// Makes a "hash plan": an instruction how to compute the hash of each chunk of
/// the new manifest.
fn hash_plan(
    base_manifest: &Manifest,
    files: &[FileWithSize],
    dirty_file_chunks: BTreeMap<PathBuf, BitVec>,
    max_chunk_size: u32,
    seed: u64,
    rehash_every_nth: u64,
) -> Vec<ChunkAction> {
    // Even if we could reuse all chunks, we want to ensure that we sometimes still
    // recompute them anyway to not propagate errors indefinitely. We choose a
    // uniformly random offset in [0, rehash_every_nth - 1] and recompute any chunks
    // with ((chunk_index + offset) % rehash_every_nth) == 0. The sampling is done
    // using an rng so that it's not always the same chunks but seeded
    // deterministically. We want to ensure that all replicas have the same hash
    // plan, as otherwise a replica that detects an error might not be able to
    // sway consensus. At the same time, we do not require unpredictability
    // here, as long as we can guarantee that we find faulty chunks within
    // rehash_every_nth checkpoints in expectation.
    let mut rng = ChaChaRng::seed_from_u64(seed);
    let rehash_every_nth = rehash_every_nth.max(1); // 0 will behave like 1
    let offset = rng.gen_range(0..rehash_every_nth);

    debug_assert!(uses_chunk_size(base_manifest, max_chunk_size));

    let mut chunk_actions: Vec<ChunkAction> = Vec::new();

    for FileWithSize(relative_path, size_bytes) in files.iter() {
        let num_chunks = count_chunks(*size_bytes, max_chunk_size);

        let compute_dirty_chunk_bitmap = || -> Option<(&BitVec, usize)> {
            let dirty_chunk_bitmap = dirty_file_chunks.get(relative_path)?;

            let base_file_index = base_manifest
                .file_table
                .binary_search_by_key(&relative_path, |file_info| &file_info.relative_path)
                .ok()?;

            // The chunk table contains chunks from all files and hence `base_index` is
            // needed to know the absolute index. The chunk table is sorted by
            // `file_index` and then `offset`. Therefore binary search can be used to find
            // the first chunk index of a file.
            let base_index = base_manifest
                .chunk_table
                .binary_search_by(|chunk_info| {
                    chunk_info
                        .file_index
                        .cmp(&(base_file_index as u32))
                        .then_with(|| chunk_info.offset.cmp(&0u64))
                })
                .ok()?;
            Some((dirty_chunk_bitmap, base_index))
        };

        if let Some((dirty_chunk_bitmap, base_index)) = compute_dirty_chunk_bitmap() {
            debug_assert_eq!(num_chunks, dirty_chunk_bitmap.len());

            for i in 0..num_chunks {
                let action = if dirty_chunk_bitmap[i] {
                    ChunkAction::Recompute
                } else {
                    let chunk = &base_manifest.chunk_table[base_index + i];

                    debug_assert_eq!(
                        &base_manifest.file_table[chunk.file_index as usize].relative_path,
                        relative_path
                    );
                    debug_assert_eq!(chunk.offset, i as u64 * max_chunk_size as u64);
                    debug_assert_eq!(
                        chunk.size_bytes as u64,
                        (size_bytes - chunk.offset).min(max_chunk_size as u64)
                    );

                    // We are using chunk_actions.len() as shorthand for the chunk_index.
                    let offset_index = (chunk_actions.len() as u64).wrapping_add(offset);

                    if (offset_index % rehash_every_nth) == 0 {
                        ChunkAction::RecomputeAndCompare(chunk.hash)
                    } else {
                        ChunkAction::UseHash(chunk.hash)
                    }
                };
                chunk_actions.push(action);
            }
        } else {
            for _ in 0..num_chunks {
                chunk_actions.push(ChunkAction::Recompute);
            }
        }
    }
    chunk_actions
}

/// Returns the trivial hash plan that instructs the caller to recompute hashes
/// of all the chunks.
fn default_hash_plan(files: &[FileWithSize], max_chunk_size: u32) -> Vec<ChunkAction> {
    let chunks_total: usize = files
        .iter()
        .map(|FileWithSize(_, size_bytes)| count_chunks(*size_bytes, max_chunk_size))
        .sum();
    vec![ChunkAction::Recompute; chunks_total]
}

fn dirty_chunks_of_file(
    relative_path: &Path,
    page_indices: &[PageIndex],
    files: &[FileWithSize],
    max_chunk_size: u32,
    base_manifest: &Manifest,
) -> Option<BitVec> {
    if let Ok(index) =
        files.binary_search_by(|FileWithSize(file_path, _)| file_path.as_path().cmp(relative_path))
    {
        let size_bytes = files[index].1;
        let num_chunks = count_chunks(size_bytes, max_chunk_size);
        let mut chunks_bitmap = BitVec::from_elem(num_chunks, false);

        for page_index in page_indices {
            // As the chunk size is a multiple of the page size, at most one chunk could
            // possibly be affected.
            let chunk_index = PAGE_SIZE * page_index.get() as usize / max_chunk_size as usize;
            chunks_bitmap.set(chunk_index, true);
        }

        // NB. The code below handles the case when the file size increased, but the
        // dirty pages do not cover the new area.  This should not happen in the current
        // implementation of PageMap, but we don't want to rely too much on these
        // implementation details.  So we mark the expanded area as dirty explicitly
        // instead.
        let base_file_index = base_manifest
            .file_table
            .binary_search_by(|file_info| file_info.relative_path.as_path().cmp(relative_path));

        // This should never happen under normal operation. However, disaster recovery can add
        // files into checkpoints, so we relax the check in production and return None if the file
        // is missing in the base manifest. This triggers full re-hashing of the corresponding
        // file.
        debug_assert!(
            base_file_index.is_ok(),
            "could not find file {} in the base manifest",
            relative_path.display()
        );

        let base_file_index = base_file_index.ok()?;
        let base_file_size = base_manifest.file_table[base_file_index].size_bytes;

        if base_file_size < size_bytes {
            let from_chunk = count_chunks(base_file_size, max_chunk_size).max(1) - 1;
            for i in from_chunk..num_chunks {
                chunks_bitmap.set(i, true);
            }
        }
        Some(chunks_bitmap)
    } else {
        None
    }
}

/// Computes the bitmap of chunks modified since the base state.
/// For the files with provided dirty pages, the pages not in the list are assumed unchanged.
/// The files that are hardlinks of the same inode are not rehashed as they must contain the same
/// data.
fn dirty_pages_to_dirty_chunks(
    log: &ReplicaLogger,
    manifest_delta: &ManifestDelta,
    checkpoint: &CheckpointLayout<ReadOnly>,
    files: &[FileWithSize],
    max_chunk_size: u32,
) -> Result<BTreeMap<PathBuf, BitVec>, CheckpointError> {
    debug_assert!(uses_chunk_size(
        &manifest_delta.base_manifest,
        max_chunk_size
    ));
    // The `max_chunk_size` is set to 1 MiB currently and the assertion below meets.
    // Note that currently the code does not support changing `max_chunk_size`
    // without adding explicit code for backward compatibility.
    assert_eq!(
        max_chunk_size as usize % PAGE_SIZE,
        0,
        "chunk size must be a multiple of page size for incremental computation to work correctly"
    );

    let mut dirty_chunks: BTreeMap<PathBuf, BitVec> = Default::default();

    // If `lsmt_status` is enabled, we shouldn't have populated `dirty_memory_pages` in the first place.
    debug_assert!(
        manifest_delta.lsmt_status == FlagStatus::Disabled
            || manifest_delta.dirty_memory_pages.is_empty()
    );

    // Any information on dirty pages is not relevant to what files might have changed with
    // `lsmt_status` enabled.
    if manifest_delta.lsmt_status == FlagStatus::Disabled {
        for dirty_page in &manifest_delta.dirty_memory_pages {
            if dirty_page.height != manifest_delta.base_height {
                continue;
            }

            let path = dirty_page
                .page_type
                .layout(checkpoint)
                .map(|layout| layout.base());

            if let Ok(path) = path {
                let relative_path = path
                    .strip_prefix(checkpoint.raw_path())
                    .expect("failed to strip path prefix");

                if let Some(chunks_bitmap) = dirty_chunks_of_file(
                    relative_path,
                    &dirty_page.page_delta_indices,
                    files,
                    max_chunk_size,
                    &manifest_delta.base_manifest,
                ) {
                    dirty_chunks.insert(relative_path.to_path_buf(), chunks_bitmap);
                }
            }
        }
    }

    // The files with the same inode and device IDs are hardlinks, hence contain exactly the same
    // data.
    if manifest_delta.base_height != manifest_delta.base_checkpoint.height() {
        debug_assert!(false);
        return Ok(dirty_chunks);
    }
    for FileWithSize(path, size_bytes) in files.iter() {
        use std::os::unix::fs::MetadataExt;
        let new_path = checkpoint.raw_path().join(path);
        let old_path = manifest_delta.base_checkpoint.raw_path().join(path);
        if !old_path.exists() {
            continue;
        }
        let new_metadata = new_path.metadata();
        let old_metadata = old_path.metadata();
        if new_metadata.is_err() || old_metadata.is_err() {
            error!(
                log,
                "Failed to get metadata for an existing path. {} -> {:#?}, {} -> {:#?}",
                &old_path.display(),
                &old_metadata,
                &new_path.display(),
                &new_metadata
            );
            debug_assert!(false);
            continue;
        }
        let new_metadata = new_metadata.unwrap();
        let old_metadata = old_metadata.unwrap();
        if new_metadata.ino() == old_metadata.ino() && new_metadata.dev() == old_metadata.dev() {
            let num_chunks = count_chunks(*size_bytes, max_chunk_size);
            let chunks_bitmap = BitVec::from_elem(num_chunks, false);
            let _prev_chunk = dirty_chunks.insert(path.clone(), chunks_bitmap);
            // Check that for hardlinked files there are no dirty pages.
            debug_assert!(_prev_chunk.is_none());
        }
    }
    Ok(dirty_chunks)
}

/// Computes manifest for the checkpoint located at `checkpoint_root_path`.
pub fn compute_manifest(
    thread_pool: &mut scoped_threadpool::Pool,
    metrics: &ManifestMetrics,
    log: &ReplicaLogger,
    version: StateSyncVersion,
    checkpoint: &CheckpointLayout<ReadOnly>,
    max_chunk_size: u32,
    opt_manifest_delta: Option<ManifestDelta>,
) -> Result<Manifest, CheckpointError> {
    let mut files = {
        let mut files = Vec::new();
        files_with_sizes(checkpoint.raw_path(), "".into(), &mut files)?;
        // We sort the table to make sure that the table is the same on all replicas
        files.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));
        files
    };

    // Currently, the unverified checkpoint marker file should already be removed by the time we reach this point.
    // If it accidentally exists, the replica will crash in the outer function `handle_compute_manifest_request`.
    //
    // Because this function may still be used by tests and external tools to compute manifest of an unverified checkpoint,
    // the function does not crash here. Instead, we exclude the marker file from the manifest computation.
    if !checkpoint.is_checkpoint_verified() {
        files.retain(|FileWithSize(p, _)| {
            checkpoint.raw_path().join(p) != checkpoint.unverified_checkpoint_marker()
        });
        assert!(!files
            .iter()
            .any(|FileWithSize(p, _)| p.ends_with(UNVERIFIED_CHECKPOINT_MARKER)));
    }

    let chunk_actions = match opt_manifest_delta {
        Some(manifest_delta) => {
            // We have to check that the old manifest uses exactly the same chunk size.
            // Otherwise, if someone decides to change the chunk size in future,
            // all the tests are going to pass (because all of them will use the
            // new chunk size), but the manifest might be computed incorrectly
            // on the mainnet.
            if uses_chunk_size(&manifest_delta.base_manifest, max_chunk_size) {
                let dirty_file_chunks = dirty_pages_to_dirty_chunks(
                    log,
                    &manifest_delta,
                    checkpoint,
                    &files,
                    max_chunk_size,
                )?;
                hash_plan(
                    &manifest_delta.base_manifest,
                    &files,
                    dirty_file_chunks,
                    max_chunk_size,
                    manifest_delta.target_height.get(),
                    REHASH_EVERY_NTH_CHUNK,
                )
            } else {
                default_hash_plan(&files, max_chunk_size)
            }
        }
        None => default_hash_plan(&files, max_chunk_size),
    };

    #[cfg(debug_assertions)]
    let (seq_file_table, seq_chunk_table) = {
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        let metrics = ManifestMetrics::new(&metrics_registry);
        build_chunk_table_sequential(
            &metrics,
            log,
            checkpoint.raw_path(),
            files.clone(),
            max_chunk_size,
            chunk_actions.clone(),
            version,
        )
    };

    let (file_table, chunk_table) = build_chunk_table_parallel(
        thread_pool,
        metrics,
        log,
        checkpoint.raw_path(),
        files,
        max_chunk_size,
        chunk_actions,
        version,
    );

    #[cfg(debug_assertions)]
    {
        assert_eq!(file_table, seq_file_table);
        assert_eq!(chunk_table, seq_chunk_table);
    }

    let manifest = Manifest::new(version, file_table, chunk_table);
    metrics
        .manifest_size
        .set(encode_manifest(&manifest).len() as i64);

    metrics
        .chunk_table_length
        .set(manifest.chunk_table.len() as i64);

    metrics
        .file_table_length
        .set(manifest.file_table.len() as i64);

    let file_chunk_id_range_length = FILE_GROUP_CHUNK_ID_OFFSET as usize - FILE_CHUNK_ID_OFFSET;
    if manifest.chunk_table.len() > file_chunk_id_range_length / 2 {
        error!(
            log,
            "{}: The chunk table is longer than half of the available ID space for file chunks in state sync. chunk table length: {}, file chunk ID range length: {}",
            CRITICAL_ERROR_CHUNK_ID_USAGE_NEARING_LIMITS,
            manifest.chunk_table.len(),
            file_chunk_id_range_length,
        );
        metrics.chunk_id_usage_nearing_limits_critical.inc();
    }

    // Sanity check: ensure that we have produced a valid manifest.
    debug_assert_eq!(Ok(()), validate_manifest_internal_consistency(&manifest));

    Ok(manifest)
}

/// Validates the internal consistency of the manifest.
pub fn validate_manifest_internal_consistency(
    manifest: &Manifest,
) -> Result<(), ManifestValidationError> {
    if manifest.version > MAX_SUPPORTED_STATE_SYNC_VERSION {
        return Err(ManifestValidationError::UnsupportedManifestVersion {
            manifest_version: manifest.version,
            max_supported_version: MAX_SUPPORTED_STATE_SYNC_VERSION,
        });
    }

    let mut chunk_start: usize = 0;
    let mut last_path: Option<&Path> = None;
    for (file_index, f) in manifest.file_table.iter().enumerate() {
        if f.relative_path.is_absolute() {
            return Err(ManifestValidationError::InconsistentManifest {
                reason: format!("absolute file path: {},", f.relative_path.display(),),
            });
        }
        if let Some(last_path) = last_path {
            if f.relative_path <= last_path {
                return Err(ManifestValidationError::InconsistentManifest {
                    reason: format!(
                        "file paths are not sorted: {}, {}",
                        last_path.display(),
                        f.relative_path.display()
                    ),
                });
            }
        }

        let mut hasher = file_hasher();

        let chunk_count: usize = manifest.chunk_table[chunk_start..]
            .iter()
            .take_while(|chunk| chunk.file_index as usize == file_index)
            .count();

        (chunk_count as u32).update_hash(&mut hasher);

        let mut file_offset = 0;
        for i in chunk_start..chunk_start + chunk_count {
            let chunk_info = manifest.chunk_table.get(i).unwrap();
            assert_eq!(chunk_info.file_index, file_index as u32);
            if chunk_info.offset != file_offset {
                return Err(ManifestValidationError::InconsistentManifest {
                    reason: format!(
                        "unexpected offset for chunk {} of file {}: was {}, expected {}",
                        i,
                        f.relative_path.display(),
                        chunk_info.offset,
                        file_offset
                    ),
                });
            }
            file_offset += chunk_info.size_bytes as u64;
            write_chunk_hash(&mut hasher, chunk_info, manifest.version);
        }
        if f.size_bytes != file_offset {
            return Err(ManifestValidationError::InconsistentManifest {
                reason: format!(
                    "mismatching file size and total chunk size for {}: {} vs {}",
                    f.relative_path.display(),
                    f.size_bytes,
                    file_offset
                ),
            });
        }

        let hash = hasher.finish();
        if hash != f.hash {
            return Err(ManifestValidationError::InvalidFileHash {
                relative_path: f.relative_path.clone(),
                expected_hash: f.hash.to_vec(),
                actual_hash: hash.to_vec(),
            });
        }

        chunk_start += chunk_count;
        last_path = Some(&f.relative_path);
    }

    if manifest.chunk_table.len() != chunk_start {
        return Err(ManifestValidationError::InconsistentManifest {
            reason: format!(
                "extra chunks in manifest: actual {}, expected {}",
                manifest.chunk_table.len(),
                chunk_start
            ),
        });
    }

    Ok(())
}

/// Validates manifest contents and checks that the hash of the manifest matches
/// the expected root hash.
pub fn validate_manifest(
    manifest: &Manifest,
    root_hash: &CryptoHashOfState,
) -> Result<(), ManifestValidationError> {
    validate_manifest_internal_consistency(manifest)?;

    let hash = manifest_hash(manifest);

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
    let mut hasher = chunk_hasher();

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

/// Checks that the size and hash of the received sub-manifest match the meta-manifest.
pub fn validate_sub_manifest(
    ix: usize,
    bytes: &[u8],
    meta_manifest: &MetaManifest,
) -> Result<(), ChunkValidationError> {
    let expected_hash = meta_manifest.sub_manifest_hashes.get(ix).ok_or(
        ChunkValidationError::InvalidChunkIndex {
            chunk_ix: ix,
            actual_length: meta_manifest.sub_manifest_hashes.len(),
        },
    )?;

    let mut hasher = sub_manifest_hasher();

    let hash = {
        hasher.write(bytes);
        hasher.finish()
    };
    if hash != *expected_hash {
        return Err(ChunkValidationError::InvalidChunkHash {
            chunk_ix: ix,
            expected_hash: expected_hash.to_vec(),
            actual_hash: hash.to_vec(),
        });
    }
    Ok(())
}

/// Computes root hash of the manifest based on its version.
/// See note [Manifest Hash].
pub fn manifest_hash(manifest: &Manifest) -> [u8; 32] {
    assert!(manifest.version <= MAX_SUPPORTED_STATE_SYNC_VERSION);
    if manifest.version >= StateSyncVersion::V2 {
        manifest_hash_v2(manifest)
    } else {
        manifest_hash_v1(manifest)
    }
}

fn manifest_hash_v1(manifest: &Manifest) -> [u8; 32] {
    assert!(manifest.version <= StateSyncVersion::V1);

    let mut hash = manifest_hasher();

    if manifest.version >= StateSyncVersion::V1 {
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

    if manifest.version >= StateSyncVersion::V1 {
        (manifest.chunk_table.len() as u32).update_hash(&mut hash);

        for c in manifest.chunk_table.iter() {
            write_chunk_hash(&mut hash, c, manifest.version);
        }
    }

    hash.finish()
}

/// Builds meta-manifest from a manifest by encoding, splitting and hashing.
pub fn build_meta_manifest(manifest: &Manifest) -> MetaManifest {
    let mut sub_manifest_hashes = Vec::new();

    let encoded_manifest = encode_manifest(manifest);
    let size_bytes = encoded_manifest.len();
    let mut bytes_left = size_bytes;
    let mut hashed_bytes = 0;

    while bytes_left > 0 {
        let sub_manifest_size = bytes_left.min(DEFAULT_CHUNK_SIZE as usize);
        let offset = size_bytes - bytes_left;

        let mut sub_manifest_hasher = sub_manifest_hasher();
        let sub_manifest = &encoded_manifest[offset..offset + sub_manifest_size];
        sub_manifest.update_hash(&mut sub_manifest_hasher);
        let sub_manifest_hash = sub_manifest_hasher.finish();

        sub_manifest_hashes.push(sub_manifest_hash);

        bytes_left -= sub_manifest_size;
        hashed_bytes += sub_manifest_size;
    }

    debug_assert_eq!(hashed_bytes, size_bytes);

    MetaManifest {
        version: manifest.version,
        sub_manifest_hashes,
    }
}

/// Computes the hash of meta-manifest.
fn meta_manifest_hash(meta_manifest: &MetaManifest) -> [u8; 32] {
    let mut hash = meta_manifest_hasher();
    meta_manifest.version.update_hash(&mut hash);
    (meta_manifest.sub_manifest_hashes.len() as u32).update_hash(&mut hash);
    for sub_manifest_hash in &meta_manifest.sub_manifest_hashes {
        sub_manifest_hash.update_hash(&mut hash);
    }
    hash.finish()
}

/// The meta-manifest hash is used as the manifest hash if its version is greater than or equal to `StateSyncVersion::V1`.
fn manifest_hash_v2(manifest: &Manifest) -> [u8; 32] {
    assert!(manifest.version >= StateSyncVersion::V2);
    let meta_manifest = build_meta_manifest(manifest);
    meta_manifest_hash(&meta_manifest)
}

/// Computes the bundled metadata from a manifest.
pub(crate) fn compute_bundled_manifest(manifest: Manifest) -> BundledManifest {
    let meta_manifest = build_meta_manifest(&manifest);
    let hash = if manifest.version >= StateSyncVersion::V2 {
        meta_manifest_hash(&meta_manifest)
    } else {
        manifest_hash_v1(&manifest)
    };
    let root_hash = CryptoHashOfState::from(CryptoHash(hash.to_vec()));
    BundledManifest {
        root_hash,
        manifest,
        meta_manifest: Arc::new(meta_manifest),
    }
}

/// Checks that the hash of the meta-manifest matches the expected root hash.
pub fn validate_meta_manifest(
    meta_manifest: &MetaManifest,
    root_hash: &CryptoHashOfState,
) -> Result<(), ManifestValidationError> {
    if meta_manifest.version > MAX_SUPPORTED_STATE_SYNC_VERSION {
        return Err(ManifestValidationError::UnsupportedManifestVersion {
            manifest_version: meta_manifest.version,
            max_supported_version: MAX_SUPPORTED_STATE_SYNC_VERSION,
        });
    }

    let hash = meta_manifest_hash(meta_manifest);

    if root_hash.get_ref().0 != hash {
        return Err(ManifestValidationError::InvalidRootHash {
            expected_hash: root_hash.get_ref().0.clone(),
            actual_hash: hash.to_vec(),
        });
    }

    Ok(())
}

/// Computes diff between two manifests and get DiffScript.
pub fn diff_manifest(
    manifest_old: &Manifest,
    missing_chunks_old: &HashSet<usize>,
    manifest_new: &Manifest,
) -> DiffScript {
    // missing_chunks_old should only contain chunks that are listed in manifest_old
    debug_assert!(
        missing_chunks_old.is_empty()
            || *missing_chunks_old.iter().max().unwrap() < manifest_old.chunk_table.len()
    );

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

    let chunk_index_to_file_index = |chunk_index: &usize| {
        let chunk_info = manifest_old
            .chunk_table
            .get(*chunk_index)
            .unwrap_or_else(|| panic!("Invalid chunk index {}", chunk_index));

        chunk_info.file_index as usize
    };

    // A file is missing if at least one of its chunks is missing
    let missing_files_old: HashSet<usize> = missing_chunks_old
        .iter()
        .map(chunk_index_to_file_index)
        .collect();

    let file_hash_to_index: HashMap<[u8; 32], OldIndex> = manifest_old
        .file_table
        .iter()
        .enumerate()
        .filter(|(index, _)| !missing_files_old.contains(index))
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
        .filter(|(index, _)| !missing_chunks_old.contains(index))
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

/// Helper function to compute the manifest from a raw path.
/// This function is intended for tests and external tools only.
pub fn manifest_from_path(path: &Path) -> Result<Manifest, CheckpointError> {
    let cp_layout = CheckpointLayout::<ReadOnly>::new_untracked(path.to_owned(), Height::new(0))?;

    let metadata = cp_layout.system_metadata().deserialize()?;

    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
    let metrics_registry = MetricsRegistry::new();
    let manifest_metrics = ManifestMetrics::new(&metrics_registry);
    compute_manifest(
        &mut thread_pool,
        &manifest_metrics,
        &no_op_logger(),
        metadata
            .state_sync_version
            .try_into()
            .map_err(|v| CheckpointError::ProtoError {
                path: path.to_path_buf(),
                field: "SystemMetadata::state_sync_version".into(),
                proto_err: format!("Replica does not implement state sync version {}", v),
            })?,
        &cp_layout,
        DEFAULT_CHUNK_SIZE,
        None,
    )
}
