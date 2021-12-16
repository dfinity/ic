pub mod hash;

#[cfg(test)]
mod tests;

use super::CheckpointError;
use crate::{DirtyPages, ManifestMetrics, CRITICAL_ERROR_REUSED_CHUNK_HASH};
use bit_vec::BitVec;
use hash::{
    chunk_hasher, cow_chunk_hasher, cow_file_hasher, file_hasher, manifest_hasher, ManifestHash,
};
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState};
use ic_crypto_sha::Sha256;
use ic_logger::{error, ReplicaLogger};
use ic_state_layout::{CheckpointLayout, ReadOnly};
use ic_sys::{mmap::ScopedMmap, PAGE_SIZE};
use ic_types::{
    state_sync::{ChunkInfo, FileInfo, Manifest},
    CryptoHashOfState, Height,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

pub const STATE_SYNC_V1: u32 = 1;

/// The version of StateSync protocol that should be used for all newly produced
/// states.
pub const CURRENT_STATE_SYNC_VERSION: u32 = STATE_SYNC_V1;

pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20; // 1 MiB.

/// When computing a manifest, we recompute the hash of every
/// `REHASH_EVERY_NTH_CHUNK` chunk, even if we know it to be unchanged and
/// have a hash computed earlier by this replica process.
const REHASH_EVERY_NTH_CHUNK: u64 = 10;

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
#[derive(Clone)]
struct FileWithSize(PathBuf, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Wasm memory pages that might have changed since the state at
    /// `base_height`.
    pub(crate) dirty_memory_pages: DirtyPages,
}

fn write_chunk_hash(hasher: &mut Sha256, chunk_info: &ChunkInfo) {
    chunk_info.file_index.update_hash(hasher);
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

/// Updates manifest computation statistics.
fn update_metrics(metrics: &ManifestMetrics, chunk_actions: &[ChunkAction], chunks: &[ChunkInfo]) {
    let mut hashed_bytes = 0;
    let mut reused_bytes = 0;
    let mut hashed_and_compared_bytes = 0;

    for (i, chunk) in chunks.iter().enumerate() {
        match chunk_actions[i] {
            ChunkAction::Recompute => {
                hashed_bytes += chunk.size_bytes as u64;
            }
            ChunkAction::UseHash(_) => {
                reused_bytes += chunk.size_bytes as u64;
            }
            ChunkAction::RecomputeAndCompare(_) => {
                hashed_and_compared_bytes += chunk.size_bytes as u64;
            }
        }
    }

    metrics.hashed_chunk_bytes.inc_by(hashed_bytes);
    metrics.reused_chunk_bytes.inc_by(reused_bytes);
    metrics
        .hashed_and_compared_chunk_bytes
        .inc_by(hashed_and_compared_bytes);
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
                                ScopedMmap::from_path(&file_path).expect("failed to open file"),
				);
				cache.insert(chunk_info.file_index, Arc::downgrade(&mmap));
				mmap
                            }
			}
                    } else {
			Arc::new(ScopedMmap::from_path(&file_path).expect("failed to open file"))
                    };
                    let data = mmap.as_slice();

		    let mut hasher = chunk_hasher();
                    let chunk_start = chunk_info.offset as usize;
                    let chunk_end = chunk_start + chunk_info.size_bytes as usize;
                    hasher.write(&data[chunk_start..chunk_end]);
                    hasher.finish()
                };

                chunk_info.hash = match chunk_action {
                    ChunkAction::Recompute => recompute_chunk_hash(),
                    ChunkAction::RecomputeAndCompare(precomputed_hash) => {
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
                    ChunkAction::UseHash(precomputed_hash) => precomputed_hash,
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
            write_chunk_hash(&mut hasher, &chunk_table[chunk_idx])
        }
        file_info.hash = hasher.finish();
    }

    update_metrics(metrics, &chunk_actions, &chunk_table);

    (file_table, chunk_table)
}

/// Build a chunk table from the file table.
fn build_chunk_table_sequential(
    metrics: &ManifestMetrics,
    log: &ReplicaLogger,
    root: &Path,
    files: Vec<FileWithSize>,
    max_chunk_size: u32,
    chunk_actions: Vec<ChunkAction>,
) -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    let mut chunk_table = Vec::new();
    let mut file_table = Vec::new();
    let mut chunk_index: usize = 0;

    for (file_index, FileWithSize(relative_path, size_bytes)) in files.into_iter().enumerate() {
        let mut file_hash = if relative_path.ends_with("state_file") {
            cow_file_hasher()
        } else {
            file_hasher()
        };

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
                    let mut hasher = if relative_path.ends_with("state_file") {
                        cow_chunk_hasher()
                    } else {
                        chunk_hasher()
                    };
                    hasher.write(&data[offset as usize..(offset + chunk_size) as usize]);
                    hasher.finish()
                };

                assert!(chunk_index < chunk_actions.len());

                let chunk_hash = match chunk_actions[chunk_index] {
                    ChunkAction::RecomputeAndCompare(reused_chunk_hash) => {
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
                    ChunkAction::UseHash(reused_chunk_hash) => reused_chunk_hash,
                    ChunkAction::Recompute => recompute_chunk_hash(),
                };

                let chunk_info = ChunkInfo {
                    file_index: file_index as u32,
                    size_bytes: chunk_size as u32,
                    offset: offset as u64,
                    hash: chunk_hash,
                };

                write_chunk_hash(&mut file_hash, &chunk_info);

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

    assert_eq!(chunk_table.len(), chunk_actions.len());

    update_metrics(metrics, &chunk_actions, &chunk_table);

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
    let offset = rng.gen_range(0, rehash_every_nth);

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
    return vec![ChunkAction::Recompute; chunks_total];
}

/// Computes the bitmap of chunks modified since the base state.
fn dirty_pages_to_dirty_chunks(
    manifest_delta: &ManifestDelta,
    checkpoint_root_path: &Path,
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

    // The field `height` of the checkpoint layout is not used here.
    // The checkpoint layout is only used to get the file path of canister heap.
    let checkpoint_layout: CheckpointLayout<ReadOnly> =
        CheckpointLayout::new(PathBuf::from(checkpoint_root_path), Height::from(0))?;

    let mut dirty_chunks: BTreeMap<PathBuf, BitVec> = Default::default();
    for (canister_id, (height, page_indices)) in manifest_delta.dirty_memory_pages.iter() {
        if *height != manifest_delta.base_height {
            continue;
        }

        if let Ok(canister_layout) = checkpoint_layout.canister(canister_id) {
            let vmemory_0 = canister_layout.vmemory_0();
            let vmemory_relative_path = vmemory_0
                .strip_prefix(checkpoint_root_path)
                .expect("failed to strip path prefix");

            if let Ok(index) = files.binary_search_by(|FileWithSize(file_path, _)| {
                file_path.as_path().cmp(vmemory_relative_path)
            }) {
                let size_bytes = files[index].1;
                let num_chunks = count_chunks(size_bytes, max_chunk_size);
                let mut chunks_bitmap = BitVec::from_elem(num_chunks, false);

                for page_index in page_indices {
                    // As the chunk size is multiple times of the page size, at most one chunk could
                    // possibly be affected.
                    let chunk_index =
                        PAGE_SIZE * page_index.get() as usize / max_chunk_size as usize;
                    chunks_bitmap.set(chunk_index, true);
                }

                // NB. The code below handles the case when the file size increased, but the
                // dirty pages do not cover the new area.  This should not happen in the current
                // implementation of PageMap, but we don't want to rely too much on these
                // implementation details.  So we mark the expanded area as dirty explicitly
                // instead.
                let base_file_index = manifest_delta
                    .base_manifest
                    .file_table
                    .binary_search_by(|file_info| {
                        file_info.relative_path.as_path().cmp(vmemory_relative_path)
                    })
                    .expect("couldn't find a file in the base manifest");

                let base_file_size =
                    manifest_delta.base_manifest.file_table[base_file_index].size_bytes;

                if base_file_size < size_bytes {
                    let from_chunk = count_chunks(base_file_size, max_chunk_size).max(1) - 1;
                    for i in from_chunk..num_chunks {
                        chunks_bitmap.set(i, true);
                    }
                }

                dirty_chunks.insert(vmemory_relative_path.to_path_buf(), chunks_bitmap);
            }
        }
    }
    Ok(dirty_chunks)
}

/// Computes manifest for the checkpoint located at `checkpoint_root_path`.
pub fn compute_manifest(
    thread_pool: &mut scoped_threadpool::Pool,
    metrics: &ManifestMetrics,
    log: &ReplicaLogger,
    version: u32,
    checkpoint_root_path: &Path,
    max_chunk_size: u32,
    opt_manifest_delta: Option<ManifestDelta>,
) -> Result<Manifest, CheckpointError> {
    let mut files = Vec::new();
    files_with_sizes(checkpoint_root_path, "".into(), &mut files)?;
    // We sort the table to make sure that the table is the same on all replicas
    files.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    let chunk_actions = match opt_manifest_delta {
        Some(manifest_delta) => {
            // We have to check that the old manifest uses exactly the same chunk size.
            // Otherwise, if someone decides to change the chunk size in future,
            // all the tests are going to pass (because all of them will use the
            // new chunk size), but the manifest might be computed incorrectly
            // on the mainnet.
            if uses_chunk_size(&manifest_delta.base_manifest, max_chunk_size) {
                let dirty_file_chunks = dirty_pages_to_dirty_chunks(
                    &manifest_delta,
                    checkpoint_root_path,
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

    if files
        .iter()
        .any(|FileWithSize(path, _)| path.ends_with("state_file"))
    {
        // The parallel algorithm doesn't handle COW memory manager, which is a subject
        // for removal anyway.
        let (file_table, chunk_table) = build_chunk_table_sequential(
            metrics,
            log,
            checkpoint_root_path,
            files,
            max_chunk_size,
            chunk_actions,
        );
        Ok(Manifest {
            version,
            file_table,
            chunk_table,
        })
    } else {
        #[cfg(debug_assertions)]
        let (seq_file_table, seq_chunk_table) = {
            let metrics_registry = ic_metrics::MetricsRegistry::new();
            let metrics = ManifestMetrics::new(&metrics_registry);
            build_chunk_table_sequential(
                &metrics,
                log,
                checkpoint_root_path,
                files.clone(),
                max_chunk_size,
                chunk_actions.clone(),
            )
        };

        let (file_table, chunk_table) = build_chunk_table_parallel(
            thread_pool,
            metrics,
            log,
            checkpoint_root_path,
            files,
            max_chunk_size,
            chunk_actions,
        );

        #[cfg(debug_assertions)]
        {
            assert_eq!(file_table, seq_file_table);
            assert_eq!(chunk_table, seq_chunk_table);
        }

        Ok(Manifest {
            version,
            file_table,
            chunk_table,
        })
    }
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
            .expect("Invalid chunk index");

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
