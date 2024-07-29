use crate::{
    manifest::{build_file_group_chunks, filter_out_zero_chunks, DiffScript},
    state_sync::types::{
        decode_manifest, decode_meta_manifest, state_sync_chunk_type, FileGroupChunks, Manifest,
        MetaManifest, StateSyncChunk, StateSyncMessage, FILE_CHUNK_ID_OFFSET,
        FILE_GROUP_CHUNK_ID_OFFSET, MANIFEST_CHUNK_ID_OFFSET, META_MANIFEST_CHUNK,
    },
    state_sync::StateSync,
    StateManagerMetrics, StateSyncMetrics, StateSyncRefs,
    CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS, LABEL_COPY_CHUNKS, LABEL_COPY_FILES, LABEL_FETCH,
    LABEL_FETCH_MANIFEST_CHUNK, LABEL_FETCH_META_MANIFEST_CHUNK, LABEL_FETCH_STATE_CHUNK,
    LABEL_PREALLOCATE, LABEL_STATE_SYNC_MAKE_CHECKPOINT,
};
use ic_interfaces::p2p::state_sync::{AddChunkError, Chunk, ChunkId, Chunkable};
use ic_logger::{debug, error, fatal, info, trace, warn, ReplicaLogger};
use ic_state_layout::utils::do_copy_overwrite;
use ic_state_layout::{error::LayoutError, CheckpointLayout, ReadOnly, RwPolicy, StateLayout};
use ic_sys::mmap::ScopedMmap;
use ic_types::{malicious_flags::MaliciousFlags, CryptoHashOfState, Height};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
};

pub mod cache;

// If set to true, we validate chunks even in situations where it might not be
// necessary.
const ALWAYS_VALIDATE: bool = false;

type SubManifest = Vec<u8>;
/// The state of the communication with up-to-date nodes.
#[derive(Clone)]
enum DownloadState {
    /// Haven't received any chunks yet, waiting for the meta-manifest chunk.
    Blank,
    /// In the process of assembling the manifest.
    Prep {
        /// The received meta-manifest
        meta_manifest: MetaManifest,
        /// This field stores the sub-manifests received and can be used to reconstruct the whole manifest.
        manifest_in_construction: BTreeMap<u32, SubManifest>,
        /// Set of chunks that still needed to be fetched for the manifest.
        manifest_chunks: BTreeSet<u32>,
    },
    /// In the process of loading chunks, have some more to load.
    Loading {
        /// The received meta-manifest
        meta_manifest: MetaManifest,
        /// The received manifest
        manifest: Manifest,
        state_sync_file_group: FileGroupChunks,
        /// Set of chunks that still need to be fetched. For the purpose of this
        /// set, chunk 0 is the meta-manifest.
        ///
        /// To get indices into the manifest's chunk table, subtract 1. Note that
        /// it does not apply to file group chunks because they are assigned with
        /// a dedicated chunk id range.
        /// The manifest chunks are not part of `fetch_chunks` because they are fetched in the `Prep` phase.
        fetch_chunks: HashSet<usize>,
    },
    /// Successfully completed and delivered the state sync, nothing else to do.
    Complete,
}

/// An implementation of Chunkable trait that represents a (on-disk) state under
/// construction.
///
/// P2P decides when to start or abort a fetch based on the output of the state
/// sync priority function.  When priority function returns "Fetch", P2P calls
/// StateManager to construct an IncompleteState corresponding to the state
/// artifact advert.
pub(crate) struct IncompleteState {
    log: ReplicaLogger,
    root: PathBuf,
    state_sync: Arc<StateSync>,
    state_layout: StateLayout,
    height: Height,
    root_hash: CryptoHashOfState,
    state: DownloadState,
    manifest_with_checkpoint_layout: Option<(Manifest, CheckpointLayout<ReadOnly>)>,
    metrics: StateManagerMetrics,
    started_at: Instant,
    fetch_started_at: Option<Instant>,
    thread_pool: Arc<Mutex<scoped_threadpool::Pool>>,
    state_sync_refs: StateSyncRefs,
    #[allow(dead_code)]
    malicious_flags: MaliciousFlags,
}

impl Drop for IncompleteState {
    fn drop(&mut self) {
        // If state sync is aborted before completion we need to
        // measure the total duration here
        let elapsed = self.started_at.elapsed();
        match &self.state {
            DownloadState::Blank => {
                self.metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["aborted_blank"])
                    .observe(elapsed.as_secs_f64());
            }
            DownloadState::Prep { .. } => {
                self.metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["aborted_prep"])
                    .observe(elapsed.as_secs_f64());
            }
            DownloadState::Loading {
                meta_manifest: _,
                manifest: _,
                state_sync_file_group,
                fetch_chunks,
            } => {
                self.metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["aborted"])
                    .observe(elapsed.as_secs_f64());

                let dropped_chunks: usize = fetch_chunks
                    .iter()
                    .map(|ix| {
                        if (*ix as u32) < FILE_GROUP_CHUNK_ID_OFFSET {
                            1
                        } else {
                            state_sync_file_group
                                .get(&(*ix as u32))
                                .map(|vec| vec.len())
                                .unwrap_or(0)
                        }
                    })
                    .sum();
                self.metrics
                    .state_sync_metrics
                    .remaining
                    .sub(dropped_chunks as i64);
            }
            DownloadState::Complete => {
                // state sync duration already recorded earlier in make_checkpoint
            }
        }

        // We need to record the download state before passing self to the cache, as
        // passing it to the cache might alter the download state
        let description = match self.state {
            DownloadState::Blank => "aborted before receiving any chunks",
            DownloadState::Prep { .. } => "aborted before receiving the entire manifest",
            DownloadState::Loading { .. } => "aborted before receiving all the chunks",
            DownloadState::Complete => "completed successfully",
        };

        info!(self.log, "State sync @{} {}", self.height, description);

        // Pass self to the cache, taking ownership of chunks on disk
        let cache = Arc::clone(&self.state_sync_refs.cache);
        cache.write().push(self);

        // Remove the active state sync reference
        let mut active = self.state_sync_refs.active.write();
        match active.take() {
            Some((active_height, _hash)) => {
                if active_height != self.height {
                    warn!(
                        self.log,
                        "the active state sync reference was for a different height @{}, expected @{}",
                        active_height,
                        self.height,
                    );
                }
            }
            None => {
                warn!(self.log, "the active state sync reference was None",);
            }
        }
    }
}

impl IncompleteState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        log: ReplicaLogger,
        height: Height,
        root_hash: CryptoHashOfState,
        state_sync: Arc<StateSync>,
        thread_pool: Arc<Mutex<scoped_threadpool::Pool>>,
    ) -> Option<IncompleteState> {
        // The state sync manager in the p2p layer is expected not to start a new state sync when there is an ongoing state sync.
        // Here we check it again as a last resort and return `None` if there is already an active state sync reference.
        let mut active = state_sync.state_sync_refs.active.write();
        if let Some((active_height, _hash)) = active.as_ref() {
            warn!(
                &log,
                "Attempt to start state sync @{} while we are fetching state @{}",
                height,
                active_height
            );
            return None;
        }
        *active = Some((height, root_hash.clone()));
        let state_layout = state_sync.state_manager.state_layout.clone();
        // Create the `IncompleteState` object while holding the write lock on the active state sync reference.
        Some(Self {
            log,
            root: state_layout
                .state_sync_scratchpad(height)
                .expect("failed to create directory for state sync scratchpad"),
            state_sync: state_sync.clone(),
            state_layout,
            height,
            root_hash,
            state: DownloadState::Blank,
            manifest_with_checkpoint_layout: state_sync.state_manager.latest_manifest(),
            metrics: state_sync.state_manager.metrics.clone(),
            started_at: Instant::now(),
            fetch_started_at: None,
            thread_pool,
            state_sync_refs: state_sync.state_sync_refs.clone(),
            malicious_flags: state_sync.state_manager.malicious_flags.clone(),
        })
    }

    /// Creates all the files listed in the manifest and resizes them to their
    /// expected sizes.  This way we won't have to worry about creating parent
    /// directories when we receive chunks.
    pub(crate) fn preallocate_layout(log: &ReplicaLogger, root: &Path, manifest: &Manifest) {
        for file_info in manifest.file_table.iter() {
            let path = root.join(&file_info.relative_path);

            std::fs::create_dir_all(
                path.parent()
                    .expect("every file in the manifest must have a parent"),
            )
            .unwrap_or_else(|err| {
                fatal!(
                    log,
                    "Failed to create parent directory for path {}: {}",
                    path.display(),
                    err
                )
            });

            let f = std::fs::File::create(&path).unwrap_or_else(|err| {
                fatal!(log, "Failed to create file {}: {}", path.display(), err)
            });
            f.set_len(file_info.size_bytes).unwrap_or_else(|err| {
                fatal!(
                    log,
                    "Failed to truncate file {} to size {}: {}",
                    path.display(),
                    file_info.size_bytes,
                    err
                )
            });
        }
    }

    /// Copy reusable files from previous checkpoint according to diff script.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn copy_files(
        log: &ReplicaLogger,
        metrics: &StateSyncMetrics,
        thread_pool: &mut scoped_threadpool::Pool,
        root_old: &Path,
        root_new: &Path,
        manifest_old: &Manifest,
        manifest_new: &Manifest,
        diff_script: &DiffScript,
        validate_data: bool,
        fetch_chunks: &mut HashSet<usize>,
    ) {
        let _timer = metrics
            .step_duration
            .with_label_values(&[LABEL_COPY_FILES])
            .start_timer();

        info!(
            log,
            "state sync: copy_files for {} files {} validation",
            diff_script.copy_files.len(),
            if validate_data || ALWAYS_VALIDATE {
                "with"
            } else {
                "without"
            }
        );

        let corrupted_chunks = Arc::new(Mutex::new(Vec::new()));

        thread_pool.scoped(|scope| {
            for (new_index, old_index) in diff_script.copy_files.iter() {
                let src_path = root_old.join(&manifest_old.file_table[*old_index].relative_path);
                let dst_path = root_new.join(&manifest_new.file_table[*new_index].relative_path);
                let corrupted_chunks = Arc::clone(&corrupted_chunks);

                scope.execute(move || {
                    let new_chunk_range = crate::manifest::file_chunk_range(
                        &manifest_new.chunk_table,
                        *new_index,
                    );

                    let original_perms = std::fs::metadata(&dst_path).unwrap_or_else(|err| {
                        fatal!(
                            log,
                            "Failed to get metadata of file {}: {}",
                            dst_path.display(),
                            err
                        )
                    })
                        .permissions();
                    if validate_data || ALWAYS_VALIDATE {

                        let src = std::fs::File::open(&src_path).unwrap_or_else(|err| {
                            fatal!(
                                log,
                                "Failed to open file {} for read: {}",
                                src_path.display(),
                                err
                            )
                        });
                        let src_len = src
                            .metadata()
                            .unwrap_or_else(|err| {
                                fatal!(
                                    log,
                                    "Failed to get metadata of file {}: {}",
                                    src_path.display(),
                                    err
                                )
                            })
                            .len() as usize;

                        let src_map = ScopedMmap::from_readonly_file(&src, src_len).unwrap_or_else(|err| {
                            fatal!(log, "Failed to mmap file {}: {}", src_path.display(), err)
                        });
                        let src_data = src_map.as_slice();

                        let old_chunk_range = crate::manifest::file_chunk_range(
                            &manifest_old.chunk_table,
                            *old_index,
                        );

                        // bad_chunks contains ids of chunks from the old checkpoint that
                        // didn't pass validation or refer to non-existing portions of
                        // the corresponding file.  The contents of these chunks will be
                        // requested later from peers.
                        let mut bad_chunks = vec![];

                        // Go through all the chunks of the local file and validate
                        // each one.  If the validation fails, add the corresponding new
                        // chunk ids to the set of chunks to fetch.
                        for idx in old_chunk_range.clone() {
                            let chunk = &manifest_old.chunk_table[idx];
                            let chunk_offset = idx - old_chunk_range.start;
                            let new_chunk_idx = new_chunk_range.start + chunk_offset;
                            let byte_range = chunk.byte_range();

                            if src_data.len() < byte_range.end {
                                warn!(
                                    log,
                                    "Local chunk {} ({}@{}—{}) is out of range (file len = {}), \
                                     will request chunk {} instead",
                                    idx,
                                    src_path.display(),
                                    byte_range.start,
                                    byte_range.end,
                                    src_data.len(),
                                    new_chunk_idx + FILE_CHUNK_ID_OFFSET
                                );
                                bad_chunks.push(idx);
                                corrupted_chunks.lock().unwrap().push(new_chunk_idx + FILE_CHUNK_ID_OFFSET);
                                if !validate_data && ALWAYS_VALIDATE {
                                    error!(
                                        log,
                                        "{}: Unexpected chunk validation error for local chunk {}",
                                        CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS,
                                        idx,
                                    );
                                    metrics.corrupted_chunks_critical.inc();
                                }
                                metrics.corrupted_chunks.with_label_values(&[LABEL_COPY_FILES]).inc();
                                continue;
                            }

                            if let Err(err) = crate::manifest::validate_chunk(
                                idx,
                                &src_data[byte_range.clone()],
                                manifest_old,
                            ) {
                                warn!(
                                    log,
                                    "Local chunk {} ({}@{}–{}) doesn't pass validation: {}, \
                                     will request chunk {} instead",
                                    idx,
                                    src_path.display(),
                                    byte_range.start,
                                    byte_range.end,
                                    err,
                                    new_chunk_idx + FILE_CHUNK_ID_OFFSET
                                );

                                bad_chunks.push(idx);
                                corrupted_chunks.lock().unwrap().push(new_chunk_idx + FILE_CHUNK_ID_OFFSET);
                                if !validate_data && ALWAYS_VALIDATE {
                                    error!(
                                        log,
                                        "{}: Unexpected chunk validation error for local chunk {}",
                                        CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS,
                                        idx,
                                    );
                                    metrics.corrupted_chunks_critical.inc();
                                }
                                metrics.corrupted_chunks.with_label_values(&[LABEL_COPY_FILES]).inc();
                            }
                        }

                        if bad_chunks.is_empty()
                            && src_data.len()
                                == manifest_old.file_table[*old_index].size_bytes as usize
                        {
                            // All the hash sums and the file size match, so we can
                            // simply copy the whole file.  That's much faster than
                            // copying one chunk at a time.
                            do_copy_overwrite(log, &src_path, &dst_path).unwrap_or_else(
                                |err| {
                                    fatal!(
                                        log,
                                        "Failed to copy file from {} to {}: {}",
                                        src_path.display(),
                                        dst_path.display(),
                                        err
                                    )
                                },
                            );
                            metrics
                                .remaining
                                .sub(new_chunk_range.len() as i64);
                        } else {
                            // Copy the chunks that passed validation to the
                            // destination, the rest will be fetched and applied later.
                            let dst = std::fs::OpenOptions::new()
                                .write(true)
                                .create(false)
                                .open(&dst_path)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to open file {}: {}",
                                        dst_path.display(),
                                        err
                                    )
                                });
                            for idx in old_chunk_range {
                                if bad_chunks.contains(&idx) {
                                    continue;
                                }

                                let chunk = &manifest_old.chunk_table[idx];

                                #[cfg(target_os = "linux")]
                                {
                                    // The source and the destination offsets are the same because we are copying
                                    // over uncorrupted chunks of the file into the new checkpoint.
                                    let src_offset = chunk.offset as i64;
                                    let dst_offset = chunk.offset as i64;

                                    ic_sys::fs::copy_file_range_all(
                                        &src,
                                        src_offset,
                                        &dst,
                                        dst_offset,
                                        chunk.size_bytes as usize
                                    ).unwrap_or_else(|err| {
                                        fatal!(
                                            log,
                                            "Failed to copy file range from {} => {} (offset = {}, size = {}): {}",
                                            src_path.display(),
                                            dst_path.display(),
                                            chunk.offset,
                                            chunk.size_bytes,
                                            err
                                        )
                                    });
                                }

                                #[cfg(not(target_os = "linux"))]
                                {
                                    let data = &src_data[chunk.byte_range()];

                                    dst.write_all_at(data, chunk.offset).unwrap_or_else(|err| {
                                        fatal!(
                                            log,
                                            "Failed to write chunk (offset = {}, size = {}) to file {}: {}",
                                            chunk.offset,
                                            chunk.size_bytes,
                                            dst_path.display(),
                                            err
                                        )
                                    });
                                }
                                metrics.remaining.sub(1);
                            }
                        }
                    } else {
                        // Since we do not validate in this else branch, we can simply copy the
                        // file without any extra work
                        do_copy_overwrite(log, &src_path, &dst_path).unwrap_or_else(|err| {
                            fatal!(
                                log,
                                "Failed to copy file from {} to {}: {}",
                                src_path.display(),
                                dst_path.display(),
                                err
                            )
                        });
                        metrics
                            .remaining
                            .sub(new_chunk_range.len() as i64);
                    }
                    std::fs::set_permissions(&dst_path, original_perms).unwrap_or_else(|err| {
                        fatal!(
                            log,
                            "failed to set permissions for file {}: {}",
                            dst_path.display(),
                            err
                        )
                    });
                });
            }
        });
        for chunk_idx in corrupted_chunks.lock().unwrap().iter() {
            fetch_chunks.insert(*chunk_idx);
        }
    }

    /// Copy reusable chunks from previous checkpoint according to diff script.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn copy_chunks(
        log: &ReplicaLogger,
        metrics: &StateSyncMetrics,
        thread_pool: &mut scoped_threadpool::Pool,
        root_old: &Path,
        root_new: &Path,
        manifest_old: &Manifest,
        manifest_new: &Manifest,
        diff_script: &DiffScript,
        validate_data: bool,
        fetch_chunks: &mut HashSet<usize>,
    ) {
        let _timer = metrics
            .step_duration
            .with_label_values(&[LABEL_COPY_CHUNKS])
            .start_timer();

        info!(
            log,
            "state sync: copy_chunks for {} chunks {} validation",
            diff_script.copy_chunks.len(),
            if validate_data || ALWAYS_VALIDATE {
                "with"
            } else {
                "without"
            }
        );

        type DstIndex = usize;
        type SrcIndex = usize;
        type ChunkGroup = Vec<(DstIndex, SrcIndex)>;
        // Group chunks by the file index to lower cost of opening files.
        // Key is the pair of dst file index and src file index,
        // value is vector of pairs of the dst chunk index and src chunk index.
        let mut chunk_groups: HashMap<(DstIndex, SrcIndex), ChunkGroup> = HashMap::default();

        for (dst_chunk_index, src_chunk_index) in &diff_script.copy_chunks {
            let dst_file_index = manifest_new.chunk_table[*dst_chunk_index].file_index;
            let src_file_index = manifest_old.chunk_table[*src_chunk_index].file_index;
            let entry = chunk_groups
                .entry((dst_file_index as usize, src_file_index as usize))
                .or_default();
            entry.push((*dst_chunk_index, *src_chunk_index));
        }

        let corrupted_chunks = Arc::new(Mutex::new(Vec::new()));

        thread_pool.scoped(|scope| {
            for ((dst_file_index, src_file_index), chunk_group) in chunk_groups.iter() {
                let dst_path =
                    root_new.join(&manifest_new.file_table[*dst_file_index].relative_path);
                let src_path =
                    root_old.join(&manifest_old.file_table[*src_file_index].relative_path);
                let corrupted_chunks = Arc::clone(&corrupted_chunks);
                scope.execute(move || {
                    let src = std::fs::File::open(&src_path).unwrap_or_else(|err| {
                        fatal!(
                            log,
                            "Failed to open file {} for read: {}",
                            src_path.display(),
                            err
                        )
                    });

                    let src_len = src
                        .metadata()
                        .unwrap_or_else(|err| {
                            fatal!(
                                log,
                                "Failed to get metadata of file {}: {}",
                                src_path.display(),
                                err
                            )
                        })
                        .len() as usize;
                    let dst = std::fs::OpenOptions::new()
                        .write(true)
                        .create(false)
                        .open(&dst_path)
                        .unwrap_or_else(|err| {
                            fatal!(log, "Failed to open file {}: {}", dst_path.display(), err)
                        });

                    let src_map = ScopedMmap::from_readonly_file(&src, src_len).unwrap_or_else(|err| {
                        fatal!(log, "Failed to mmap file {}: {}", src_path.display(), err)
                    });

                    // Validate each chunk that we happen to have locally.  If the
                    // validation passes, copy it to the corresponding location, otherwise
                    // add the destination chunk id to the set of chunks to fetch.
                    for (dst_chunk_index, src_chunk_index) in chunk_group {
                        let dst_chunk = &manifest_new.chunk_table[*dst_chunk_index];
                        let src_chunk = &manifest_old.chunk_table[*src_chunk_index];
                        let byte_range = src_chunk.byte_range();

                        if src_map.len() < byte_range.end {
                            warn!(
                                log,
                                "Local chunk {} ({}@{}—{}) is out of range (file len = {}), \
                                 will request chunk {} instead",
                                *src_chunk_index,
                                src_path.display(),
                                byte_range.start,
                                byte_range.end,
                                src_map.len(),
                                *dst_chunk_index + FILE_CHUNK_ID_OFFSET
                            );
                            corrupted_chunks.lock().unwrap().push(*dst_chunk_index + FILE_CHUNK_ID_OFFSET);
                            continue;
                        }
                        #[cfg(not(target_os = "linux"))]
                        let src_data = &src_map.as_slice()[byte_range];
                        if validate_data || ALWAYS_VALIDATE {
                            #[cfg(target_os = "linux")]
                            let src_data = &src_map.as_slice()[byte_range];

                            if let Err(err) = crate::manifest::validate_chunk(
                                *dst_chunk_index,
                                src_data,
                                manifest_new,
                            ) {
                                let byte_range = src_chunk.byte_range();
                                warn!(
                                    log,
                                    "Local chunk {} ({}@{}–{}) doesn't pass validation: {}, \
                                     will request chunk {} instead",
                                    *src_chunk_index,
                                    src_path.display(),
                                    byte_range.start,
                                    byte_range.end,
                                    err,
                                    *dst_chunk_index + FILE_CHUNK_ID_OFFSET
                                );

                                corrupted_chunks.lock().unwrap().push(*dst_chunk_index + FILE_CHUNK_ID_OFFSET);
                                if !validate_data && ALWAYS_VALIDATE {
                                    error!(
                                        log,
                                        "{}: Unexpected chunk validation error for local chunk {}.",
                                        CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS,
                                        *src_chunk_index,
                                    );
                                    metrics.corrupted_chunks_critical.inc();
                                }
                                metrics
                                    .corrupted_chunks
                                    .with_label_values(&[LABEL_COPY_CHUNKS])
                                    .inc();
                                continue;
                            }
                        }
                        #[cfg(target_os = "linux")]
                        {
                            let src_offset = src_chunk.offset as i64;
                            let dst_offset = dst_chunk.offset as i64;

                            ic_sys::fs::copy_file_range_all(
                                &src,
                                src_offset,
                                &dst,
                                dst_offset,
                                dst_chunk.size_bytes as usize,
                            )
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to copy file range from {} => {} (offset = {}, size = {}): {}",
                                        src_path.display(),
                                        dst_path.display(),
                                        dst_chunk.offset,
                                        dst_chunk.size_bytes,
                                        err
                                    )
                                });
                        }

                        #[cfg(not(target_os = "linux"))]
                        {
                            dst.write_all_at(src_data, dst_chunk.offset)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to write chunk (offset = {}, size = {}) to file {}: {}",
                                        dst_chunk.offset,
                                        dst_chunk.size_bytes,
                                        dst_path.display(),
                                        err
                                    )
                                });
                        }
                        metrics.remaining.sub(1);
                    }
                });
            }
        });

        for chunk_idx in corrupted_chunks.lock().unwrap().iter() {
            fetch_chunks.insert(*chunk_idx);
        }
    }

    pub(crate) fn apply_chunk(
        log: &ReplicaLogger,
        metrics: &StateSyncMetrics,
        root: &Path,
        ix: usize,
        bytes: &[u8],
        manifest: &Manifest,
    ) {
        let chunk = &manifest.chunk_table[ix];
        let file_index = chunk.file_index as usize;
        let path = root.join(&manifest.file_table[file_index].relative_path);

        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .open(&path)
            .unwrap_or_else(|err| fatal!(log, "Failed to open file {}: {}", path.display(), err));
        f.write_all_at(bytes, chunk.offset).unwrap_or_else(|err| {
            fatal!(
                log,
                "Failed to write chunk (offset = {}, size = {}) to file {}: {}",
                chunk.offset,
                chunk.size_bytes,
                path.display(),
                err
            )
        });
        metrics.remaining.sub(1);
    }

    fn make_checkpoint(
        log: &ReplicaLogger,
        metrics: &StateManagerMetrics,
        started_at: Instant,
        root: &Path,
        height: Height,
        state_layout: &StateLayout,
        thread_pool: &mut scoped_threadpool::Pool,
    ) {
        let _timer = metrics
            .state_sync_metrics
            .step_duration
            .with_label_values(&[LABEL_STATE_SYNC_MAKE_CHECKPOINT])
            .start_timer();

        info!(
            log,
            "state sync: start to make a checkpoint from the scratchpad"
        );

        let scratchpad_layout =
            CheckpointLayout::<RwPolicy<()>>::new_untracked(root.to_path_buf(), height)
                .expect("failed to create checkpoint layout");

        scratchpad_layout
            .create_unverified_checkpoint_marker()
            .unwrap_or_else(|err| {
                fatal!(
                    log,
                    "Failed to create a checkpoint marker for state {} at path {}: {}",
                    height,
                    scratchpad_layout.raw_path().display(),
                    err,
                )
            });

        match state_layout.scratchpad_to_checkpoint(scratchpad_layout, height, Some(thread_pool)) {
            Ok(_) => {
                let elapsed = started_at.elapsed();
                metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["ok"])
                    .observe(elapsed.as_secs_f64());

                info!(
                    log,
                    "Successfully completed sync of state {} in {:?}", height, elapsed
                );
            }
            Err(LayoutError::AlreadyExists(_)) => {
                let elapsed = started_at.elapsed();
                metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["already_exists"])
                    .observe(elapsed.as_secs_f64());

                warn!(
                    log,
                    "Couldn't complete sync of state {} because it already exists locally ({:?} elapsed)",
                    height,
                    elapsed,
                );
            }
            Err(LayoutError::IoError {
                path,
                message,
                io_err,
            }) => {
                let elapsed = started_at.elapsed();
                metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["io_err"])
                    .observe(elapsed.as_secs_f64());

                fatal!(
                    log,
                    "Failed to promote synced state to a checkpoint {} after {:?}: {}: {} (at {})",
                    height,
                    elapsed,
                    message,
                    io_err,
                    path.display(),
                )
            }
            Err(err) => fatal!(log, "Unexpected layout error: {}", err),
        }
    }

    /// Preallocates the files listed in the manifest and copies the chunks
    /// that we have locally.
    /// Returns a set of chunks that still need to be fetched
    fn initialize_state_on_disk(&mut self, manifest_new: &Manifest) -> HashSet<usize> {
        Self::preallocate_layout(&self.log, &self.root, manifest_new);

        let state_sync_size_fetch = self
            .metrics
            .state_sync_metrics
            .size
            .with_label_values(&[LABEL_FETCH]);
        let state_sync_size_copy_files = self
            .metrics
            .state_sync_metrics
            .size
            .with_label_values(&[LABEL_COPY_FILES]);
        let state_sync_size_copy_chunks = self
            .metrics
            .state_sync_metrics
            .size
            .with_label_values(&[LABEL_COPY_CHUNKS]);
        let state_sync_size_preallocate = self
            .metrics
            .state_sync_metrics
            .size
            .with_label_values(&[LABEL_PREALLOCATE]);
        let total_bytes: u64 = manifest_new.file_table.iter().map(|f| f.size_bytes).sum();

        self.metrics
            .state_sync_metrics
            .remaining
            .add(manifest_new.chunk_table.len() as i64);

        // Get the cache line. We now own an Arc on that cache line, so we are extending
        // the lifetime of the data on disk as long as we keep this cache line in scope
        let cache = self.state_sync_refs.cache.read().get();

        // A little helper struct of all we need to know to copy out of
        struct DiffData<'a> {
            manifest_old: &'a Manifest,
            missing_chunks: HashSet<usize>,
            root_old: PathBuf,
            height_old: Height,
            validate_data: bool,
        }

        // Get a DiffData from the cache or checkpoint_layout, or neither
        let diff_data: Option<DiffData> = match (
            cache.as_ref(),
            self.manifest_with_checkpoint_layout.as_ref(),
        ) {
            (Some(cache_entry), Some((checkpoint_manifest, checkpoint_layout))) => {
                let cache_height = cache_entry.height;
                let checkpoint_height = checkpoint_layout.height();
                if cache_height > checkpoint_height {
                    // The cache will have missing chunks. However, it likely started from a
                    // DiffScript with the same checkpoint we have now, so there should be more
                    // relevant chunks in the cache than in the checkpoint.
                    // This is just a heuristic however, as the cached chunks might have been
                    // initialized with a DiffScript from an older checkpoint.
                    Some(DiffData {
                        manifest_old: &cache_entry.manifest,
                        missing_chunks: cache_entry.missing_chunks.clone(),
                        // The data at root_old will live at least as long as the
                        // StateSyncCacheEntry, so cloning the path is safe
                        root_old: cache_entry.path().to_path_buf(),
                        height_old: cache_entry.height,
                        validate_data: false,
                    })
                } else {
                    // This should be a special case that can only happen if the source of the
                    // checkpoint is outside of state sync, as otherwise we would have cleared
                    // the cache upon successfully syncing a state.
                    Some(DiffData {
                        manifest_old: checkpoint_manifest,
                        missing_chunks: Default::default(),
                        root_old: checkpoint_layout.raw_path().to_path_buf(),
                        height_old: checkpoint_height,
                        validate_data: true,
                    })
                }
            }
            (Some(cache_entry), None) => Some(DiffData {
                manifest_old: &cache_entry.manifest,
                missing_chunks: cache_entry.missing_chunks.clone(),
                root_old: cache_entry.path().to_path_buf(),
                height_old: cache_entry.height,
                validate_data: false,
            }),
            (None, Some((checkpoint_manifest, checkpoint_old))) => {
                let checkpoint_height = checkpoint_old.height();
                Some(DiffData {
                    manifest_old: checkpoint_manifest,
                    missing_chunks: Default::default(),
                    root_old: checkpoint_old.raw_path().to_path_buf(),
                    height_old: checkpoint_height,
                    validate_data: !self
                        .state_sync_refs
                        .cache
                        .read()
                        .state_is_fetched(checkpoint_height),
                })
            }
            (None, None) => None,
        };

        if let Some(DiffData {
            manifest_old,
            missing_chunks,
            root_old,
            height_old,
            validate_data,
        }) = diff_data
        {
            info!(
                self.log,
                "Initializing state sync for height {} based on {} at height {}",
                self.height,
                if missing_chunks.is_empty() {
                    "checkpoint"
                } else {
                    "cache"
                },
                height_old
            );
            let diff_script =
                crate::manifest::diff_manifest(manifest_old, &missing_chunks, manifest_new);
            debug!(
                self.log,
                "State sync diff script (@{} -> @{}): {:?}", height_old, self.height, diff_script
            );

            // diff_script contains indices into the manifest chunk table, but p2p
            // counts the manifest itself as chunk 0, so all other chunk indices are
            // shifted by 1
            let mut fetch_chunks = diff_script
                .fetch_chunks
                .iter()
                .map(|i| *i + FILE_CHUNK_ID_OFFSET)
                .collect();

            let diff_bytes: u64 = diff_script
                .fetch_chunks
                .iter()
                .map(|i| manifest_new.chunk_table[*i].size_bytes as u64)
                .sum();

            let preallocate_bytes: u64 =
                (diff_script.zeros_chunks * crate::state_sync::types::DEFAULT_CHUNK_SIZE) as u64;

            let copy_files_bytes: u64 = diff_script
                .copy_files
                .keys()
                .map(|i| manifest_new.file_table[*i].size_bytes)
                .sum();

            let copy_chunks_bytes: u64 =
                total_bytes - diff_bytes - preallocate_bytes - copy_files_bytes;

            state_sync_size_fetch.inc_by(diff_bytes);
            state_sync_size_preallocate.inc_by(preallocate_bytes);
            state_sync_size_copy_files.inc_by(copy_files_bytes);
            state_sync_size_copy_chunks.inc_by(copy_chunks_bytes);

            self.metrics
                .state_sync_metrics
                .remaining
                .sub(diff_script.zeros_chunks as i64);

            let mut thread_pool = self.thread_pool.lock().unwrap();
            Self::copy_files(
                &self.log,
                &self.metrics.state_sync_metrics,
                &mut thread_pool,
                &root_old,
                &self.root,
                manifest_old,
                manifest_new,
                &diff_script,
                validate_data,
                &mut fetch_chunks,
            );

            Self::copy_chunks(
                &self.log,
                &self.metrics.state_sync_metrics,
                &mut thread_pool,
                &root_old,
                &self.root,
                manifest_old,
                manifest_new,
                &diff_script,
                validate_data,
                &mut fetch_chunks,
            );

            fetch_chunks
        } else {
            info!(
                self.log,
                "Initializing state sync for height {} without any caches or previous checkpoints",
                self.height
            );
            let non_zero_chunks = filter_out_zero_chunks(manifest_new);
            let diff_bytes: u64 = non_zero_chunks
                .iter()
                .map(|i| manifest_new.chunk_table[*i].size_bytes as u64)
                .sum();
            state_sync_size_fetch.inc_by(diff_bytes);
            state_sync_size_preallocate.inc_by(total_bytes - diff_bytes);

            let zeros_chunks = manifest_new.chunk_table.len() - non_zero_chunks.len();

            self.metrics
                .state_sync_metrics
                .remaining
                .sub(zeros_chunks as i64);

            non_zero_chunks
                .iter()
                .map(|i| *i + FILE_CHUNK_ID_OFFSET)
                .collect()
        }
    }
}

#[cfg(feature = "malicious_code")]
fn maliciously_alter_chunk_data(
    mut chunk: Chunk,
    chunk_id: ChunkId,
    malicious_flags: &mut MaliciousFlags,
) -> Chunk {
    let allowance = match malicious_flags
        .maliciously_alter_state_sync_chunk_receiving_side
        .as_mut()
    {
        Some(allowance) => allowance,
        None => {
            return chunk;
        }
    };

    let ix = chunk_id.get();
    match state_sync_chunk_type(ix) {
        StateSyncChunk::MetaManifestChunk => {
            if allowance.meta_manifest_chunk_error_allowance == 0 {
                return chunk;
            }
            allowance.meta_manifest_chunk_error_allowance -= 1;
            let meta_manifest = match decode_meta_manifest(chunk.as_bytes().to_vec().into()) {
                Ok(meta_manifest) => meta_manifest,
                Err(_) => {
                    return chunk;
                }
            };
            chunk = crate::state_sync::types::maliciously_alter_meta_manifest(meta_manifest).into();
        }
        StateSyncChunk::ManifestChunk(_) => {
            if allowance.manifest_chunk_error_allowance == 0 {
                return chunk;
            }
            allowance.manifest_chunk_error_allowance -= 1;
            chunk = crate::state_sync::types::maliciously_alter_chunk_payload(
                chunk.as_bytes().to_vec(),
            )
            .into();
        }
        _ => {
            if allowance.state_chunk_error_allowance == 0 {
                return chunk;
            }
            allowance.state_chunk_error_allowance -= 1;
            chunk = crate::state_sync::types::maliciously_alter_chunk_payload(
                chunk.as_bytes().to_vec(),
            )
            .into();
        }
    }
    // Sleep for 15 seconds to allow the replica connecting to more peers for state sync.
    // Otherwise, the first invalid chunk in the very beginning will immediately fail the state sync
    // if there is only one peer connected.
    // Note that this is only an issue for tests not the real system.
    std::thread::sleep(std::time::Duration::from_secs(15));
    chunk
}

impl Chunkable<StateSyncMessage> for IncompleteState {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        match self.state {
            DownloadState::Blank => Box::new(std::iter::once(META_MANIFEST_CHUNK)),
            DownloadState::Prep {
                meta_manifest: _,
                manifest_in_construction: _,
                ref manifest_chunks,
            } => {
                #[allow(clippy::needless_collect)]
                let ids: Vec<_> = manifest_chunks.iter().map(|id| ChunkId::new(*id)).collect();
                Box::new(ids.into_iter())
            }
            DownloadState::Loading {
                meta_manifest: _,
                manifest: _,
                state_sync_file_group: _,
                ref fetch_chunks,
            } => {
                #[allow(clippy::needless_collect)]
                let ids: Vec<_> = fetch_chunks
                    .iter()
                    .map(|id| ChunkId::new(*id as u32))
                    .collect();
                Box::new(ids.into_iter())
            }
            DownloadState::Complete => Box::new(std::iter::empty()),
        }
    }

    fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError> {
        #[cfg(feature = "malicious_code")]
        let chunk = maliciously_alter_chunk_data(chunk, chunk_id, &mut self.malicious_flags);
        let ix = chunk_id.get();
        match &mut self.state {
            DownloadState::Complete => {
                debug!(
                    self.log,
                    "Received chunk {} on completed state {}", chunk_id, self.height
                );

                Ok(())
            }
            DownloadState::Blank => {
                if chunk_id == META_MANIFEST_CHUNK {
                    let meta_manifest = decode_meta_manifest(chunk).map_err(|err| {
                        warn!(
                            self.log,
                            "Failed to decode meta-manifest chunk for state {}: {}",
                            self.height,
                            err
                        );
                        AddChunkError::Invalid
                    })?;

                    crate::manifest::validate_meta_manifest(&meta_manifest, &self.root_hash)
                        .map_err(|err| {
                            warn!(self.log, "Received invalid meta-manifest: {}", err);
                            self.metrics
                                .state_sync_metrics
                                .corrupted_chunks
                                .with_label_values(&[LABEL_FETCH_META_MANIFEST_CHUNK])
                                .inc();
                            AddChunkError::Invalid
                        })?;
                    let manifest_chunks_len = meta_manifest.sub_manifest_hashes.len();
                    debug!(
                        self.log,
                        "Received META_MANIFEST chunk for state {}, got {} more chunks to download for the manifest",
                        self.height,
                        manifest_chunks_len
                    );
                    trace!(self.log, "Received meta-manifest:\n{:?}", meta_manifest);

                    assert!(
                        MANIFEST_CHUNK_ID_OFFSET
                            .checked_add(manifest_chunks_len as u32)
                            .is_some(),
                        "Not enough chunk id space for manifest chunks!"
                    );
                    let manifest_chunks = (MANIFEST_CHUNK_ID_OFFSET
                        ..MANIFEST_CHUNK_ID_OFFSET + manifest_chunks_len as u32)
                        .collect();

                    self.state = DownloadState::Prep {
                        meta_manifest,
                        manifest_in_construction: Default::default(),
                        manifest_chunks,
                    };

                    Ok(())
                } else {
                    warn!(
                        self.log,
                        "Received non-meta-manifest chunk {} on blank state {}", ix, self.height
                    );
                    Err(AddChunkError::Invalid)
                }
            }
            DownloadState::Prep {
                ref meta_manifest,
                ref mut manifest_in_construction,
                ref mut manifest_chunks,
            } => {
                let manifest_chunk_index = match state_sync_chunk_type(ix) {
                    StateSyncChunk::MetaManifestChunk => {
                        // Have already seen the meta-manifest chunk
                        return Ok(());
                    }
                    StateSyncChunk::ManifestChunk(index) => index as usize,
                    _ => {
                        // Have not requested such chunks
                        return Err(AddChunkError::Invalid);
                    }
                };
                debug_assert!(ix >= MANIFEST_CHUNK_ID_OFFSET);

                if !manifest_chunks.contains(&ix) {
                    return Ok(());
                }

                crate::manifest::validate_sub_manifest(
                    manifest_chunk_index,
                    chunk.as_bytes(),
                    meta_manifest,
                )
                .map_err(|err| {
                    warn!(self.log, "Received invalid sub-manifest: {}", err);
                    self.metrics
                        .state_sync_metrics
                        .corrupted_chunks
                        .with_label_values(&[LABEL_FETCH_MANIFEST_CHUNK])
                        .inc();

                    AddChunkError::Invalid
                })?;
                manifest_in_construction.insert(ix, chunk.take());
                manifest_chunks.remove(&ix);

                debug!(
                    self.log,
                    "Received MANIFEST chunk {} for state {}, got {} more chunks to download",
                    manifest_chunk_index,
                    self.height,
                    manifest_chunks.len()
                );

                if manifest_chunks.is_empty() {
                    let length: usize = manifest_in_construction.values().map(|x| x.len()).sum();
                    let mut encoded_manifest = Vec::with_capacity(length);
                    // The sub-manifests are stored in a BTreeMap so the manifest can be assembled by adding each sub-manifest in order.
                    manifest_in_construction
                        .values()
                        .for_each(|sub_manifest| encoded_manifest.extend(sub_manifest));

                    // Since manifest version 2, the authenticity of a manifest comes from the meta-manifest hash which is signed in the CUP.
                    // It implies severe problems if all sub-manifests pass validation but we fail to get a valid manifest from them.
                    // The replica should panic in such situation otherwise the state sync will stall in the Prep phase.
                    let manifest = decode_manifest(&encoded_manifest).map_err(|err| {
                        fatal!(
                            self.log,
                            "Received all sub-manifests but failed to decode manifest chunk for state {}: {}", self.height, err
                        );
                    })?;

                    crate::manifest::validate_manifest(&manifest, &self.root_hash).map_err(
                        |err| {
                            fatal!(self.log, "Received all sub-manifests but the assembled manifest is invalid: {}", err);
                        },
                    )?;

                    debug!(
                        self.log,
                        "Received MANIFEST chunks for state {}, got {} more chunks to download",
                        self.height,
                        manifest.chunk_table.len()
                    );

                    trace!(self.log, "Received manifest:\n{}", manifest);

                    let meta_manifest = meta_manifest.clone();

                    let mut fetch_chunks = self.initialize_state_on_disk(&manifest);

                    if fetch_chunks.is_empty() {
                        debug!(
                            self.log,
                            "No chunks need to be fetched for state {}", self.height
                        );

                        Self::make_checkpoint(
                            &self.log,
                            &self.metrics,
                            self.started_at,
                            &self.root,
                            self.height,
                            &self.state_layout,
                            &mut self.thread_pool.lock().unwrap(),
                        );

                        self.state_sync.deliver_state_sync(
                            self.height,
                            self.root_hash.clone(),
                            manifest.clone(),
                            Arc::new(meta_manifest.clone()),
                        );
                        self.state = DownloadState::Complete;
                        self.state_sync_refs
                            .cache
                            .write()
                            .register_successful_sync(self.height);
                        Ok(())
                    } else {
                        let state_sync_file_group = build_file_group_chunks(&manifest);

                        // The chunks in the chunk table should not collide with the file group chunk IDs.
                        assert!(manifest.chunk_table.len() < FILE_GROUP_CHUNK_ID_OFFSET as usize);

                        // The file group chunk IDs should not collide with the manifest chunk IDs.
                        assert!(
                            FILE_GROUP_CHUNK_ID_OFFSET + state_sync_file_group.len() as u32 - 1
                                < MANIFEST_CHUNK_ID_OFFSET
                        );

                        for (&chunk_id, chunk_table_indices) in state_sync_file_group.iter() {
                            for &chunk_table_index in chunk_table_indices.iter() {
                                fetch_chunks
                                    .remove(&(chunk_table_index as usize + FILE_CHUNK_ID_OFFSET));
                            }
                            // We decide to fetch all the file group chunks unconditionally for two reasons:
                            //     1. `canister.pbuf` files change between checkpoints and are unlikely to be covered in the copy phase.
                            //     2. `canister.pbuf` files are small so there will be only a handful of chunks after grouping.
                            fetch_chunks.insert(chunk_id as usize);
                        }
                        let num_fetch_chunks = fetch_chunks.len();
                        self.state = DownloadState::Loading {
                            meta_manifest,
                            manifest,
                            state_sync_file_group,
                            fetch_chunks,
                        };
                        self.fetch_started_at = Some(Instant::now());
                        info!(
                            self.log,
                            "state sync enters the loading phase with {} chunks to fetch",
                            num_fetch_chunks,
                        );
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            DownloadState::Loading {
                ref meta_manifest,
                ref manifest,
                ref mut fetch_chunks,
                ref state_sync_file_group,
            } => {
                debug!(
                    self.log,
                    "Received chunk {} / {} of state {}",
                    ix,
                    manifest.chunk_table.len(),
                    self.height
                );

                if !fetch_chunks.contains(&(ix as usize)) {
                    return Ok(());
                }

                // Each index in `chunk_table_indices` is mapped to a piece of payload bytes
                // with its corresponding start and end position.
                let (chunk_table_indices, payload_pieces) = match state_sync_chunk_type(ix) {
                    StateSyncChunk::FileChunk(index) => {
                        // If it is a normal chunk, there is only one index mapped to the whole payload.
                        (vec![index], vec![(0, chunk.as_bytes().len())])
                    }
                    StateSyncChunk::FileGroupChunk(index) => {
                        // If it is a file group chunk, divide it into pieces according to the `FileGroupChunks`.
                        let chunk_table_indices = state_sync_file_group
                            .get(&index)
                            .ok_or(AddChunkError::Invalid)?
                            .clone();

                        let mut cur_offset = 0;
                        let mut payload_pieces: Vec<(usize, usize)> = Vec::new();
                        for chunk_table_index in &chunk_table_indices {
                            let chunk_size = manifest.chunk_table[*chunk_table_index as usize]
                                .size_bytes as usize;
                            payload_pieces.push((cur_offset, cur_offset + chunk_size));
                            cur_offset += chunk_size;
                        }

                        if cur_offset != chunk.as_bytes().len() {
                            warn!(self.log, "Received invalid file group chunk {}", ix);
                            return Err(AddChunkError::Invalid);
                        }
                        (chunk_table_indices, payload_pieces)
                    }
                    _ => {
                        // meta-manifest/manifest chunks are not expected in the `Loading` phase.
                        return Ok(());
                    }
                };

                let log = &self.log;
                let metrics = &self.metrics;

                // If any of the chunks is invalid, the whole file group chunk is considered as invalid.
                // In this case, none of them will be applied.
                for (chunk_table_index, &(start, end)) in
                    chunk_table_indices.iter().zip(payload_pieces.iter())
                {
                    crate::manifest::validate_chunk(
                        *chunk_table_index as usize,
                        &chunk.as_bytes()[start..end],
                        manifest,
                    )
                    .map_err(|err| {
                        warn!(log, "Received invalid chunk: {}", err);
                        metrics
                            .state_sync_metrics
                            .corrupted_chunks
                            .with_label_values(&[LABEL_FETCH_STATE_CHUNK])
                            .inc();
                        AddChunkError::Invalid
                    })?;
                }

                for (chunk_table_index, &(start, end)) in
                    chunk_table_indices.iter().zip(payload_pieces.iter())
                {
                    Self::apply_chunk(
                        &self.log,
                        &self.metrics.state_sync_metrics,
                        &self.root,
                        *chunk_table_index as usize,
                        &chunk.as_bytes()[start..end],
                        manifest,
                    );
                }

                fetch_chunks.remove(&(ix as usize));

                if fetch_chunks.is_empty() {
                    debug!(
                        self.log,
                        "Received all {} chunks of state {}",
                        manifest.chunk_table.len(),
                        self.height
                    );

                    if let Some(fetch_start_at) = self.fetch_started_at {
                        let elapsed = fetch_start_at.elapsed();
                        self.metrics
                            .state_sync_metrics
                            .step_duration
                            .with_label_values(&[LABEL_FETCH])
                            .observe(elapsed.as_secs_f64());
                    } else {
                        warn!(
                            self.log,
                            "The starting time of the loading phase was not properly set."
                        )
                    }

                    Self::make_checkpoint(
                        &self.log,
                        &self.metrics,
                        self.started_at,
                        &self.root,
                        self.height,
                        &self.state_layout,
                        &mut self.thread_pool.lock().unwrap(),
                    );

                    self.state_sync.deliver_state_sync(
                        self.height,
                        self.root_hash.clone(),
                        manifest.clone(),
                        Arc::new(meta_manifest.clone()),
                    );
                    self.state = DownloadState::Complete;
                    self.state_sync_refs
                        .cache
                        .write()
                        .register_successful_sync(self.height);

                    // Delay delivery of artifact
                    #[cfg(feature = "malicious_code")]
                    if let Some(delay) = self.malicious_flags.delay_state_sync(self.started_at) {
                        info!(self.log, "[MALICIOUS]: Delayed state sync by {:?}", delay);
                    }
                }

                Ok(())
            }
        }
    }
}
