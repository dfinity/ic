use crate::{
    manifest::{filter_out_zero_chunks, DiffScript},
    CheckpointRef, StateManagerMetrics, StateSyncMetrics, StateSyncRefs,
    CRITICAL_ERROR_STATE_SYNC_CORRUPTED_CHUNKS, LABEL_COPY_CHUNKS, LABEL_COPY_FILES, LABEL_FETCH,
    LABEL_PREALLOCATE,
};
use ic_logger::{debug, error, fatal, info, trace, warn, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_state_layout::utils::do_copy_overwrite;
use ic_state_layout::{error::LayoutError, CheckpointLayout, ReadOnly, RwPolicy, StateLayout};
use ic_sys::mmap::ScopedMmap;
use ic_types::{
    artifact::{Artifact, StateSyncMessage},
    chunkable::{
        ArtifactChunk, ArtifactChunkData,
        ArtifactErrorCode::{self, ChunkVerificationFailed, ChunksMoreNeeded},
        ChunkId, Chunkable,
    },
    crypto::CryptoHash,
    state_sync::{decode_manifest, Manifest, MANIFEST_CHUNK},
    CryptoHashOfState, Height,
};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

pub mod cache;

// If set to true, we validate chunks even in situations where it might not be
// necessary.
const ALWAYS_VALIDATE: bool = false;

/// The state of the communication with up-to-date nodes.
#[derive(Clone)]
enum DownloadState {
    /// Haven't received any chunks yet, waiting for the manifest chunk.
    Blank,
    /// In the process of loading chunks, have some more to load.
    Loading {
        /// The received manifest
        manifest: Manifest,
        /// Set of chunks that still need to be fetched. For the purpose of this
        /// set chunk 0 is the manifest. To get indices into the manifests's
        /// chunk table subtract 1.
        fetch_chunks: HashSet<usize>,
    },
    /// Successfully completed and returned the artifact to P2P, nothing else to
    /// do.
    Complete(Box<Artifact>),
}

/// An implementation of Chunkable trait that represents a (on-disk) state under
/// construction.
///
/// P2P decides when to start or abort a fetch based on the output of the state
/// sync priority function.  When priority function returns "Fetch", P2P calls
/// StateManager to construct an IncompleteState corresponding to the state
/// artifact advert.
pub struct IncompleteState {
    log: ReplicaLogger,
    root: PathBuf,
    state_layout: StateLayout,
    height: Height,
    root_hash: CryptoHashOfState,
    state: DownloadState,
    manifest_with_checkpoint_ref: Option<(Manifest, CheckpointRef)>,
    metrics: StateManagerMetrics,
    started_at: Instant,
    own_subnet_type: SubnetType,
    thread_pool: Arc<Mutex<scoped_threadpool::Pool>>,
    state_sync_refs: StateSyncRefs,
}

impl Drop for IncompleteState {
    fn drop(&mut self) {
        if self.state_sync_refs.remove(&self.height).is_none() {
            warn!(
                self.log,
                "State sync refs does not contain incomplete state @{}.", self.height,
            );
        }

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
            DownloadState::Loading {
                manifest: _,
                fetch_chunks: _,
            } => {
                self.metrics
                    .state_sync_metrics
                    .duration
                    .with_label_values(&["aborted"])
                    .observe(elapsed.as_secs_f64());
            }
            DownloadState::Complete(_) => {
                // state sync duration already recorded earlier in make_checkpoint
            }
        }

        if let DownloadState::Loading {
            manifest: _,
            ref fetch_chunks,
        } = self.state
        {
            self.metrics
                .state_sync_metrics
                .remaining
                .sub(fetch_chunks.len() as i64);
        }

        // We need to record the download state before passing self to the cache, as
        // passing it to the cache might alter the download state
        let description = match self.state {
            DownloadState::Blank => "aborted before receiving any chunks",
            DownloadState::Loading { .. } => "aborted before receiving all the chunks",
            DownloadState::Complete(_) => "completed successfully",
        };

        info!(self.log, "State sync @{} {}", self.height, description);

        // Pass self to the cache, taking ownership of chunks on disk
        let cache = Arc::clone(&self.state_sync_refs.cache);
        cache.write().push(self);
    }
}

pub(crate) fn get_state_sync_chunk(
    file_path: PathBuf,
    offset: u64,
    len: u32,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0; len as usize];
    let f = std::fs::File::open(&file_path)?;
    f.read_exact_at(&mut buf[..], offset)?;
    Ok(buf)
}

impl IncompleteState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: ReplicaLogger,
        height: Height,
        root_hash: CryptoHashOfState,
        state_layout: StateLayout,
        manifest_with_checkpoint_ref: Option<(Manifest, CheckpointRef)>,
        metrics: StateManagerMetrics,
        own_subnet_type: SubnetType,
        thread_pool: Arc<Mutex<scoped_threadpool::Pool>>,
        state_sync_refs: StateSyncRefs,
    ) -> Self {
        if state_sync_refs.insert(height, root_hash.clone()).is_some() {
            // Currently, we don't handle two concurrent fetches of the same state
            // correctly. This case indicates a non-deterministic bug either in StateManager
            // or P2P. We'd rather detect this early and crash, the replica
            // should be able to recover after a restart.
            fatal!(log, "There is already a live state sync @{}.", height);
        }

        Self {
            log,
            root: state_layout
                .state_sync_scratchpad(height)
                .expect("failed to create directory for state sync scratchpad"),
            state_layout,
            height,
            root_hash,
            state: DownloadState::Blank,
            manifest_with_checkpoint_ref,
            metrics,
            started_at: Instant::now(),
            own_subnet_type,
            thread_pool,
            state_sync_refs,
        }
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
                                    new_chunk_idx + 1
                                );
                                bad_chunks.push(idx);
                                corrupted_chunks.lock().unwrap().push(new_chunk_idx + 1);
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
                                    new_chunk_idx + 1
                                );

                                bad_chunks.push(idx);
                                corrupted_chunks.lock().unwrap().push(new_chunk_idx + 1);
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

                                    ic_utils::fs::copy_file_range_all(
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
                .or_insert_with(Vec::new);
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
                                *dst_chunk_index + 1
                            );
                            corrupted_chunks.lock().unwrap().push(*dst_chunk_index + 1);
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
                                    *dst_chunk_index + 1
                                );

                                corrupted_chunks.lock().unwrap().push(*dst_chunk_index + 1);
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

                            ic_utils::fs::copy_file_range_all(
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

    fn build_artifact(
        state_layout: &StateLayout,
        height: Height,
        root_hash: CryptoHashOfState,
        manifest: &Manifest,
    ) -> Artifact {
        Artifact::StateSync(StateSyncMessage {
            height,
            root_hash,
            checkpoint_root: state_layout
                .checkpoint(height)
                .unwrap()
                .raw_path()
                .to_path_buf(),
            manifest: manifest.clone(),
            get_state_sync_chunk: Some(get_state_sync_chunk),
        })
    }

    fn make_checkpoint(
        log: &ReplicaLogger,
        metrics: &StateManagerMetrics,
        started_at: Instant,
        root: &Path,
        height: Height,
        state_layout: &StateLayout,
        own_subnet_type: SubnetType,
    ) {
        let ro_layout = CheckpointLayout::<ReadOnly>::new(root.to_path_buf(), height)
            .expect("failed to create checkpoint layout");

        // Recover the state to make sure it's usable
        if let Err(err) = crate::checkpoint::load_checkpoint_parallel(
            &ro_layout,
            own_subnet_type,
            &metrics.checkpoint_metrics,
        ) {
            let elapsed = started_at.elapsed();
            metrics
                .state_sync_metrics
                .duration
                .with_label_values(&["unrecoverable"])
                .observe(elapsed.as_secs_f64());

            fatal!(
                log,
                "Failed to recover synced state {} after {:?}: {}",
                height,
                elapsed,
                err
            )
        }

        let scratchpad_layout = CheckpointLayout::<RwPolicy>::new(root.to_path_buf(), height)
            .expect("failed to create checkpoint layout");

        let elapsed = started_at.elapsed();
        match state_layout.scratchpad_to_checkpoint(scratchpad_layout, height) {
            Ok(_) => {
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

        // Get a DiffData from the cache or checkpoint_ref, or neither
        let diff_data: Option<DiffData> =
            match (cache.as_ref(), self.manifest_with_checkpoint_ref.as_ref()) {
                (Some(cache_entry), Some((checkpoint_manifest, checkpoint_ref))) => {
                    let cache_height = cache_entry.height;
                    let checkpoint_height = checkpoint_ref.0.height;
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
                        let checkpoint_old = checkpoint_ref
                            .0
                            .state_layout
                            .checkpoint(checkpoint_height)
                            .unwrap_or_else(|err| {
                                fatal!(
                                    &self.log,
                                    "Failed to get checkpoint path for height {}: {}",
                                    checkpoint_height,
                                    err
                                );
                            });
                        Some(DiffData {
                            manifest_old: checkpoint_manifest,
                            missing_chunks: Default::default(),
                            root_old: checkpoint_old.raw_path().to_path_buf(),
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
                (None, Some((checkpoint_manifest, checkpoint_ref))) => {
                    let checkpoint_height = checkpoint_ref.0.height;
                    let checkpoint_old = checkpoint_ref
                        .0
                        .state_layout
                        .checkpoint(checkpoint_height)
                        .unwrap_or_else(|err| {
                            fatal!(
                                &self.log,
                                "Failed to get checkpoint path for height {}: {}",
                                checkpoint_height,
                                err
                            );
                        });
                    Some(DiffData {
                        manifest_old: checkpoint_manifest,
                        missing_chunks: Default::default(),
                        // The data in root_old will live at least as long as self.checkpoint_ref,
                        // so cloning here is safe
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
            let mut fetch_chunks = diff_script.fetch_chunks.iter().map(|i| *i + 1).collect();

            let diff_bytes: u64 = diff_script
                .fetch_chunks
                .iter()
                .map(|i| manifest_new.chunk_table[*i].size_bytes as u64)
                .sum();

            let preallocate_bytes: u64 =
                (diff_script.zeros_chunks * crate::manifest::DEFAULT_CHUNK_SIZE) as u64;

            let copy_files_bytes: u64 = diff_script
                .copy_files
                .iter()
                .map(|(i, _)| manifest_new.file_table[*i].size_bytes as u64)
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

            non_zero_chunks.iter().map(|i| *i + 1).collect()
        }
    }
}

impl Chunkable for IncompleteState {
    fn get_artifact_hash(&self) -> CryptoHash {
        self.root_hash.get_ref().clone()
    }

    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        match self.state {
            DownloadState::Blank => Box::new(std::iter::once(MANIFEST_CHUNK)),
            DownloadState::Complete(_) => Box::new(std::iter::empty()),
            DownloadState::Loading {
                manifest: _,
                ref fetch_chunks,
            } => {
                #[allow(clippy::needless_collect)]
                let ids: Vec<_> = fetch_chunks
                    .iter()
                    .map(|id| ChunkId::new(*id as u32))
                    .collect();
                Box::new(ids.into_iter())
            }
        }
    }

    fn get_artifact_identifier(&self) -> CryptoHash {
        self.get_artifact_hash()
    }

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        let ix = artifact_chunk.chunk_id.get() as usize;

        let payload = match artifact_chunk.artifact_chunk_data {
            ArtifactChunkData::SemiStructuredChunkData(ref payload) => payload,
            other => {
                warn!(self.log, "State sync chunk has wrong shape {:?}", other);
                return Err(ChunkVerificationFailed);
            }
        };

        match &mut self.state {
            DownloadState::Complete(ref artifact) => {
                debug!(
                    self.log,
                    "Received chunk {} on completed state {}", artifact_chunk.chunk_id, self.height
                );

                Ok(*artifact.clone())
            }

            DownloadState::Blank => {
                if artifact_chunk.chunk_id == MANIFEST_CHUNK {
                    let manifest = decode_manifest(payload).map_err(|err| {
                        warn!(
                            self.log,
                            "Failed to decode manifest chunk for state {}: {}", self.height, err
                        );
                        ChunkVerificationFailed
                    })?;

                    crate::manifest::validate_manifest(&manifest, &self.root_hash).map_err(
                        |err| {
                            warn!(self.log, "Received invalid manifest: {}", err);
                            ChunkVerificationFailed
                        },
                    )?;

                    debug!(
                        self.log,
                        "Received MANIFEST chunk for state {}, got {} more chunks to download",
                        self.height,
                        manifest.chunk_table.len()
                    );

                    trace!(self.log, "Received manifest:\n{}", manifest);

                    let fetch_chunks = self.initialize_state_on_disk(&manifest);

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
                            self.own_subnet_type,
                        );

                        let artifact = Self::build_artifact(
                            &self.state_layout,
                            self.height,
                            self.root_hash.clone(),
                            &manifest,
                        );

                        self.state = DownloadState::Complete(Box::new(artifact.clone()));
                        self.state_sync_refs
                            .cache
                            .write()
                            .register_successful_sync(self.height);
                        Ok(artifact)
                    } else {
                        self.state = DownloadState::Loading {
                            manifest,
                            fetch_chunks,
                        };
                        Err(ChunksMoreNeeded)
                    }
                } else {
                    warn!(
                        self.log,
                        "Received non-manifest chunk {} on blank state {}", ix, self.height
                    );
                    Err(ChunkVerificationFailed)
                }
            }
            DownloadState::Loading {
                ref manifest,
                ref mut fetch_chunks,
            } => {
                if artifact_chunk.chunk_id == MANIFEST_CHUNK {
                    // Have already seen the manifest chunk
                    return Err(ChunksMoreNeeded);
                }

                debug!(
                    self.log,
                    "Received chunk {} / {} of state {}",
                    ix,
                    manifest.chunk_table.len(),
                    self.height
                );

                if !fetch_chunks.contains(&(ix)) {
                    return Err(ChunksMoreNeeded);
                }

                let chunk_table_index = ix - 1;

                let log = &self.log;
                let metrics = &self.metrics;
                crate::manifest::validate_chunk(chunk_table_index, payload, manifest).map_err(
                    |err| {
                        warn!(log, "Received invalid chunk: {}", err);
                        metrics
                            .state_sync_metrics
                            .corrupted_chunks
                            .with_label_values(&[LABEL_FETCH])
                            .inc();
                        ChunkVerificationFailed
                    },
                )?;

                Self::apply_chunk(
                    &self.log,
                    &self.metrics.state_sync_metrics,
                    &self.root,
                    chunk_table_index,
                    payload,
                    manifest,
                );

                fetch_chunks.remove(&ix);

                if fetch_chunks.is_empty() {
                    debug!(
                        self.log,
                        "Received all {} chunks of state {}",
                        manifest.chunk_table.len(),
                        self.height
                    );

                    Self::make_checkpoint(
                        &self.log,
                        &self.metrics,
                        self.started_at,
                        &self.root,
                        self.height,
                        &self.state_layout,
                        self.own_subnet_type,
                    );

                    let artifact = Self::build_artifact(
                        &self.state_layout,
                        self.height,
                        self.root_hash.clone(),
                        manifest,
                    );

                    self.state = DownloadState::Complete(Box::new(artifact.clone()));
                    self.state_sync_refs
                        .cache
                        .write()
                        .register_successful_sync(self.height);
                    return Ok(artifact);
                }

                Err(ChunksMoreNeeded)
            }
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, DownloadState::Complete(_))
    }

    fn get_chunk_size(&self, chunk_id: ChunkId) -> usize {
        let ix = chunk_id.get() as usize;

        if ix == 0 {
            // Guestimate of manifest size
            return crate::manifest::DEFAULT_CHUNK_SIZE as usize;
        }
        match &self.state {
            DownloadState::Blank | DownloadState::Complete(_) => {
                crate::manifest::DEFAULT_CHUNK_SIZE as usize
            }
            DownloadState::Loading { manifest, .. } => {
                if ix > manifest.chunk_table.len() {
                    return 0;
                }
                manifest.chunk_table[ix - 1].size_bytes as usize
            }
        }
    }
}
