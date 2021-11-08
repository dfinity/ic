use crate::{
    manifest::{filter_out_zero_chunks, DiffScript},
    CheckpointRef, StateManagerMetrics, StateSyncRefs,
};
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState};
use ic_logger::{debug, fatal, info, trace, warn, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_state_layout::utils::do_copy_overwrite;
use ic_state_layout::{error::LayoutError, CheckpointLayout, ReadOnly, RwPolicy, StateLayout};
use ic_sys::{mmap::ScopedMmap, PAGE_SIZE};
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
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The state of the communication with up-to-date nodes.
enum DownloadState {
    /// Haven't received any chunks yet, waiting for the manifest chunk.
    Blank,
    /// In the process of loading chunks, have some more to load.
    Loading {
        manifest: Manifest,
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
    state_sync_refs: StateSyncRefs,
}

impl Drop for IncompleteState {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.root) {
            // If the state sync succeeded, the root will be moved to
            // checkpoints, so NotFound is expected here.
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    self.log,
                    "Failed to remove incomplete state sync state at {}: {}",
                    self.root.display(),
                    err
                );
            }
        }
        if self.state_sync_refs.remove(&self.height).is_none() {
            warn!(
                self.log,
                "State sync refs does not contain incomplete state @{}.", self.height,
            );
        }
        let description = match self.state {
            DownloadState::Blank => "aborted before receiving any chunks",
            DownloadState::Loading { .. } => "aborted before receiving all the chunks",
            DownloadState::Complete(_) => "completed successfully",
        };

        info!(self.log, "State sync @{} {}", self.height, description);
    }
}

pub(crate) fn get_state_sync_chunk(
    file_path: PathBuf,
    offset: u64,
    len: u32,
) -> std::io::Result<Vec<u8>> {
    if file_path.ends_with("state_file") {
        let cow_base_dir = file_path.parent().unwrap();
        let cow_mgr = CowMemoryManagerImpl::open_readonly(cow_base_dir.to_path_buf());
        let mapped_state = cow_mgr.get_map();
        mapped_state.make_heap_accessible();
        let base = unsafe { mapped_state.get_heap_base().add(offset as usize) };

        let data = unsafe { std::slice::from_raw_parts(base, len as usize) };
        Ok(data.to_vec())
    } else {
        let mut buf = vec![0; len as usize];
        let f = std::fs::File::open(&file_path)?;
        f.read_exact_at(&mut buf[..], offset)?;
        Ok(buf)
    }
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

            if path.ends_with("state_file") {
                // cow memory files are special, ignore there creation here
                continue;
            }

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
    pub(crate) fn copy_files(
        log: &ReplicaLogger,
        root_old: &Path,
        root_new: &Path,
        manifest_old: &Manifest,
        manifest_new: &Manifest,
        diff_script: &DiffScript,
        fetch_chunks: &mut HashSet<usize>,
    ) {
        for (new_index, old_index) in diff_script.copy_files.iter() {
            let src_path = root_old.join(&manifest_old.file_table[*old_index].relative_path);
            let dst_path = root_new.join(&manifest_new.file_table[*new_index].relative_path);

            if dst_path.ends_with("state_file") {
                // It is guaranteed by the different domain hash separators.
                assert!(src_path.ends_with("state_file"));

                let src_cow_base_dir = src_path.parent().expect("paths must have a parent");
                let dst_cow_base_dir = dst_path.parent().expect("paths must have a parent");

                let src_cow_mgr =
                    CowMemoryManagerImpl::open_readonly(src_cow_base_dir.to_path_buf());
                let src_mapped_state = src_cow_mgr.get_map();
                src_mapped_state.make_heap_accessible();
                let src_heap_base = src_mapped_state.get_heap_base();
                let size_bytes = manifest_old.file_table[*old_index].size_bytes as usize;
                let data: &[u8] = unsafe { std::slice::from_raw_parts(src_heap_base, size_bytes) };
                assert_eq!(data.len() % PAGE_SIZE, 0);

                let dst_cow_mgr =
                    CowMemoryManagerImpl::open_readwrite_statesync(dst_cow_base_dir.to_path_buf());
                let dst_mapped_state = dst_cow_mgr.get_map();

                let nr_pages = data.len() / PAGE_SIZE;
                let pages_to_copy: Vec<u64> = (0..nr_pages).map(|page| page as u64).collect();
                dst_mapped_state.copy_to_heap(0, &data);
                dst_mapped_state.soft_commit(&pages_to_copy);
            } else {
                assert!(!src_path.ends_with("state_file"));

                let src_map = ScopedMmap::from_path(&src_path).unwrap_or_else(|err| {
                    fatal!(log, "Failed to mmap file {}: {}", src_path.display(), err)
                });
                let src_data = src_map.as_slice();

                let old_chunk_range = crate::manifest::file_chunk_range(manifest_old, *old_index);
                let new_chunk_range = crate::manifest::file_chunk_range(manifest_new, *new_index);

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
                        fetch_chunks.insert(new_chunk_idx + 1);
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
                        fetch_chunks.insert(new_chunk_idx + 1);
                    }
                }

                if bad_chunks.is_empty()
                    && src_data.len() == manifest_old.file_table[*old_index].size_bytes as usize
                {
                    // All the hash sums and the file size match, so we can
                    // simply copy the whole file.  That's much faster than
                    // copying one chunk at a time.
                    do_copy_overwrite(log, &src_path, &dst_path).unwrap_or_else(|err| {
                        fatal!(
                            log,
                            "Failed to copy file from {} to {}: {}",
                            src_path.display(),
                            dst_path.display(),
                            err
                        )
                    });
                } else {
                    // Copy the chunks that passed validation to the
                    // destination, the rest will be fetched and applied later.
                    let dst = std::fs::OpenOptions::new()
                        .write(true)
                        .create(false)
                        .open(&dst_path)
                        .unwrap_or_else(|err| {
                            fatal!(log, "Failed to open file {}: {}", dst_path.display(), err)
                        });
                    for idx in old_chunk_range {
                        if bad_chunks.contains(&idx) {
                            continue;
                        }

                        let chunk = &manifest_old.chunk_table[idx];
                        let data = &src_data[chunk.byte_range()];

                        dst.write_at(&data, chunk.offset).unwrap_or_else(|err| {
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
                }
            }
        }
    }

    /// Copy reusable chunks from previous checkpoint according to diff script.
    pub(crate) fn copy_chunks(
        log: &ReplicaLogger,
        root_old: &Path,
        root_new: &Path,
        manifest_old: &Manifest,
        manifest_new: &Manifest,
        diff_script: &DiffScript,
        fetch_chunks: &mut HashSet<usize>,
    ) {
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

        for ((dst_file_index, src_file_index), chunk_group) in chunk_groups.iter() {
            let dst_path = root_new.join(&manifest_new.file_table[*dst_file_index].relative_path);
            let src_path = root_old.join(&manifest_old.file_table[*src_file_index].relative_path);
            if dst_path.ends_with("state_file") {
                let src_cow_base_dir = src_path.parent().expect("paths must have a parent");
                let dst_cow_base_dir = dst_path.parent().expect("paths must have a parent");

                let src_cow_mgr =
                    CowMemoryManagerImpl::open_readonly(src_cow_base_dir.to_path_buf());
                let src_mapped_state = src_cow_mgr.get_map();
                src_mapped_state.make_heap_accessible();
                let src_heap_base = src_mapped_state.get_heap_base();

                let dst_cow_mgr =
                    CowMemoryManagerImpl::open_readwrite_statesync(dst_cow_base_dir.to_path_buf());
                let dst_mapped_state = dst_cow_mgr.get_map();

                for (dst_chunk_index, src_chunk_index) in chunk_group {
                    let dst_chunk = &manifest_new.chunk_table[*dst_chunk_index];
                    let src_chunk = &manifest_old.chunk_table[*src_chunk_index];

                    assert_eq!(src_chunk.size_bytes % PAGE_SIZE as u32, 0);

                    let dst_base_page = dst_chunk.offset / PAGE_SIZE as u64;
                    let nr_pages = src_chunk.size_bytes / PAGE_SIZE as u32;

                    let pages_to_copy: Vec<u64> = (0..nr_pages)
                        .map(|page| page as u64 + dst_base_page)
                        .collect();

                    let bytes = unsafe {
                        let base = src_heap_base.add(src_chunk.offset as usize);
                        std::slice::from_raw_parts(base, src_chunk.size_bytes as usize)
                    };
                    dst_mapped_state.copy_to_heap(dst_chunk.offset, &bytes);

                    dst_mapped_state.soft_commit(&pages_to_copy);
                }
                continue;
            }

            let dst = std::fs::OpenOptions::new()
                .write(true)
                .create(false)
                .open(&dst_path)
                .unwrap_or_else(|err| {
                    fatal!(log, "Failed to open file {}: {}", dst_path.display(), err)
                });

            let src_map = ScopedMmap::from_path(&src_path).unwrap_or_else(|err| {
                fatal!(log, "Failed to mmap file {}: {}", src_path.display(), err)
            });

            // Validate each chunk that we happen to have locally.  If the
            // validation pass, copy it to the corresponding location, otherwise
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
                    fetch_chunks.insert(*dst_chunk_index + 1);
                    continue;
                }

                let src_data = &src_map.as_slice()[byte_range];
                if let Err(err) =
                    crate::manifest::validate_chunk(*dst_chunk_index, &src_data, &manifest_new)
                {
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

                    fetch_chunks.insert(*dst_chunk_index + 1);
                    continue;
                }

                dst.write_at(&src_data, dst_chunk.offset)
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
        }
    }

    pub(crate) fn apply_chunk(
        log: &ReplicaLogger,
        root: &Path,
        ix: usize,
        bytes: &[u8],
        manifest: &Manifest,
    ) {
        let chunk = &manifest.chunk_table[ix];
        let file_index = chunk.file_index as usize;
        let path = root.join(&manifest.file_table[file_index].relative_path);
        if path.ends_with("state_file") {
            let cow_base_dir = path.parent().unwrap();
            let cow_mgr =
                CowMemoryManagerImpl::open_readwrite_statesync(cow_base_dir.to_path_buf());
            let mapped_state = cow_mgr.get_map();

            assert_eq!(chunk.size_bytes % PAGE_SIZE as u32, 0);

            let base_page = chunk.offset / PAGE_SIZE as u64;
            let nr_pages = chunk.size_bytes / PAGE_SIZE as u32;

            let pages_to_copy: Vec<u64> =
                (0..nr_pages).map(|page| page as u64 + base_page).collect();

            for pi in &pages_to_copy {
                let offset = (*pi - base_page) as usize * PAGE_SIZE;
                mapped_state.update_heap_page(*pi, &bytes[offset..]);
            }

            mapped_state.soft_commit(&pages_to_copy.as_slice());
            return;
        }

        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(false)
            .open(&path)
            .unwrap_or_else(|err| fatal!(log, "Failed to open file {}: {}", path.display(), err));
        f.write_at(bytes, chunk.offset).unwrap_or_else(|err| {
            fatal!(
                log,
                "Failed to write chunk (offset = {}, size = {}) to file {}: {}",
                chunk.offset,
                chunk.size_bytes,
                path.display(),
                err
            )
        });
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
        match crate::checkpoint::load_checkpoint(&ro_layout, own_subnet_type) {
            Err(err) => {
                let elapsed = started_at.elapsed();
                metrics
                    .state_sync_duration
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
            Ok(rs) => {
                for (canister, canister_state) in rs.canister_states.iter() {
                    let canister_layout = ro_layout
                        .canister(canister)
                        .expect("unable to get canister layout");
                    if CowMemoryManagerImpl::is_cow(&canister_layout.raw_path()) {
                        if let Some(es) = &canister_state.execution_state {
                            // if we state sycned a state with cow memory, create the corresponding
                            // cow snapshot
                            let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite_statesync(
                                canister_layout.raw_path(),
                            );
                            cow_mem_mgr.create_snapshot(es.last_executed_round.get());
                            // sync the recently created snapshot
                            cow_mem_mgr.checkpoint();
                        }
                    }
                }
            }
        }

        let scratchpad_layout = CheckpointLayout::<RwPolicy>::new(root.to_path_buf(), height)
            .expect("failed to create checkpoint layout");

        let elapsed = started_at.elapsed();
        match state_layout.scratchpad_to_checkpoint(scratchpad_layout, height) {
            Ok(_) => {
                metrics
                    .state_sync_duration
                    .with_label_values(&["ok"])
                    .observe(elapsed.as_secs_f64());

                info!(
                    log,
                    "Successfully completed sync of state {} in {:?}", height, elapsed
                );
            }
            Err(LayoutError::AlreadyExists(_)) => {
                metrics
                    .state_sync_duration
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
                    .state_sync_duration
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

                    Self::preallocate_layout(&self.log, &self.root, &manifest);

                    let state_sync_size_fetch =
                        self.metrics.state_sync_size.with_label_values(&["fetch"]);

                    let state_sync_size_copy =
                        self.metrics.state_sync_size.with_label_values(&["copy"]);

                    let state_sync_size_preallocate = self
                        .metrics
                        .state_sync_size
                        .with_label_values(&["preallocate"]);

                    let total_bytes: u64 = manifest.file_table.iter().map(|f| f.size_bytes).sum();
                    let mut fetch_chunks: HashSet<usize>;

                    if let Some((manifest_old, checkpoint_ref)) =
                        &self.manifest_with_checkpoint_ref.take()
                    {
                        info!(
                            self.log,
                            "Will use local state {} to speed up state sync",
                            checkpoint_ref.0.height
                        );

                        let manifest_new = &manifest;
                        let diff_script =
                            crate::manifest::diff_manifest(manifest_old, manifest_new);

                        debug!(
                            self.log,
                            "State sync diff script (@{} -> @{}): {:?}",
                            checkpoint_ref.0.height,
                            self.height,
                            diff_script
                        );

                        let height_old = checkpoint_ref.0.height;
                        let checkpoint_old = checkpoint_ref
                            .0
                            .state_layout
                            .checkpoint(height_old)
                            .unwrap_or_else(|err| {
                                fatal!(
                                    &self.log,
                                    "Failed to get checkpoint path for height {}: {}",
                                    height_old,
                                    err
                                )
                            });
                        let root_old = checkpoint_old.raw_path();

                        fetch_chunks = diff_script.fetch_chunks.iter().map(|i| *i + 1).collect();

                        Self::copy_files(
                            &self.log,
                            root_old,
                            &self.root,
                            &manifest_old,
                            &manifest_new,
                            &diff_script,
                            &mut fetch_chunks,
                        );

                        Self::copy_chunks(
                            &self.log,
                            root_old,
                            &self.root,
                            &manifest_old,
                            &manifest_new,
                            &diff_script,
                            &mut fetch_chunks,
                        );

                        let diff_bytes: u64 = diff_script
                            .fetch_chunks
                            .iter()
                            .map(|i| manifest_new.chunk_table[*i].size_bytes as u64)
                            .sum();

                        let preallocate_bytes =
                            diff_script.zeros_chunks * crate::manifest::DEFAULT_CHUNK_SIZE;

                        state_sync_size_fetch.inc_by(diff_bytes);
                        state_sync_size_preallocate.inc_by(preallocate_bytes as u64);
                        state_sync_size_copy
                            .inc_by(total_bytes - diff_bytes - preallocate_bytes as u64);
                    } else {
                        let non_zero_chunks = filter_out_zero_chunks(&manifest);
                        let diff_bytes: u64 = non_zero_chunks
                            .iter()
                            .map(|i| manifest.chunk_table[*i].size_bytes as u64)
                            .sum();
                        state_sync_size_fetch.inc_by(diff_bytes);
                        state_sync_size_preallocate.inc_by(total_bytes - diff_bytes);

                        fetch_chunks = non_zero_chunks.iter().map(|i| *i + 1).collect();
                    }

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
                crate::manifest::validate_chunk(chunk_table_index, payload, manifest).map_err(
                    |err| {
                        warn!(log, "Received invalid chunk: {}", err);
                        ChunkVerificationFailed
                    },
                )?;

                Self::apply_chunk(&self.log, &self.root, chunk_table_index, payload, manifest);

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
