use super::*;

#[cfg(test)]
mod tests;

/// Local helper function used to delete unfinished syncs from disk
fn delete_folder(log: &ReplicaLogger, path: &Path) {
    if let Err(err) = std::fs::remove_dir_all(path) {
        warn!(
            log,
            "Failed to remove incomplete state sync state at {}: {}",
            path.display(),
            err
        );
    };
}

/// A cache for unfinished state sync artifacts.
///
/// It contains the most recent incomplete state (i.e., with the largest
/// height). This cache is constructed by StateManagerImpl and is shared with
/// instances of IncompleteState. IncompleteStates push their data into this
/// cache if the artifact manager aborts the corresponding state sync.
pub struct StateSyncCache {
    entry: Option<Arc<StateSyncCacheEntry>>,
    log: ReplicaLogger,
}

/// An entry of `StateSyncCache`.
///
/// Contains metadata about an unfinished state sync.
/// State manager uses this information to speed up future state syncs.
pub struct StateSyncCacheEntry {
    pub manifest: Manifest,
    pub height: Height,
    path: PathBuf,
    pub missing_chunks: HashSet<usize>,
    log: ReplicaLogger,
}

impl StateSyncCacheEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StateSyncCacheEntry {
    /// The struct owns the data at self.path, therefore we need to delete
    /// it if we go out of scope
    fn drop(&mut self) {
        delete_folder(&self.log, &self.path)
    }
}

impl StateSyncCache {
    /// Create an empty cache
    pub fn new(log: ReplicaLogger) -> Self {
        Self { entry: None, log }
    }

    /// Returns a reference to the cached entry if there is one available.
    pub fn get(&self) -> Option<Arc<StateSyncCacheEntry>> {
        self.entry.clone()
    }

    /// Pushes the state sync data to the cache without checking that
    /// the new state is newer that the stored one.
    ///
    /// This function is not public and therefore cannot be called directly.
    fn push_inner(
        &mut self,
        sync: &IncompleteState,
        manifest: Manifest,
        fetch_chunks: HashSet<usize>,
        state_sync_file_group: FileGroupChunks,
        copied_chunks_from_file_group: HashSet<ManifestChunkIndex>,
    ) {
        // fetch_chunks, as stored by IncompleteState considers the meta-manifest as chunk 0
        // For the cache we store indices into the manifest's chunk table as
        // missing_chunks.
        debug_assert!(!fetch_chunks.contains(&0));
        let mut missing_chunks: HashSet<usize> = Default::default();
        for i in fetch_chunks.into_iter() {
            assert_ne!(0, i);
            if i < FILE_GROUP_CHUNK_ID_OFFSET as usize {
                missing_chunks.insert(i - FILE_CHUNK_ID_OFFSET);
            } else {
                // If it's a chunk group, the individual chunks are missing in the manifest,
                // not the group
                let chunks = state_sync_file_group
                    .get(&(i as u32))
                    .expect("Unknown chunk group");
                missing_chunks.extend(
                    chunks
                        .iter()
                        .filter(|i| !copied_chunks_from_file_group.contains(i))
                        .map(|i| *i as usize),
                );
            }
        }

        debug_assert!(
            missing_chunks
                .iter()
                .all(|i| *i + FILE_CHUNK_ID_OFFSET < FILE_GROUP_CHUNK_ID_OFFSET as usize)
        );

        // We rename the folder to decouple the cache from active state syncs a bit.
        // Otherwise we'd have to assume that there won't be an active state sync at
        // the same height as the cache (as the folder name
        // only depends on the height).
        let cache_root = sync
            .state_layout
            .state_sync_cache(sync.height)
            .expect("failed to create directory for state sync cache");
        if let Err(err) = std::fs::rename(&sync.root, &cache_root) {
            warn!(
                self.log,
                "Failed to create state sync cache at {}: {}",
                cache_root.display(),
                err
            );

            // On error, make sure the cache is empty and clean up
            self.entry = None;
            delete_folder(&self.log, &cache_root);
            delete_folder(&self.log, &sync.root);
            return;
        }
        let entry = StateSyncCacheEntry {
            manifest,
            height: sync.height,
            path: cache_root,
            missing_chunks,
            log: self.log.clone(),
        };
        self.entry = Some(Arc::new(entry));
    }

    /// Passes an `IncompleteState` `sync` to the cache, moving out any data
    /// relevant to caching.
    ///
    /// Only replaces the cache if `sync` has started, not finished, and
    /// doesn't have an older height than what is currently in the cache.
    ///
    /// This function takes ownership of any data on disk at `sync.root` and
    /// resets the `state` to `Blank`. This function is intended to
    /// be called in the `drop` function of `sync`, so changing the state is
    /// safe.
    pub fn push(&mut self, sync: &mut IncompleteState) {
        // We start by clearing the old entry
        // This avoids any edge cases where we replace the cache with a new entry at the
        // same height (and path)
        if let Some(ref entry) = self.entry {
            match sync.state {
                // Retain the existing cache entry if the state is Blank or Prep.
                // The cache is only populated after `initialize_state_on_disk()` is called,
                // as it incorporates actual state data from previous checkpoints or syncs at that point.
                DownloadState::Blank | DownloadState::Prep { .. } => {
                    // Keep what we have
                }
                DownloadState::Loading { .. } | DownloadState::Complete => {
                    if sync.height >= entry.height {
                        self.entry = None;
                    }
                }
            };
        }

        match std::mem::replace(&mut sync.state, DownloadState::Blank) {
            DownloadState::Loading {
                meta_manifest: _,
                manifest,
                state_sync_file_group,
                fetch_chunks,
                copied_chunks_from_file_group,
            } => {
                if self.entry.is_some() {
                    // The current cache is newer
                    delete_folder(&self.log, &sync.root);
                } else {
                    self.push_inner(
                        sync,
                        manifest,
                        fetch_chunks,
                        state_sync_file_group,
                        copied_chunks_from_file_group,
                    );
                }
            }
            DownloadState::Complete | DownloadState::Blank | DownloadState::Prep { .. } => {
                // Nothing to cache
                // Sanity check that the folder is gone (if completed, should have been moved to
                // a permanent checkpoint, if blank or prep, should never have been created)
                if sync.root.exists() {
                    warn!(
                        self.log,
                        "Scratchpad exists for inactive state sync at {}. Deleting.",
                        sync.root.display()
                    );
                    delete_folder(&self.log, &sync.root);
                }
            }
        }
    }
}
