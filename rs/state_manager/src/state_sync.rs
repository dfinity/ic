pub(crate) mod chunkable;
pub mod types;

use super::StateManagerImpl;
use crate::{
    EXTRA_CHECKPOINTS_TO_KEEP, LABEL_LOAD_AND_VALIDATE_CHECKPOINT, LABEL_ON_SYNCED_CHECKPOINT,
    NUMBER_OF_CHECKPOINT_THREADS, StateSyncRefs,
    manifest::build_file_group_chunks,
    state_sync::types::{FileGroupChunks, Manifest, MetaManifest, StateSyncMessage},
};
use ic_interfaces::p2p::state_sync::{
    Chunk, ChunkId, Chunkable, StateSyncArtifactId, StateSyncClient,
};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, fatal, info, warn};
use ic_types::{CryptoHashOfState, Height};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct StateSync {
    state_manager: Arc<StateManagerImpl>,
    state_sync_refs: StateSyncRefs,
    log: ReplicaLogger,
    #[cfg(debug_assertions)]
    pub test_force_validate: bool,
}

impl StateSync {
    pub fn new(state_manager: Arc<StateManagerImpl>, log: ReplicaLogger) -> Self {
        Self {
            state_manager,
            state_sync_refs: StateSyncRefs::new(log.clone()),
            log,
            #[cfg(debug_assertions)]
            test_force_validate: false,
        }
    }

    #[cfg(test)]
    fn new_for_testing(
        state_manager: Arc<StateManagerImpl>,
        state_sync_refs: StateSyncRefs,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            state_manager,
            state_sync_refs,
            log,
            #[cfg(debug_assertions)]
            test_force_validate: false,
        }
    }

    #[cfg(debug_assertions)]
    fn is_test_force_validate(&self) -> bool {
        self.test_force_validate
    }

    /// Returns requested state as a Chunkable artifact for StateSync.
    fn create_chunkable_state(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<StateSyncMessage> + Send>> {
        info!(self.log, "Starting state sync @{}", id.height);
        chunkable::IncompleteState::try_new(
            self.log.clone(),
            id.height,
            CryptoHashOfState::from(id.hash.clone()),
            Arc::new(self.clone()),
            Arc::new(Mutex::new(scoped_threadpool::Pool::new(
                NUMBER_OF_CHECKPOINT_THREADS,
            ))),
        )
        .map(|incomplete_state| {
            Box::new(incomplete_state) as Box<dyn Chunkable<StateSyncMessage> + Send>
        })
    }

    /// Loads the synced checkpoint and gets the corresponding replicated state.
    /// Delivers both to the state manager and updates the internals of the state manager.
    fn deliver_state_sync(
        &self,
        height: Height,
        root_hash: CryptoHashOfState,
        manifest: Manifest,
        meta_manifest: Arc<MetaManifest>,
    ) {
        info!(
            self.log,
            "Starting to deliver the synced state at height {}", height
        );
        let state_sync_metrics = &self.state_manager.metrics.state_sync_metrics;

        let timer = state_sync_metrics
            .step_duration
            .with_label_values(&[LABEL_LOAD_AND_VALIDATE_CHECKPOINT])
            .start_timer();
        let ro_layout = self
            .state_manager
            .state_layout
            .checkpoint_in_verification(height)
            .expect("failed to create checkpoint layout");

        let state = match crate::checkpoint::load_checkpoint_and_validate_parallel(
            &ro_layout,
            self.state_manager.own_subnet_type,
            &self.state_manager.metrics.checkpoint_metrics,
            self.state_manager.get_fd_factory(),
        ) {
            Ok(state) => state,
            Err(err) => {
                fatal!(
                    self.log,
                    "Failed to load and finalize checkpoint or remove the unverified marker @height {}: {}",
                    height,
                    err
                );
            }
        };
        drop(timer);

        let _timer = state_sync_metrics
            .step_duration
            .with_label_values(&[LABEL_ON_SYNCED_CHECKPOINT])
            .start_timer();
        self.state_manager.on_synced_checkpoint(
            state,
            ro_layout,
            manifest,
            meta_manifest,
            root_hash,
        );

        let height = self.state_manager.states.read().last_advertised;
        let ids = self.get_all_validated_ids_by_height(height);
        if let Some(ids) = ids.last() {
            self.state_manager.states.write().last_advertised = ids.height;
        }
    }

    pub fn get(&self, msg_id: &StateSyncArtifactId) -> Option<StateSyncMessage> {
        let mut file_group_to_populate: Option<Arc<FileGroupChunks>> = None;

        let state_sync_message = self
            .state_manager
            .states
            .read()
            .states_metadata
            .iter()
            .find_map(|(height, metadata)| {
                if metadata.root_hash().map(|v| v.get_ref()) == Some(&msg_id.hash) {
                    let manifest = metadata.manifest()?;
                    let meta_manifest = metadata.meta_manifest()?;
                    let checkpoint_root = self
                        .state_manager
                        .state_layout
                        .checkpoint_verified(*height)
                        .ok()?;
                    let state_sync_file_group = match &metadata.state_sync_file_group {
                        Some(value) => value.clone(),
                        None => {
                            // Note that this code path will be called at most once because the value is then populated.
                            let computed_file_group_chunks =
                                Arc::new(build_file_group_chunks(manifest));
                            file_group_to_populate = Some(computed_file_group_chunks.clone());
                            computed_file_group_chunks
                        }
                    };

                    Some(StateSyncMessage {
                        height: *height,
                        root_hash: CryptoHashOfState::from(msg_id.hash.clone()),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        meta_manifest,
                        manifest: manifest.clone(),
                        state_sync_file_group,
                        malicious_flags: self.state_manager.malicious_flags.clone(),
                    })
                } else {
                    None
                }
            });

        if let Some(state_sync_file_group) = file_group_to_populate
            && let Some(metadata) = self
                .state_manager
                .states
                .write()
                .states_metadata
                .get_mut(&msg_id.height)
        {
            metadata.state_sync_file_group = Some(state_sync_file_group);
        }
        state_sync_message
    }

    // Enumerates all recent fully certified (i.e. referenced in a CUP) states that
    // is above the filter height.
    fn get_all_validated_ids_by_height(&self, height: Height) -> Vec<StateSyncArtifactId> {
        let heights = match self.state_manager.state_layout.checkpoint_heights() {
            Ok(heights) => heights,
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to fetch checkpoint heights for state sync: {}", err
                );
                return Vec::new();
            }
        };
        let states = self.state_manager.states.read();

        heights
            .into_iter()
            .filter_map(|h| {
                if h > height {
                    let metadata = states.states_metadata.get(&h)?;
                    let manifest = metadata.manifest()?;
                    let meta_manifest = metadata.meta_manifest()?;
                    let checkpoint_root = self
                        .state_manager
                        .state_layout
                        .checkpoint_verified(h)
                        .ok()?;
                    let msg = StateSyncMessage {
                        height: h,
                        root_hash: metadata.root_hash()?.clone(),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        manifest: manifest.clone(),
                        meta_manifest,
                        state_sync_file_group: Default::default(),
                        malicious_flags: self.state_manager.malicious_flags.clone(),
                    };
                    Some(StateSyncArtifactId {
                        height: msg.height,
                        hash: msg.root_hash.clone().get(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn should_download(&self, artifact_id: &StateSyncArtifactId) -> bool {
        if artifact_id.height <= self.state_manager.latest_state_height() {
            return false;
        }

        let Some((max_sync_height, hash, _cup_interval_length)) =
            &self.state_manager.states.read().fetch_state
        else {
            // the state manager is not asked to fetch any state.
            return false;
        };

        if artifact_id.height == *max_sync_height && hash.get_ref() != &artifact_id.hash {
            warn!(
                self.log,
                "Received an advert for state {} with a hash that does not match the hash passed to fetch_state: expected {:?}, got {:?}",
                artifact_id.height,
                *hash,
                artifact_id.hash
            );
        }

        artifact_id.height == *max_sync_height && hash.get_ref() == &artifact_id.hash
    }

    // Perform sanity check for the state sync artifact ID.
    // Emit warnings if the artifact ID to cancel does not exactly match the current status of state sync refs.
    fn sanity_check_for_cancelling_state_sync(&self, artifact_id: &StateSyncArtifactId) {
        match self.state_sync_refs.active.read().as_ref() {
            Some((recorded_height, recorded_hash)) => {
                if &artifact_id.height != recorded_height
                    || recorded_hash.get_ref() != &artifact_id.hash
                {
                    warn!(
                        self.log,
                        "Request to cancel state sync that does not match the state we are fetching: expected height @{} with hash{:?}, got height @{} with hash{:?}",
                        artifact_id.height,
                        artifact_id.hash,
                        recorded_height,
                        recorded_hash,
                    );
                }
            }
            None => {
                warn!(
                    self.log,
                    "Request to cancel state sync for state @{} while there are no active state syncs.",
                    artifact_id.height,
                );
            }
        }
    }
}

impl StateSyncClient for StateSync {
    type Message = StateSyncMessage;

    /// Non-blocking.
    fn available_states(&self) -> Vec<StateSyncArtifactId> {
        // Using height 0 here is sane because for state sync `get_all_validated_ids_by_height`
        // return at most the number of states present on the node. Currently this is usually 1-2.
        let height = Height::from(0);
        self.get_all_validated_ids_by_height(height)
    }

    /// Non-blocking.
    fn maybe_start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<StateSyncMessage> + Send>> {
        if self.state_sync_refs.active.read().is_some() {
            warn!(
                self.log,
                "Should not attempt to start state sync when there is an active state sync",
            );
        }
        if self.should_download(id) {
            return self.create_chunkable_state(id);
        }
        None
    }

    /// Non-Blocking.
    fn cancel_if_running(&self, id: &StateSyncArtifactId) -> bool {
        // Requesting to cancel a state sync is only meaningful if the Id refers to an active state sync started with `maybe_start_state_sync`.
        // This sanity check if the API is properly called but does not affect the decision on whether to cancel the state sync.
        self.sanity_check_for_cancelling_state_sync(id);

        // The state manager already has a newer state, we should cancel the ongoing state sync.
        if id.height <= self.state_manager.latest_state_height() {
            return true;
        }

        let Some((max_sync_height, _hash, cup_interval_length)) =
            &self.state_manager.states.read().fetch_state
        else {
            // `fetch_state` being `None` means the previous state sync has been delivered (if any) and there are no newer states to fetch.
            return true;
        };

        // If the state manager is asked to fetch a newer state, we should cancel the ongoing state sync.
        // To keep the active state sync for longer time, we wait for another
        // `EXTRA_CHECKPOINTS_TO_KEEP` CUPs. Then a CUP beyond that can drop the
        // active state sync.
        //
        // Note: CUP interval length may change, and we can't predict future intervals.
        // The condition below is only a heuristic.
        id.height + cup_interval_length.increment() * (EXTRA_CHECKPOINTS_TO_KEEP as u64)
            < *max_sync_height
    }

    /// Blocking. Makes synchronous file system calls.
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk> {
        let msg = self.get(id)?;
        msg.get_chunk(chunk_id)
    }
}
