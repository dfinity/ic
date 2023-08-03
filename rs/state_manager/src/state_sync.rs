pub(crate) mod chunkable;

use super::StateManagerImpl;
use crate::{
    manifest::build_file_group_chunks, StateSyncRefs, EXTRA_CHECKPOINTS_TO_KEEP,
    NUMBER_OF_CHECKPOINT_THREADS,
};
use ic_base_types::NodeId;
use ic_interfaces::{
    artifact_manager::{ArtifactClient, ArtifactProcessor},
    artifact_pool::UnvalidatedArtifact,
    state_sync_client::StateSyncClient,
    time_source::{SysTimeSource, TimeSource},
};
use ic_interfaces_state_manager::{StateManager, CERT_CERTIFIED};
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{
    artifact::{
        Advert, ArtifactKind, ArtifactTag, Priority, StateSyncArtifactId, StateSyncFilter,
        StateSyncMessage,
    },
    chunkable::{ArtifactChunk, ChunkId, Chunkable, ChunkableArtifact},
    crypto::crypto_hash,
    state_sync::FileGroupChunks,
    time::UNIX_EPOCH,
    Height,
};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct StateSync {
    state_manager: Arc<StateManagerImpl>,
    state_sync_refs: StateSyncRefs,
    log: ReplicaLogger,
}

impl StateSync {
    pub fn new(state_manager: Arc<StateManagerImpl>, log: ReplicaLogger) -> Self {
        Self {
            state_manager,
            state_sync_refs: StateSyncRefs::new(log.clone()),
            log,
        }
    }
    /// Returns requested state as a Chunkable artifact for StateSync.
    pub fn create_chunkable_state(
        &self,
        id: &StateSyncArtifactId,
    ) -> Box<dyn Chunkable + Send + Sync> {
        info!(self.log, "Starting state sync @{}", id.height);

        Box::new(crate::state_sync::chunkable::IncompleteState::new(
            self.log.clone(),
            id.height,
            id.hash.clone(),
            self.state_manager.state_layout.clone(),
            self.state_manager.latest_manifest(),
            self.state_manager.metrics.clone(),
            self.state_manager.own_subnet_type,
            Arc::new(Mutex::new(scoped_threadpool::Pool::new(
                NUMBER_OF_CHECKPOINT_THREADS,
            ))),
            self.state_sync_refs.clone(),
            self.state_manager.get_fd_factory(),
            self.state_manager.malicious_flags.clone(),
        ))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StateSyncArtifact;

impl ArtifactKind for StateSyncArtifact {
    const TAG: ArtifactTag = ArtifactTag::StateSyncArtifact;
    type Id = StateSyncArtifactId;
    type Message = StateSyncMessage;
    type Attribute = ();
    type Filter = StateSyncFilter;

    fn message_to_advert(msg: &StateSyncMessage) -> Advert<StateSyncArtifact> {
        let size: u64 = msg
            .manifest
            .file_table
            .iter()
            .map(|file_info| file_info.size_bytes)
            .sum();
        Advert {
            id: StateSyncArtifactId {
                height: msg.height,
                hash: msg.root_hash.clone(),
            },
            attribute: (),
            size: size as usize,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

impl ArtifactClient<StateSyncArtifact> for StateSync {
    fn get_validated_by_identifier(
        &self,
        msg_id: &StateSyncArtifactId,
    ) -> Option<StateSyncMessage> {
        let mut file_group_to_populate: Option<Arc<FileGroupChunks>> = None;

        let state_sync_message = self
            .state_manager
            .states
            .read()
            .states_metadata
            .iter()
            .find_map(|(height, metadata)| {
                if metadata.root_hash() == Some(&msg_id.hash) {
                    let manifest = metadata.manifest()?;
                    let meta_manifest = metadata.meta_manifest()?;
                    let checkpoint_root =
                        self.state_manager.state_layout.checkpoint(*height).ok()?;
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
                        root_hash: msg_id.hash.clone(),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        meta_manifest,
                        manifest: manifest.clone(),
                        state_sync_file_group,
                    })
                } else {
                    None
                }
            });

        if let Some(state_sync_file_group) = file_group_to_populate {
            if let Some(metadata) = self
                .state_manager
                .states
                .write()
                .states_metadata
                .get_mut(&msg_id.height)
            {
                metadata.state_sync_file_group = Some(state_sync_file_group);
            }
        }
        state_sync_message
    }

    fn has_artifact(&self, msg_id: &StateSyncArtifactId) -> bool {
        self.state_manager
            .states
            .read()
            .states_metadata
            .iter()
            .any(|(height, metadata)| {
                *height == msg_id.height && metadata.root_hash() == Some(&msg_id.hash)
            })
    }

    // Enumerates all recent fully certified (i.e. referenced in a CUP) states that
    // is above the filter height.
    fn get_all_validated_by_filter(
        &self,
        filter: &StateSyncFilter,
    ) -> Vec<Advert<StateSyncArtifact>> {
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
                if h > filter.height {
                    let metadata = states.states_metadata.get(&h)?;
                    let manifest = metadata.manifest()?;
                    let meta_manifest = metadata.meta_manifest()?;
                    let checkpoint_root = self.state_manager.state_layout.checkpoint(h).ok()?;
                    let msg = StateSyncMessage {
                        height: h,
                        root_hash: metadata.root_hash()?.clone(),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        manifest: manifest.clone(),
                        meta_manifest,
                        state_sync_file_group: Default::default(),
                    };
                    Some(StateSyncArtifact::message_to_advert(&msg))
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_priority_function(
        &self,
    ) -> Box<dyn Fn(&StateSyncArtifactId, &()) -> Priority + Send + Sync + 'static> {
        use ic_interfaces_state_manager::StateReader;

        let latest_height = self.state_manager.latest_state_height();
        let fetch_state = self.state_manager.states.read().fetch_state.clone();
        let state_sync_refs = self.state_sync_refs.clone();
        let log = self.log.clone();

        Box::new(move |artifact_id, _attr| {
            use std::cmp::Ordering;

            if artifact_id.height <= latest_height {
                return Priority::Drop;
            }

            if let Some((max_sync_height, hash, cup_interval_length)) = &fetch_state {
                if let Some(recorded_root_hash) = state_sync_refs.get(&artifact_id.height) {
                    // If this advert@h is for an ongoing state sync, we check if the hash is the
                    // same as the hash that consensus gave us.
                    if recorded_root_hash != artifact_id.hash {
                        warn!(
                            log,
                            "Received an advert for state @{} with a hash that does not match the hash of the state we are fetching: expected {:?}, got {:?}",
                            artifact_id.height,
                            recorded_root_hash,
                            artifact_id.hash
                        );
                        return Priority::Drop;
                    }

                    // To keep the active state sync for longer time, we wait for another
                    // `EXTRA_CHECKPOINTS_TO_KEEP` CUPs. Then a CUP beyond that can drop the
                    // active state sync.
                    //
                    // Note: CUP interval length may change, and we can't predict future intervals.
                    // The condition below is only a heuristic.
                    if *max_sync_height
                        > artifact_id.height
                            + cup_interval_length.increment() * EXTRA_CHECKPOINTS_TO_KEEP as u64
                    {
                        return Priority::Drop;
                    } else {
                        return Priority::Fetch;
                    };
                }

                return match artifact_id.height.cmp(max_sync_height) {
                    Ordering::Less => Priority::Drop,
                    // Drop the advert if the hashes do not match.
                    Ordering::Equal if *hash != artifact_id.hash => {
                        warn!(
                            log,
                            "Received an advert for state {} with a hash that does not match the hash passed to fetch_state: expected {:?}, got {:?}",
                            artifact_id.height,
                            *hash,
                            artifact_id.hash
                        );
                        Priority::Drop
                    }
                    // Do not fetch it for now if we're already fetching another state.
                    Ordering::Equal if !state_sync_refs.is_empty() => Priority::Stash,
                    Ordering::Equal => Priority::Fetch,
                    Ordering::Greater => Priority::Stash,
                };
            }

            Priority::Stash
        })
    }

    /// Get StateSync Filter for re-transmission purpose.
    ///
    /// Anything below or equal to the filter represents what the local
    /// state_manager already has.
    ///
    /// Return the highest certified height as the filter.
    fn get_filter(&self) -> StateSyncFilter {
        StateSyncFilter {
            height: *self
                .state_manager
                .list_state_heights(CERT_CERTIFIED)
                .last()
                .unwrap_or(&Height::from(0)),
        }
    }

    /// Returns requested state as a Chunkable artifact for StateSync.
    fn get_chunk_tracker(&self, id: &StateSyncArtifactId) -> Box<dyn Chunkable + Send + Sync> {
        self.create_chunkable_state(id)
    }
}

impl ArtifactProcessor<StateSyncArtifact> for StateSync {
    // Returns the states checkpointed since the last time process_changes was
    // called.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        artifacts: Vec<UnvalidatedArtifact<StateSyncMessage>>,
    ) -> (Vec<Advert<StateSyncArtifact>>, bool) {
        // Processes received state sync artifacts.
        for UnvalidatedArtifact {
            message,
            peer_id,
            timestamp: _,
        } in artifacts
        {
            let height = message.height;
            info!(
                self.log,
                "Received state {} from peer {}", message.height, peer_id
            );

            let ro_layout = self
                .state_manager
                .state_layout
                .checkpoint(height)
                .expect("failed to create checkpoint layout");
            let state = crate::checkpoint::load_checkpoint_parallel(
                &ro_layout,
                self.state_manager.own_subnet_type,
                &self.state_manager.metrics.checkpoint_metrics,
                self.state_manager.get_fd_factory(),
            )
            .expect("failed to recover checkpoint");

            self.state_manager.on_synced_checkpoint(
                state,
                height,
                message.manifest,
                message.meta_manifest,
                message.root_hash,
            );
        }

        let filter = StateSyncFilter {
            height: self.state_manager.states.read().last_advertised,
        };
        let artifacts = self.get_all_validated_by_filter(&filter);
        if let Some(artifact) = artifacts.last() {
            self.state_manager.states.write().last_advertised = artifact.id.height;
        }

        (artifacts, false)
    }
}

impl StateSyncClient for StateSync {
    /// Non-blocking.
    fn available_states(&self) -> Vec<StateSyncArtifactId> {
        // Using height 0 here is sane because for state sync `get_all_validated_by_filter`
        // return at most the number of states present on the node. Currently this is usually 1-2.
        let filter = StateSyncFilter {
            height: Height::from(0),
        };
        self.get_all_validated_by_filter(&filter)
            .into_iter()
            .map(|a| a.id)
            .collect()
    }

    /// Non-blocking.
    fn start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>> {
        if self.get_priority_function()(id, &()) != Priority::Fetch {
            return None;
        }
        Some(self.get_chunk_tracker(id))
    }

    /// Non-Blocking.
    fn should_cancel(&self, id: &StateSyncArtifactId) -> bool {
        self.get_priority_function()(id, &()) == Priority::Drop
    }

    /// Blocking. Makes synchronous file system calls.
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        let msg = self.get_validated_by_identifier(id)?;
        Box::new(msg).get_chunk(chunk_id)
    }

    /// Blocking. Makes synchronous file system calls.
    fn deliver_state_sync(&self, msg: StateSyncMessage, peer_id: NodeId) {
        let _ = self.process_changes(
            &SysTimeSource::new(),
            vec![UnvalidatedArtifact {
                message: msg,
                peer_id,
                timestamp: UNIX_EPOCH,
            }],
        );
    }
}
