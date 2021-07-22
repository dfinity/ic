pub(crate) mod chunkable;

use super::StateManagerImpl;
use ic_crypto::crypto_hash;
use ic_interfaces::{
    artifact_manager::{ArtifactAcceptance, ArtifactClient, ArtifactProcessor, ProcessingResult},
    artifact_pool::{ArtifactPoolError, UnvalidatedArtifact},
    state_manager::{StateManager, CERT_CERTIFIED},
    time_source::TimeSource,
};
use ic_logger::{info, warn};
use ic_types::{
    artifact::{
        Advert, ArtifactKind, ArtifactTag, Priority, StateSyncArtifactId, StateSyncAttribute,
        StateSyncFilter, StateSyncMessage,
    },
    chunkable::Chunkable,
    Height, NodeId,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StateSyncArtifact;

impl ArtifactKind for StateSyncArtifact {
    const TAG: ArtifactTag = ArtifactTag::StateSyncArtifact;
    type Id = StateSyncArtifactId;
    type Message = StateSyncMessage;
    type SerializeAs = StateSyncMessage;
    type Attribute = StateSyncAttribute;
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
            attribute: StateSyncAttribute {
                height: msg.height,
                root_hash: msg.root_hash.clone(),
            },
            size: size as usize,
            integrity_hash: crypto_hash(msg).get(),
        }
    }
}

impl ArtifactClient<StateSyncArtifact> for StateManagerImpl {
    fn check_artifact_acceptance(
        &self,
        msg: StateSyncMessage,
        peer_id: &NodeId,
    ) -> Result<ArtifactAcceptance<StateSyncMessage>, ArtifactPoolError> {
        let height = msg.height;
        info!(
            self.log,
            "Received state {} from peer {}", msg.height, peer_id
        );

        let ro_layout = self
            .state_layout
            .checkpoint(height)
            .expect("failed to create checkpoint layout");
        let state = crate::checkpoint::load_checkpoint(&ro_layout, self.own_subnet_type)
            .expect("failed to recover checkpoint");
        self.on_synced_checkpoint(state, height, msg.manifest, msg.root_hash);

        Ok(ArtifactAcceptance::Processed)
    }

    fn get_validated_by_identifier(
        &self,
        msg_id: &StateSyncArtifactId,
    ) -> Option<StateSyncMessage> {
        self.states
            .read()
            .states_metadata
            .iter()
            .find_map(|(height, metadata)| {
                if metadata.root_hash.as_ref() == Some(&msg_id.hash) {
                    let manifest = metadata.manifest.as_ref()?;
                    let checkpoint_root = self.state_layout.checkpoint(*height).ok()?;
                    Some(StateSyncMessage {
                        height: *height,
                        root_hash: msg_id.hash.clone(),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        manifest: manifest.clone(),
                        get_state_sync_chunk: Some(
                            crate::state_sync::chunkable::get_state_sync_chunk,
                        ),
                    })
                } else {
                    None
                }
            })
    }

    fn has_artifact(&self, msg_id: &StateSyncArtifactId) -> bool {
        self.states
            .read()
            .states_metadata
            .iter()
            .any(|(height, metadata)| {
                *height == msg_id.height && metadata.root_hash.as_ref() == Some(&msg_id.hash)
            })
    }

    // Enumerates all recent fully certified (i.e. referenced in a CUP) states that
    // is above the filter height.
    fn get_all_validated_by_filter(
        &self,
        filter: &StateSyncFilter,
    ) -> Vec<Advert<StateSyncArtifact>> {
        let heights = match self.state_layout.checkpoint_heights() {
            Ok(heights) => heights,
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to fetch checkpoint heights for state sync: {}", err
                );
                return Vec::new();
            }
        };
        let states = self.states.read();

        heights
            .into_iter()
            .filter_map(|h| {
                if h > filter.height {
                    let metadata = states.states_metadata.get(&h)?;
                    let manifest = metadata.manifest.as_ref()?;
                    let checkpoint_root = self.state_layout.checkpoint(h).ok()?;
                    let msg = StateSyncMessage {
                        height: h,
                        root_hash: metadata.root_hash.as_ref()?.clone(),
                        checkpoint_root: checkpoint_root.raw_path().to_path_buf(),
                        manifest: manifest.clone(),
                        get_state_sync_chunk: Some(
                            crate::state_sync::chunkable::get_state_sync_chunk,
                        ),
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
    ) -> Option<
        Box<dyn Fn(&StateSyncArtifactId, &StateSyncAttribute) -> Priority + Send + Sync + 'static>,
    > {
        use ic_interfaces::state_manager::StateReader;

        let latest_height = self.latest_state_height();
        let fetch_state = self.states.read().fetch_state.clone();

        Some(Box::new(move |_artifact_id, attr| {
            use std::cmp::Ordering;

            if attr.height <= latest_height {
                return Priority::Drop;
            }

            if let Some((max_sync_height, hash)) = &fetch_state {
                return match attr.height.cmp(max_sync_height) {
                    Ordering::Less => Priority::Drop,
                    Ordering::Equal if *hash != attr.root_hash => Priority::Drop,
                    Ordering::Equal => Priority::Fetch,
                    Ordering::Greater => Priority::Stash,
                };
            }

            Priority::Stash
        }))
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
                .list_state_heights(CERT_CERTIFIED)
                .last()
                .unwrap_or(&Height::from(0)),
        }
    }

    /// Returns requested state as a Chunkable artifact for StateSync.
    fn get_chunk_tracker(&self, id: &StateSyncArtifactId) -> Box<dyn Chunkable + Send + Sync> {
        self.create_chunkable_state(&id)
    }
}

impl ArtifactProcessor<StateSyncArtifact> for StateManagerImpl {
    // Returns the states checkpointed since the last time process_changes was
    // called.
    fn process_changes(
        &self,
        _time_source: &dyn TimeSource,
        _artifacts: Vec<UnvalidatedArtifact<StateSyncMessage>>,
    ) -> (Vec<Advert<StateSyncArtifact>>, ProcessingResult) {
        let filter = StateSyncFilter {
            height: self.states.read().last_advertised,
        };
        let artifacts = self.get_all_validated_by_filter(&filter);

        if let Some(artifact) = artifacts.last() {
            self.states.write().last_advertised = artifact.attribute.height;
        }

        (artifacts, ProcessingResult::StateUnchanged)
    }
}
