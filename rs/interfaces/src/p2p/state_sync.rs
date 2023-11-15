use ic_types::{
    artifact::{StateSyncArtifactId, StateSyncMessage},
    chunkable::{ArtifactChunk, ChunkId, Chunkable},
    NodeId,
};

pub trait StateSyncClient: Send + Sync {
    /// Returns a list of all states available.
    fn available_states(&self) -> Vec<StateSyncArtifactId>;
    /// Initiates new state sync for the specified Id. Returns None if the state should not be synced.
    /// If `Some(..)` is returned a new state sync is initiated.
    /// Callers of this interface need to uphold the following: `start_state_sync` is not called again
    /// before the previously returned object is dropped.
    /// TODO: (NET-1469) In the future the mentioned caller restriction should be lifted.
    fn start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable + Send + Sync>>;
    /// Returns true if a state sync with the specified Id can be cancelled because a newer state is available.
    /// The result of this function is only meaningful the Id refers to a active state sync started with `start_state_sync`.
    /// TODO: (NET-1469) In the future this API should be made safer by only allowing the id of a previously initiated state sync.
    fn should_cancel(&self, id: &StateSyncArtifactId) -> bool;
    /// Get a specific chunk from the specified state.
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<ArtifactChunk>;
    /// Finish a state sync by delivering the `StateSyncMessage` returned in `Chunkable::add_chunks`.
    /// TODO: (NET-1469) In the future peer_id should be removed from this interface since it has no relevance.
    fn deliver_state_sync(&self, msg: StateSyncMessage, peer_id: NodeId);
}
