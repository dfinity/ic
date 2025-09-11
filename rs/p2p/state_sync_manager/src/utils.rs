use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_types::NodeId;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct XorDistance([u8; 32]);

impl XorDistance {
    pub(crate) fn new(
        peer_id: NodeId,
        artifact_id: StateSyncArtifactId,
        chunk_id: ChunkId,
    ) -> Self {
        let mut lhs_hash: [u8; 32] = Sha256::digest(peer_id.get().to_vec()).try_into().unwrap();

        let mut rhs_hash = Sha256::new();
        rhs_hash.update(artifact_id.height.get().to_be_bytes());
        rhs_hash.update(artifact_id.hash.0);
        rhs_hash.update(chunk_id.get().to_be_bytes());
        let rhs_hash: [u8; 32] = rhs_hash.finalize().try_into().unwrap();

        lhs_hash
            .iter_mut()
            .zip(rhs_hash.iter())
            .for_each(|(lhs, rhs)| *lhs ^= rhs);

        Self(lhs_hash)
    }
}
