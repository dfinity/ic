use ic_interfaces::p2p::state_sync::{ChunkId, StateSyncArtifactId};
use ic_protobuf::{p2p::v1 as pb, proxy::ProxyDecodeError};
use ic_types::NodeId;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Advert {
    id: StateSyncArtifactId,
    partial_state: Option<XorDistance>,
}

impl From<Advert> for pb::Advert {
    fn from(advert: Advert) -> Self {
        pb::Advert {
            id: Some(advert.id.into()),
            partial_state: advert
                .partial_state
                .map(|partial_state| partial_state.0.into()),
        }
    }
}

impl TryFrom<pb::Advert> for Advert {
    type Error = ProxyDecodeError;

    fn try_from(advert: pb::Advert) -> Result<Self, Self::Error> {
        Ok(Advert {
            id: advert
                .id
                .map(|id| StateSyncArtifactId::from(id))
                .ok_or(ProxyDecodeError::MissingField("id"))?,
            partial_state: match advert.partial_state {
                Some(partial_state) => Some(
                    <[u8; 32]>::try_from(partial_state)
                        .map(XorDistance)
                        .map_err(|partial_state| ProxyDecodeError::InvalidDigestLength {
                            expected: 32,
                            actual: partial_state.len(),
                        })?,
                ),
                None => None,
            },
        })
    }
}

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

// TODO: Test XorMetric ordering
// TODO: Test Advert round trip
// TODO: Test malformed advert parsing
