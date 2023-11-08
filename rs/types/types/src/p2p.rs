//! Defines types used by the P2P component.
use crate::artifact::{ArtifactAttribute, ArtifactId};
use crate::crypto::CryptoHash;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_protobuf::types::v1 as pb;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::time::Duration;

/// This is sent to peers to indicate that a node has a certain artifact
/// in its artifact pool. The adverts of different artifact types may differ
/// in their attributes. Upon the reception of an advert, a node can decide
/// if and when to request the corresponding artifact from the sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipAdvert {
    pub attribute: ArtifactAttribute,
    pub size: usize,
    pub artifact_id: ArtifactId,
    /// Crypto hash of the artifact's message.
    pub integrity_hash: CryptoHash,
}

// TODO(P2P-380): Move all the constants in a more reasonable shared location in
// the code.

/////////////////////////////
// Gossip subnet constants //
/////////////////////////////

/// Maximum timeout for fetching an artifact. 10_000s.
/// Reasoning: Block rate can be as low as 0.1 and we want to allow state sync
/// to last for 1000 blocks (two checkopint intervals) -> 1000b/0.1b/s = 10000s
pub const MAX_ARTIFACT_TIMEOUT: Duration = Duration::from_secs(10_000);

/// Maximum number of artifact chunks that can be downloaded
/// simultaneously from one peer
pub const MAX_ARTIFACT_STREAMS_PER_PEER: u32 = 20;

/// Timeout interval (in milliseconds) within which a chunk request must
/// succeed
pub const MAX_CHUNK_WAIT_MS: u32 = 15_000;

/// Maximum number of peers that one artifact chunk can be
/// downloaded from in parallel (`MAX_DUPLICITY=1` means no parallel
/// downloads)
pub const MAX_DUPLICITY: u32 = 1;

/// Maximum size in bytes of an artifact chunk. Used to compute the chunk
/// timeout interval.
//
// Once universal chunking is implemented (P2P-292), chunks larger than this
// size will not be requested.
pub const MAX_CHUNK_SIZE: u32 = 4096;

/// Size of each receive check hash set for each peer
pub const RECEIVE_CHECK_PEER_SET_SIZE: u32 = 5000;

/// Period for priority function evaluation in milliseconds
pub const PFN_EVALUATION_PERIOD_MS: u32 = 1000;

/// Period for polling the registry for changes in milliseconds
pub const REGISTRY_POLL_PERIOD_MS: u32 = 3_000;

/// Period for sending a retransmission request in milliseconds
pub const RETRANSMISSION_REQUEST_MS: u32 = 60_000;

/// Helper function to build a gossip config using default values.
pub fn build_default_gossip_config() -> GossipConfig {
    GossipConfig {
        max_artifact_streams_per_peer: MAX_ARTIFACT_STREAMS_PER_PEER,
        max_chunk_wait_ms: MAX_CHUNK_WAIT_MS,
        max_duplicity: MAX_DUPLICITY,
        max_chunk_size: MAX_CHUNK_SIZE,
        receive_check_cache_size: RECEIVE_CHECK_PEER_SET_SIZE,
        pfn_evaluation_period_ms: PFN_EVALUATION_PERIOD_MS,
        registry_poll_period_ms: REGISTRY_POLL_PERIOD_MS,
        retransmission_request_ms: RETRANSMISSION_REQUEST_MS,
    }
}

impl From<GossipAdvert> for pb::GossipAdvert {
    fn from(advert: GossipAdvert) -> Self {
        Self {
            attribute: Some((&advert.attribute).into()),
            size: advert.size as u64,
            artifact_id: Some((&advert.artifact_id).into()),
            integrity_hash: advert.integrity_hash.0,
        }
    }
}

impl TryFrom<pb::GossipAdvert> for GossipAdvert {
    type Error = ProxyDecodeError;
    fn try_from(advert: pb::GossipAdvert) -> Result<Self, Self::Error> {
        Ok(Self {
            attribute: try_from_option_field(advert.attribute.as_ref(), "GossipAdvert::attribute")?,
            size: advert.size as usize,
            artifact_id: try_from_option_field(
                advert.artifact_id.as_ref(),
                "GossipAdvert::artifact_id",
            )?,
            integrity_hash: CryptoHash(advert.integrity_hash),
        })
    }
}
