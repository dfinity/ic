use crate::{node_id_into_protobuf, node_id_try_from_option, QueryStatsEpoch};
use ic_base_types::{CanisterId, NodeId, NumBytes};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    state::{
        canister_state_bits::v1::{TotalQueryStats as TotalQueryStatsProto, Unsigned128},
        stats::v1::{QueryStats, QueryStatsInner},
    },
    types::v1::{self as pb},
};
use prost::{bytes::BufMut, Message};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanisterQueryStats {
    pub num_calls: u32,
    pub num_instructions: u64, // Want u128, but not supported in protobuf
    pub ingress_payload_size: u64,
    pub egress_payload_size: u64,
}

/// Total number of query stats collected since creation of the canister.
///
/// This is a separate struct since values contained in here are accumulated
/// since the canister has been created. Hence, we need larger integers to make
/// overflows very unlikely.
///
/// As rates are calculated by repeated polling query stats, overlfows should not be
/// a problem if the client side is polling frequently enough and handles those overflows.
///
/// Given the size of these values, overflows sould be rare, though.
#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct TotalCanisterQueryStats {
    pub num_calls: u128,
    pub num_instructions: u128,
    pub ingress_payload_size: u128,
    pub egress_payload_size: u128,
}

fn get_u128_from_protobuf(proto: Option<Unsigned128>) -> Result<u128, ProxyDecodeError> {
    let array: [u8; 16] = proto
        .ok_or(ProxyDecodeError::MissingField(
            "CanisterStateBits::total_query_stats",
        ))?
        .raw
        .try_into()
        .map_err(|e| {
            ProxyDecodeError::Other(format!("Failed to decode total_query_stats: {:?}", e))
        })?;
    Ok(u128::from_le_bytes(array))
}

fn get_protobuf_for_u128(value: u128) -> Unsigned128 {
    Unsigned128 {
        raw: value.to_le_bytes().to_vec(),
    }
}

impl TryFrom<TotalQueryStatsProto> for TotalCanisterQueryStats {
    type Error = ProxyDecodeError;

    fn try_from(value: TotalQueryStatsProto) -> Result<Self, Self::Error> {
        Ok(Self {
            num_calls: get_u128_from_protobuf(value.num_calls)?,
            num_instructions: get_u128_from_protobuf(value.num_instructions)?,
            ingress_payload_size: get_u128_from_protobuf(value.ingress_payload_size)?,
            egress_payload_size: get_u128_from_protobuf(value.egress_payload_size)?,
        })
    }
}

impl From<&TotalCanisterQueryStats> for TotalQueryStatsProto {
    fn from(value: &TotalCanisterQueryStats) -> Self {
        TotalQueryStatsProto {
            num_calls: Some(get_protobuf_for_u128(value.num_calls)),
            num_instructions: Some(get_protobuf_for_u128(value.num_instructions)),
            ingress_payload_size: Some(get_protobuf_for_u128(value.ingress_payload_size)),
            egress_payload_size: Some(get_protobuf_for_u128(value.egress_payload_size)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochStats {
    pub epoch: QueryStatsEpoch,
    pub stats: Vec<(CanisterId, CanisterQueryStats)>,
}

/// Stats received from block throughout the given epoch.
/// This struct is used to store defragmented stats received from blocks in the replicated state,
/// so that they can survive a restart of the node.
/// Need to remember the epoch this is for as well as the NodeId of the
/// node proposing the block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceivedEpochStats {
    pub epoch: Option<QueryStatsEpoch>,
    pub stats: BTreeMap<CanisterId, BTreeMap<NodeId, CanisterQueryStats>>,
}

impl ReceivedEpochStats {
    pub fn as_query_stats(&self) -> Option<QueryStats> {
        // Serialize BTreeMap as vector
        let mut query_stats = vec![];

        for (canister_id, inner) in &self.stats {
            for (node_id, stats) in inner {
                query_stats.push(QueryStatsInner {
                    proposer: Some(node_id_into_protobuf(*node_id)),
                    canister: Some(pb::CanisterId::from(*canister_id)),
                    num_calls: stats.num_calls,
                    num_instructions: stats.num_instructions,
                    ingress_payload_size: stats.ingress_payload_size,
                    egress_payload_size: stats.egress_payload_size,
                });
            }
        }

        self.epoch.map(|epoch| QueryStats {
            epoch: epoch.get(),
            query_stats,
        })
    }
}

impl TryFrom<QueryStats> for ReceivedEpochStats {
    type Error = ProxyDecodeError;

    fn try_from(value: QueryStats) -> Result<Self, Self::Error> {
        let mut r = ReceivedEpochStats {
            epoch: Some(QueryStatsEpoch::from(value.epoch)),
            stats: BTreeMap::new(),
        };
        for entry in value.query_stats {
            if let Ok(proposer) = node_id_try_from_option(entry.proposer) {
                let key = try_from_option_field(entry.canister, "QueryStatsInner::canister_id")?;
                r.stats.entry(key).or_default().insert(
                    proposer,
                    CanisterQueryStats {
                        num_calls: entry.num_calls,
                        num_instructions: entry.num_instructions,
                        ingress_payload_size: entry.ingress_payload_size,
                        egress_payload_size: entry.egress_payload_size,
                    },
                );
            }
        }
        Ok(r)
    }
}

/// Content of the query stats payload appended to blocks.
/// This explicitly contains the senders Node ID. While this is redundant with meta
/// data of the block itself, we want to keep metadata specific to query stats
/// as part of the query stats payload. This way, consensus stays nice and generic and
/// the query stats part is self contained.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochStatsMessages {
    pub epoch: QueryStatsEpoch,
    pub proposer: NodeId,
    pub stats: Vec<QueryStatsMessage>,
}

impl EpochStatsMessages {
    /// Serialize this payload into a vector
    ///
    /// This function will drop trailing stats to guarantee, that the
    /// payload will fit into the `byte_limit`
    pub fn serialize_with_limit(&self, byte_limit: NumBytes) -> Vec<u8> {
        if self.stats.is_empty() {
            return vec![];
        }

        let mut buffer = vec![].limit(byte_limit.get() as usize);

        // Encode the metadata about the messages
        match self
            .epoch
            .get()
            .encode_length_delimited(&mut buffer)
            .and_then(|()| self.proposer.get().encode_length_delimited(&mut buffer))
        {
            Ok(()) => (),
            // Return immidiately, if there is not enough space to fit the metadata
            Err(_) => return vec![],
        }

        let mut num_stats_included = 0;
        for entry in &self.stats {
            if pb::QueryStatsPayloadInner::from(entry)
                .encode_length_delimited(&mut buffer)
                .is_err()
            {
                break;
            }

            num_stats_included += 1;
        }

        // If there is enough space for the metadata but not for stats,
        // return an empty payload.
        if num_stats_included == 0 {
            vec![]
        } else {
            buffer.into_inner()
        }
    }

    /// Deserializes a [`EpochStatsMessages`]
    ///
    /// Allows to filter for node id and epoch.
    /// If the filters are set, the deserializer will check whether the node_id
    /// respectively epoch match, and if not skip the rest of the deserialization.
    pub fn deserialize(mut data: &[u8]) -> Result<Option<Self>, ProxyDecodeError> {
        if data.is_empty() {
            return Ok(None);
        }

        // Deserialize epoch and proposer
        let epoch = QueryStatsEpoch::new(
            u64::decode_length_delimited(&mut data).map_err(ProxyDecodeError::DecodeError)?,
        );
        let proposer = NodeId::new(
            pb::PrincipalId::decode_length_delimited(&mut data)
                .map_err(ProxyDecodeError::DecodeError)?
                .try_into()?,
        );

        let mut messages = Self {
            epoch,
            proposer,
            stats: vec![],
        };

        // Deserialize the stats
        while !data.is_empty() {
            let stat = pb::QueryStatsPayloadInner::decode_length_delimited(&mut data)
                .map_err(ProxyDecodeError::DecodeError)?;
            messages.stats.push(QueryStatsMessage::try_from(&stat)?);
        }

        Ok(Some(messages))
    }
}

/// A message about the statistics of a specific canister.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryStatsMessage {
    pub canister_id: CanisterId,
    pub stats: CanisterQueryStats,
}

impl From<&QueryStatsMessage> for pb::QueryStatsPayloadInner {
    fn from(entry: &QueryStatsMessage) -> Self {
        Self {
            canister_id: Some(pb::CanisterId::from(entry.canister_id)),
            num_calls: entry.stats.num_calls,
            num_instructions: entry.stats.num_instructions,
            ingress_payload_size: entry.stats.ingress_payload_size,
            egress_payload_size: entry.stats.egress_payload_size,
        }
    }
}

impl TryFrom<&pb::QueryStatsPayloadInner> for QueryStatsMessage {
    type Error = ProxyDecodeError;

    fn try_from(entry: &pb::QueryStatsPayloadInner) -> Result<Self, Self::Error> {
        Ok(Self {
            canister_id: try_from_option_field(
                entry.canister_id.clone(),
                "QueryStatsInner::canister_id",
            )?,
            stats: CanisterQueryStats {
                num_calls: entry.num_calls,
                num_instructions: entry.num_instructions,
                ingress_payload_size: entry.ingress_payload_size,
                egress_payload_size: entry.egress_payload_size,
            },
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryStatsPayload {
    pub canister_stats: BTreeMap<CanisterId, CanisterQueryStats>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    /// Empty serialization test
    #[test]
    fn empty_serialization() {
        let original_stats = test_message(1000);
        let serialized_stats = original_stats.serialize_with_limit(NumBytes::new(4));
        assert!(serialized_stats.is_empty());
        assert!(EpochStatsMessages::deserialize(&serialized_stats)
            .unwrap()
            .is_none());
    }

    /// Serialization and deserialization test
    #[test]
    fn serialization_roundtrip() {
        let original_stats = test_message(1000);
        let serialized_stats = original_stats.serialize_with_limit(NumBytes::new(2 * 1024 * 1024));
        let deserialized_stats = EpochStatsMessages::deserialize(&serialized_stats)
            .unwrap()
            .unwrap();
        assert_eq!(&original_stats, &deserialized_stats);
    }

    /// Test serialization with space limit
    #[test]
    fn serialization_with_byte_limit() {
        let original_stats = test_message(1000);
        let serialized_stats = original_stats.serialize_with_limit(NumBytes::new(2 * 1024));
        assert!(serialized_stats.len() < 2 * 1024);
        let deserialized_stats = EpochStatsMessages::deserialize(&serialized_stats)
            .unwrap()
            .unwrap();
        assert!(original_stats.stats.len() > deserialized_stats.stats.len());
    }

    fn test_message(num_stats: u64) -> EpochStatsMessages {
        let mut rng = ChaCha8Rng::seed_from_u64(1454);

        EpochStatsMessages {
            epoch: QueryStatsEpoch::new(1),
            proposer: NodeId::from(PrincipalId::new_node_test_id(1)),
            stats: (0..num_stats)
                .map(|idx| QueryStatsMessage {
                    canister_id: CanisterId::from(idx),
                    stats: rng_epoch_stats(&mut rng),
                })
                .collect(),
        }
    }

    fn rng_epoch_stats<R>(rng: &mut R) -> CanisterQueryStats
    where
        R: RngCore,
    {
        CanisterQueryStats {
            num_calls: rng.gen(),
            num_instructions: rng.gen(),
            ingress_payload_size: rng.gen(),
            egress_payload_size: rng.gen(),
        }
    }
}
