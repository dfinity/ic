//! Type definitions for the QueryStats feature
//!
//! QueryStats functions as follows:
//!
//! Queries are served locally by a single node, using the certified state.
//! Unlike updates, queries are read only and can not modify the state, which
//! makes accounting for resources that queries consume difficult.
//! To get a measurement of how much resources are used by non-replicated query calls,
//! each node locally accumulates [`QueryStats`] for each canister in a fixed interval
//! of certified heights called the [`QueryStatsEpoch`].
//!
//! After an epoch has passed, the collected [`LocalQueryStats`] are sent to the
//! consensus layer.
//! Consensus will include the statistics as a [`QueryStatsPayload`] in a block.
//! It may split the stats for different canisters over multiple blocks.
//!
//! When the payload of a block gets delivered to the DSM, the delivered statistics
//! will be collected as [`RawQueryStats`].
//! Again, after a [`QueryStatsEpoch`] has progressed, the statistics are aggregated
//! by taking for each [`CanisterId`] the median of the statistics reported by each node.
//! The aggregated statistics are then added to the [`TotalQueryStats`], from where they can
//! be accessed by canisters.

use crate::{QueryStatsEpoch, node_id_into_protobuf, node_id_try_from_option};
use ic_base_types::{CanisterId, NodeId, NumBytes};
use ic_heap_bytes::DeterministicHeapBytes;
use ic_protobuf::registry::subnet::v1 as proto;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    state::{
        canister_state_bits::v1::{TotalQueryStats as TotalQueryStatsProto, Unsigned128},
        stats::v1::{QueryStats as QueryStatsProto, QueryStatsInner},
    },
    types::v1::{self as pb},
};
use prost::{Message, bytes::BufMut};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

#[derive(Clone, DeterministicHeapBytes, Eq, PartialEq, Hash, Debug, Default)]
pub struct QueryStats {
    pub num_calls: u32,
    pub num_instructions: u64, // Want u128, but not supported in protobuf
    pub ingress_payload_size: u64,
    pub egress_payload_size: u64,
}

impl QueryStats {
    pub fn saturating_accumulate(&mut self, rhs: &Self) {
        self.num_calls = self.num_calls.saturating_add(rhs.num_calls);
        self.num_instructions = self.num_instructions.saturating_add(rhs.num_instructions);
        self.ingress_payload_size = self
            .ingress_payload_size
            .saturating_add(rhs.ingress_payload_size);
        self.egress_payload_size = self
            .egress_payload_size
            .saturating_add(rhs.egress_payload_size);
    }
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
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct TotalQueryStats {
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
            ProxyDecodeError::Other(format!("Failed to decode total_query_stats: {e:?}"))
        })?;
    Ok(u128::from_le_bytes(array))
}

fn get_protobuf_for_u128(value: u128) -> Unsigned128 {
    Unsigned128 {
        raw: value.to_le_bytes().to_vec(),
    }
}

impl TryFrom<TotalQueryStatsProto> for TotalQueryStats {
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

impl From<&TotalQueryStats> for TotalQueryStatsProto {
    fn from(value: &TotalQueryStats) -> Self {
        TotalQueryStatsProto {
            num_calls: Some(get_protobuf_for_u128(value.num_calls)),
            num_instructions: Some(get_protobuf_for_u128(value.num_instructions)),
            ingress_payload_size: Some(get_protobuf_for_u128(value.ingress_payload_size)),
            egress_payload_size: Some(get_protobuf_for_u128(value.egress_payload_size)),
        }
    }
}

/// QueryStats with the epoch at which they where collected.
///
/// [`LocalQueryStats`] are sent from execution to consensus for
/// inclusion in blocks.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct LocalQueryStats {
    pub epoch: QueryStatsEpoch,
    pub stats: Vec<CanisterQueryStats>,
}

/// Stats received from block throughout the given epoch.
///
/// This struct is used to store defragmented stats received from blocks in the replicated state,
/// so that they can survive a restart of the node.
/// Need to remember the epoch this is for as well as the NodeId of the
/// node proposing the block.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct RawQueryStats {
    pub highest_aggregated_epoch: Option<QueryStatsEpoch>,
    pub stats: BTreeMap<NodeId, BTreeMap<QueryStatsEpoch, BTreeMap<CanisterId, QueryStats>>>,
}

impl RawQueryStats {
    pub fn as_query_stats(&self) -> Option<QueryStatsProto> {
        // Serialize BTreeMap as vector
        let mut query_stats = vec![];

        for (node_id, inner) in &self.stats {
            for (epoch, inner) in inner {
                for (canister_id, stats) in inner {
                    query_stats.push(QueryStatsInner {
                        proposer: Some(node_id_into_protobuf(*node_id)),
                        epoch: epoch.get(),
                        canister: Some(pb::CanisterId::from(*canister_id)),
                        num_calls: stats.num_calls,
                        num_instructions: stats.num_instructions,
                        ingress_payload_size: stats.ingress_payload_size,
                        egress_payload_size: stats.egress_payload_size,
                    });
                }
            }
        }

        if query_stats.is_empty() && self.highest_aggregated_epoch.is_none() {
            None
        } else {
            Some(QueryStatsProto {
                highest_aggregated_epoch: self.highest_aggregated_epoch.map(|epoch| epoch.get()),
                query_stats,
            })
        }
    }
}

impl TryFrom<QueryStatsProto> for RawQueryStats {
    type Error = ProxyDecodeError;

    fn try_from(value: QueryStatsProto) -> Result<Self, Self::Error> {
        let mut r = RawQueryStats {
            highest_aggregated_epoch: value.highest_aggregated_epoch.map(QueryStatsEpoch::from),
            stats: BTreeMap::new(),
        };
        for entry in value.query_stats {
            if let Ok(proposer) = node_id_try_from_option(entry.proposer) {
                let epoch = QueryStatsEpoch::new(entry.epoch);
                let canister: CanisterId =
                    try_from_option_field(entry.canister, "QueryStatsInner::canister_id")?;

                r.stats
                    .entry(proposer)
                    .or_default()
                    .entry(epoch)
                    .or_default()
                    .insert(
                        canister,
                        QueryStats {
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
///
/// This explicitly contains the senders Node ID. While this is redundant with meta
/// data of the block itself, we want to keep metadata specific to query stats
/// as part of the query stats payload. This way, consensus stays nice and generic and
/// the query stats part is self contained.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct QueryStatsPayload {
    pub epoch: QueryStatsEpoch,
    pub proposer: NodeId,
    pub stats: Vec<CanisterQueryStats>,
}

impl QueryStatsPayload {
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
            if pb::CanisterQueryStats::from(entry)
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

    /// Deserializes a [`QueryStatsPayload`]
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
            let stat = pb::CanisterQueryStats::decode_length_delimited(&mut data)
                .map_err(ProxyDecodeError::DecodeError)?;
            messages.stats.push(CanisterQueryStats::try_from(&stat)?);
        }

        Ok(Some(messages))
    }
}

/// A message about the statistics of a specific canister.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CanisterQueryStats {
    pub canister_id: CanisterId,
    pub stats: QueryStats,
}

impl From<&CanisterQueryStats> for pb::CanisterQueryStats {
    fn from(entry: &CanisterQueryStats) -> Self {
        Self {
            canister_id: Some(pb::CanisterId::from(entry.canister_id)),
            num_calls: entry.stats.num_calls,
            num_instructions: entry.stats.num_instructions,
            ingress_payload_size: entry.stats.ingress_payload_size,
            egress_payload_size: entry.stats.egress_payload_size,
        }
    }
}

impl TryFrom<&pb::CanisterQueryStats> for CanisterQueryStats {
    type Error = ProxyDecodeError;

    fn try_from(entry: &pb::CanisterQueryStats) -> Result<Self, Self::Error> {
        Ok(Self {
            canister_id: try_from_option_field(
                entry.canister_id.clone(),
                "QueryStatsInner::canister_id",
            )?,
            stats: QueryStats {
                num_calls: entry.num_calls,
                num_instructions: entry.num_instructions,
                ingress_payload_size: entry.ingress_payload_size,
                egress_payload_size: entry.egress_payload_size,
            },
        })
    }
}

/// How to charge canisters for their use of computational resources (such as
/// executing instructions, storing data, network, etc.)
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanisterCyclesCostSchedule {
    #[default]
    Normal,
    Free,
}

impl From<proto::CanisterCyclesCostSchedule> for CanisterCyclesCostSchedule {
    fn from(value: proto::CanisterCyclesCostSchedule) -> Self {
        match value {
            proto::CanisterCyclesCostSchedule::Unspecified => CanisterCyclesCostSchedule::Normal,
            proto::CanisterCyclesCostSchedule::Normal => CanisterCyclesCostSchedule::Normal,
            proto::CanisterCyclesCostSchedule::Free => CanisterCyclesCostSchedule::Free,
        }
    }
}

impl From<CanisterCyclesCostSchedule> for proto::CanisterCyclesCostSchedule {
    fn from(value: CanisterCyclesCostSchedule) -> Self {
        match value {
            CanisterCyclesCostSchedule::Normal => proto::CanisterCyclesCostSchedule::Normal,
            CanisterCyclesCostSchedule::Free => proto::CanisterCyclesCostSchedule::Free,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;
    use ic_types_test_utils::ids::{canister_test_id, node_test_id};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    /// Empty serialization test
    #[test]
    fn empty_serialization() {
        let original_stats = test_message(1000);
        let serialized_stats = original_stats.serialize_with_limit(NumBytes::new(4));
        assert!(serialized_stats.is_empty());
        assert!(
            QueryStatsPayload::deserialize(&serialized_stats)
                .unwrap()
                .is_none()
        );
    }

    /// Serialization and deserialization test
    #[test]
    fn serialization_roundtrip() {
        let original_stats = test_message(1000);
        let serialized_stats = original_stats.serialize_with_limit(NumBytes::new(2 * 1024 * 1024));
        let deserialized_stats = QueryStatsPayload::deserialize(&serialized_stats)
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
        let deserialized_stats = QueryStatsPayload::deserialize(&serialized_stats)
            .unwrap()
            .unwrap();
        assert!(original_stats.stats.len() > deserialized_stats.stats.len());
    }

    fn test_message(num_stats: u64) -> QueryStatsPayload {
        let mut rng = ChaCha8Rng::seed_from_u64(1454);

        QueryStatsPayload {
            epoch: QueryStatsEpoch::new(1),
            proposer: NodeId::from(PrincipalId::new_node_test_id(1)),
            stats: (0..num_stats)
                .map(|idx| CanisterQueryStats {
                    canister_id: CanisterId::from(idx),
                    stats: rng_epoch_stats(&mut rng),
                })
                .collect(),
        }
    }

    /// Serialization and deserialization test
    #[test]
    fn serialization_roundtrip_raw_query_stats() {
        let mut rng = ChaCha8Rng::seed_from_u64(1454);

        let mut inner = BTreeMap::new();
        inner.insert(canister_test_id(1), rng_epoch_stats(&mut rng));
        let mut record = BTreeMap::new();
        record.insert(QueryStatsEpoch::new(0), inner);
        let mut stats = BTreeMap::new();
        stats.insert(node_test_id(1), record);

        let test = RawQueryStats {
            highest_aggregated_epoch: None,
            stats,
        };

        let pb_test = test.as_query_stats().unwrap();
        let check_test = RawQueryStats::try_from(pb_test).unwrap();

        assert_eq!(test, check_test);
    }

    fn rng_epoch_stats<R>(rng: &mut R) -> QueryStats
    where
        R: RngCore,
    {
        QueryStats {
            num_calls: rng.r#gen(),
            num_instructions: rng.r#gen(),
            ingress_payload_size: rng.r#gen(),
            egress_payload_size: rng.r#gen(),
        }
    }
}
