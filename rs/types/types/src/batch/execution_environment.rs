use crate::{node_id_into_protobuf, node_id_try_from_option, QueryStatsEpoch};
use ic_base_types::{CanisterId, NodeId};
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
use ic_protobuf::state::canister_state_bits::v1::{
    TotalQueryStats as TotalQueryStatsProto, Unsigned128,
};
use ic_protobuf::state::stats::v1::{QueryStats, QueryStatsInner};
use ic_protobuf::types::v1::{self as pb};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::Hash;

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
    pub stats: BTreeMap<(CanisterId, NodeId), CanisterQueryStats>,
}

impl ReceivedEpochStats {
    pub fn as_query_stats(&self) -> Option<QueryStats> {
        // Serialize BTreeMap as vector
        let query_stats: Vec<QueryStatsInner> = self
            .stats
            .iter()
            .map(|((canister_id, node_id), stats)| QueryStatsInner {
                proposer: Some(node_id_into_protobuf(*node_id)),
                canister: Some(pb::CanisterId::from(*canister_id)),
                num_calls: stats.num_calls,
                num_instructions: stats.num_instructions,
                ingress_payload_size: stats.ingress_payload_size,
                egress_payload_size: stats.egress_payload_size,
            })
            .collect();

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
                r.stats.insert(
                    (
                        try_from_option_field(entry.canister, "QueryStatsInner::canister_id")?,
                        proposer,
                    ),
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
/// This explictly contains the senders Node ID. While this is redundant with meta
/// data of the block itself, we want to keep metadata specific to query stats
/// as part of the query stats payload. This way, consensus stays nice and generic and
/// the query stats part is self contained.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochStatsMessages {
    pub proposer: NodeId,
    pub stats: Vec<(CanisterId, CanisterQueryStats)>,
}

impl Default for EpochStatsMessages {
    fn default() -> Self {
        Self {
            proposer: NodeId::try_from(ic_base_types::PrincipalId::default()).unwrap(),
            stats: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryStatsPayload {
    pub canister_stats: BTreeMap<CanisterId, CanisterQueryStats>,
}

impl From<&QueryStatsPayload> for pb::QueryStatsPayload {
    // Encode protobuf representation of query stats
    fn from(payload: &QueryStatsPayload) -> Self {
        let mut container = pb::QueryStatsPayload::default();
        for (key, value) in &payload.canister_stats {
            let inner = pb::QueryStatsPayloadInner {
                canister_id: Some(pb::CanisterId::from(*key)),
                num_calls: value.num_calls,
                num_instructions: value.num_instructions,
                ingress_payload_size: value.ingress_payload_size,
                egress_payload_size: value.egress_payload_size,
            };

            container.canister_stats.push(inner);
        }
        container
    }
}

impl TryFrom<pb::QueryStatsPayload> for QueryStatsPayload {
    type Error = ProxyDecodeError;
    // Decode protobuf representation of query stats
    fn try_from(payload: pb::QueryStatsPayload) -> Result<Self, Self::Error> {
        let mut canister_stats = BTreeMap::new();
        for entry in payload.canister_stats {
            canister_stats.insert(
                try_from_option_field(entry.canister_id, "QueryStatsPayloadInner::canister_id")?,
                CanisterQueryStats {
                    num_calls: entry.num_calls,
                    num_instructions: entry.num_instructions,
                    ingress_payload_size: entry.ingress_payload_size,
                    egress_payload_size: entry.egress_payload_size,
                },
            );
        }
        Ok(Self { canister_stats })
    }
}
