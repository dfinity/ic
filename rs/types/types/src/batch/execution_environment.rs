use crate::QueryStatsEpoch;
use ic_base_types::CanisterId;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError};
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

pub struct EpochStats {
    pub epoch: QueryStatsEpoch,
    pub stats: Vec<(CanisterId, CanisterQueryStats)>,
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
