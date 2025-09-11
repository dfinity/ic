// Goals for canister shape
// 1. easy to unit test (avoid things that can only be tested in WASM32 statemachine)
// 2. Simple structures
// 3. Good API boundaries (nothing on the inside gets out)
// 4. Structure makes boundaries clear and easy to enforce
// 5. Simple Organization

use candid::Principal;
use ic_base_types::{PrincipalId, SubnetId};
use ic_management_canister_types::NodeMetrics;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use prost::Message;
use rewards_calculation::types::RewardableNode;
use std::borrow::Cow;

pub mod canister;
pub mod metrics;
pub mod pb;
pub mod registry_querier;
pub mod storage;
pub mod telemetry;

// Maximum sizes for the storable types chosen as result of test `max_bound_size`
const MAX_BYTES_SUBNET_ID_STORED: u32 = 33;
const MAX_BYTES_NODE_METRICS_STORED_KEY: u32 = 44;
const PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;

pub const MIN_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(&[]));
pub const MAX_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(
    &[0xFF_u8; PRINCIPAL_MAX_LENGTH_IN_BYTES],
));

pub trait KeyRange {
    fn min_key() -> Self;
    fn max_key() -> Self;
}

impl From<SubnetId> for pb::v1::SubnetIdKey {
    fn from(subnet_id: SubnetId) -> Self {
        Self {
            subnet_id: Some(subnet_id.get()),
        }
    }
}

impl From<pb::v1::SubnetIdKey> for SubnetId {
    fn from(subnet_id: pb::v1::SubnetIdKey) -> Self {
        subnet_id.subnet_id.unwrap().into()
    }
}

impl From<NodeMetrics> for pb::v1::NodeMetrics {
    fn from(metrics: NodeMetrics) -> Self {
        pb::v1::NodeMetrics {
            node_id: Some(metrics.node_id.into()),
            num_blocks_proposed_total: metrics.num_blocks_proposed_total,
            num_blocks_failed_total: metrics.num_block_failures_total,
        }
    }
}

impl From<RewardableNode> for pb::v1::RewardableNode {
    fn from(value: RewardableNode) -> Self {
        Self {
            node_id: Some(value.node_id.get()),
            region: Some(value.region),
            dc_id: Some(value.dc_id),
            node_reward_type: Some(value.node_reward_type.into()),
        }
    }
}

//------------ Storable Implementations ------------//

impl Storable for pb::v1::SubnetIdKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_BYTES_SUBNET_ID_STORED,
        is_fixed_size: false,
    };
}

impl KeyRange for pb::v1::SubnetMetricsKey {
    fn min_key() -> Self {
        Self {
            timestamp_nanos: u64::MIN,
            subnet_id: Some(MIN_PRINCIPAL_ID),
        }
    }

    fn max_key() -> Self {
        Self {
            timestamp_nanos: u64::MAX,
            subnet_id: Some(MAX_PRINCIPAL_ID),
        }
    }
}

impl Storable for pb::v1::SubnetMetricsKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 2 * MAX_BYTES_NODE_METRICS_STORED_KEY,
        is_fixed_size: false,
    };
}

impl Storable for pb::v1::SubnetMetricsValue {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::v1::NodeMetrics {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl KeyRange for pb::v1::RewardableNodesKey {
    fn min_key() -> Self {
        Self {
            registry_version: u64::MIN,
            provider_id: Some(MIN_PRINCIPAL_ID),
        }
    }

    fn max_key() -> Self {
        Self {
            registry_version: u64::MAX,
            provider_id: Some(MAX_PRINCIPAL_ID),
        }
    }
}

impl Storable for pb::v1::RewardableNodesKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::v1::RewardableNodesValue {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn max_bound_size() {
        let max_subnet_id_stored = pb::v1::SubnetIdKey {
            subnet_id: MAX_PRINCIPAL_ID.into(),
        };
        let max_subnet_metrics_stored_key = pb::v1::SubnetMetricsKey {
            timestamp_nanos: u64::MAX,
            subnet_id: MAX_PRINCIPAL_ID.into(),
        };

        assert_eq!(
            max_subnet_id_stored.to_bytes().len(),
            MAX_BYTES_SUBNET_ID_STORED as usize
        );

        assert_eq!(
            max_subnet_metrics_stored_key.to_bytes().len(),
            MAX_BYTES_NODE_METRICS_STORED_KEY as usize
        );
    }
}
