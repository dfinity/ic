// Goals for canister shape
// 1. easy to unit test (avoid things that can only be tested in WASM32 statemachine)
// 2. Simple structures
// 3. Good API boundaries (nothing on the inside gets out)
// 4. Structure makes boundaries clear and easy to enforce
// 5. Simple Organization

use crate::pb::v1::{
    NodeMetrics as NodeMetricsProto, SubnetIdKey, SubnetMetricsKey, SubnetMetricsValue,
};
use candid::Principal;
use ic_base_types::{PrincipalId, SubnetId};
use ic_management_canister_types::NodeMetrics;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use prost::Message;
use rewards_calculation::types::SubnetMetricsDailyKey;
use std::borrow::Cow;

pub mod canister;
pub mod metrics;
pub mod pb;
pub mod registry_querier;
pub mod storage;

// Maximum sizes for the storable types chosen as result of test `max_bound_size`
const MAX_BYTES_SUBNET_ID_STORED: u32 = 33;
const MAX_BYTES_NODE_METRICS_STORED_KEY: u32 = 44;
const PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;

pub const MIN_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(&[]));
pub const MAX_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(
    &[0xFF_u8; PRINCIPAL_MAX_LENGTH_IN_BYTES],
));

impl From<NodeMetrics> for NodeMetricsProto {
    fn from(metrics: NodeMetrics) -> Self {
        NodeMetricsProto {
            node_id: Some(metrics.node_id.into()),
            num_blocks_proposed_total: metrics.num_blocks_proposed_total,
            num_blocks_failed_total: metrics.num_block_failures_total,
        }
    }
}

impl Storable for SubnetIdKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        SubnetIdKey::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_BYTES_SUBNET_ID_STORED,
        is_fixed_size: false,
    };
}

impl From<SubnetId> for SubnetIdKey {
    fn from(subnet_id: SubnetId) -> Self {
        Self {
            subnet_id: Some(subnet_id.get()),
        }
    }
}

impl From<SubnetIdKey> for SubnetId {
    fn from(subnet_id: SubnetIdKey) -> Self {
        subnet_id.subnet_id.unwrap().into()
    }
}

pub trait KeyRange {
    fn min_key() -> Self;
    fn max_key() -> Self;
}

impl From<SubnetMetricsKey> for SubnetMetricsDailyKey {
    fn from(key: SubnetMetricsKey) -> Self {
        Self {
            day: key.timestamp_nanos.into(),
            subnet_id: SubnetId::from(key.subnet_id.unwrap()),
        }
    }
}

impl Storable for SubnetMetricsKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        SubnetMetricsKey::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 2 * MAX_BYTES_NODE_METRICS_STORED_KEY,
        is_fixed_size: false,
    };
}

impl KeyRange for SubnetMetricsKey {
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

impl Storable for SubnetMetricsValue {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        SubnetMetricsValue::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn max_bound_size() {
        let max_subnet_id_stored = SubnetIdKey {
            subnet_id: MAX_PRINCIPAL_ID.into(),
        };
        let max_subnet_metrics_stored_key = SubnetMetricsKey {
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
