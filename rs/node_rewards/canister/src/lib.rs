// Goals for canister shape
// 1. easy to unit test (avoid things that can only be tested in WASM32 statemachine)
// 2. Simple structures
// 3. Good API boundaries (nothing on the inside gets out)
// 4. Structure makes boundaries clear and easy to enforce
// 5. Simple Organization

use crate::storage::NaiveDateStorable;
use candid::Principal;
use chrono::{Datelike, NaiveDate};
use ic_base_types::{PrincipalId, SubnetId};
use ic_management_canister_types::NodeMetrics;
use ic_stable_structures::Storable;
use ic_stable_structures::storable::Bound;
use prost::Message;
use std::borrow::Cow;

pub mod canister;
mod chrono_utils;
pub mod metrics;
pub mod pb;
pub mod registry_querier;
pub mod storage;
pub mod telemetry;
pub mod timer_tasks;

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

//------------ Storable Implementations ------------//

impl Storable for NaiveDateStorable {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        // We'll store it as a 32-bit integer: number of days since a fixed epoch.
        // NaiveDate stores dates internally as (year, ordinal_day), but we can easily
        // reconstruct it from a serializable integer.
        let days = self.0.num_days_from_ce();
        Cow::Owned(days.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        let days = i32::from_be_bytes(arr);
        Self(NaiveDate::from_num_days_from_ce_opt(days).unwrap())
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 4,
        is_fixed_size: true,
    };
}

impl Storable for pb::v1::SubnetIdKey {
    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
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

impl Storable for pb::v1::SubnetMetricsKey {
    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
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
    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::v1::NodeMetrics {
    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
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
