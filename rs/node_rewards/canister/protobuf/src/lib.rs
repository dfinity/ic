use candid::Principal;
use ic_base_types::PrincipalId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use prost::Message;
use rewards_calculation::types::DayUtc;
use serde::{Serialize, Serializer};
use std::borrow::Cow;

pub mod conversions;
pub mod pb;

// Maximum sizes for the storable types chosen as result of test `max_bound_size`
const MAX_BYTES_SUBNET_ID_STORED: u32 = 33;
const MAX_BYTES_NODE_METRICS_STORED_KEY: u32 = 44;
const PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;

pub const MIN_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(&[]));
pub const MAX_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(
    &[0xFF_u8; PRINCIPAL_MAX_LENGTH_IN_BYTES],
));

impl Serialize for pb::rewards_calculator::v1::DayUtc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(v) = self.value {
            let date_str = DayUtc::from(v).to_string();
            serializer.serialize_str(&date_str)
        } else {
            serializer.serialize_none()
        }
    }
}

pub trait KeyRange {
    fn min_key() -> Self;
    fn max_key() -> Self;
}

impl KeyRange for pb::ic_node_rewards::v1::SubnetMetricsKey {
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

impl Storable for pb::ic_node_rewards::v1::SubnetIdKey {
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

impl Storable for pb::ic_node_rewards::v1::SubnetMetricsKey {
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

impl Storable for pb::ic_node_rewards::v1::SubnetMetricsValue {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::ic_node_rewards::v1::NodeMetrics {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::rewards_calculator::v1::NodeProviderRewards {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::rewards_calculator::v1::NodeProviderRewardsKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::rewards_calculator::v1::SubnetsFailureRateKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(self.encode_to_vec())
    }
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self::decode(bytes.as_ref()).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for pb::rewards_calculator::v1::SubnetsFailureRateValue {
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
        let max_subnet_id_stored = pb::ic_node_rewards::v1::SubnetIdKey {
            subnet_id: MAX_PRINCIPAL_ID.into(),
        };
        let max_subnet_metrics_stored_key = pb::ic_node_rewards::v1::SubnetMetricsKey {
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
