use crate::pb::v1::{
    NodeMetricsDailyStored, SubnetIdKey, SubnetMetricsDailyKeyStored, SubnetMetricsDailyValueStored,
};
use candid::Principal;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::Storable;
use prost::Message;
use rewards_calculation::types::{NodeMetricsDailyRaw, SubnetMetricsDailyKey};
use std::borrow::Cow;

pub mod pb;

// Maximum sizes for the storable types chosen as result of test `max_bound_size`
const MAX_BYTES_SUBNET_ID_STORED: u32 = 33;
const MAX_BYTES_NODE_METRICS_STORED_KEY: u32 = 44;
const PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;

pub const MIN_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(&[]));
pub const MAX_PRINCIPAL_ID: PrincipalId = PrincipalId(Principal::from_slice(
    &[0xFF_u8; PRINCIPAL_MAX_LENGTH_IN_BYTES],
));

#[test]
fn max_bound_size() {
    let max_subnet_id_stored = SubnetIdKey {
        subnet_id: MAX_PRINCIPAL_ID.into(),
    };
    let max_subnet_metrics_stored_key = SubnetMetricsDailyKeyStored {
        ts: u64::MAX,
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

impl Storable for SubnetIdKey {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Cow::Owned(buf)
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

impl From<SubnetMetricsDailyKeyStored> for SubnetMetricsDailyKey {
    fn from(key: SubnetMetricsDailyKeyStored) -> Self {
        Self {
            day: key.ts.into(),
            subnet_id: SubnetId::from(key.subnet_id.unwrap()),
        }
    }
}

impl Storable for SubnetMetricsDailyKeyStored {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        SubnetMetricsDailyKeyStored::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_BYTES_NODE_METRICS_STORED_KEY,
        is_fixed_size: false,
    };
}

impl KeyRange for SubnetMetricsDailyKeyStored {
    fn min_key() -> Self {
        Self {
            ts: u64::MIN,
            subnet_id: Some(MIN_PRINCIPAL_ID),
        }
    }

    fn max_key() -> Self {
        Self {
            ts: u64::MAX,
            subnet_id: Some(MAX_PRINCIPAL_ID),
        }
    }
}

impl From<NodeMetricsDailyStored> for NodeMetricsDailyRaw {
    fn from(node_metrics: NodeMetricsDailyStored) -> Self {
        Self {
            node_id: NodeId::from(node_metrics.node_id.unwrap()),
            num_blocks_proposed: node_metrics.num_blocks_proposed,
            num_blocks_failed: node_metrics.num_blocks_failed,
        }
    }
}

impl From<SubnetMetricsDailyValueStored> for Vec<NodeMetricsDailyRaw> {
    fn from(subnet_metrics: SubnetMetricsDailyValueStored) -> Self {
        subnet_metrics
            .nodes_metrics
            .into_iter()
            .map(NodeMetricsDailyRaw::from)
            .collect()
    }
}

impl Storable for SubnetMetricsDailyValueStored {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf).unwrap();
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        SubnetMetricsDailyValueStored::decode(bytes.as_ref()).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}
