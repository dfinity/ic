use super::*;
use crate::pb::v1::{NodeMetrics, SubnetIdKey, SubnetMetricsKey, SubnetMetricsValue};
use chrono::NaiveDate;
use ic_base_types::PrincipalId;
use ic_stable_structures::storable::Bound;
use ic_stable_structures_0_6::memory_manager::{
    MemoryId as MemoryId0_6, MemoryManager as MemoryManager0_6,
};
use ic_stable_structures_0_6::{BTreeMap as BTreeMap0_6, Cell as Cell0_6};
use std::borrow::Cow;
use std::ops::Range;

/// Stores a `T` through ic-stable-structures 0.6, using `T`'s own `Storable` encoding. Only types
/// that implement their own encoding are wrapped: `u64` and `Option<_>` use 0.6's implementation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct V0_6<T>(T);

impl<T: Storable> ic_stable_structures_0_6::Storable for V0_6<T> {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(T::from_bytes(bytes))
    }

    const BOUND: ic_stable_structures_0_6::storable::Bound = match T::BOUND {
        Bound::Unbounded => ic_stable_structures_0_6::storable::Bound::Unbounded,
        Bound::Bounded {
            max_size,
            is_fixed_size,
        } => ic_stable_structures_0_6::storable::Bound::Bounded {
            max_size,
            is_fixed_size,
        },
    };
}

/// A registry record as (key, version, timestamp, value).
type RegistryRecord = (String, u64, u64, Option<Vec<u8>>);

/// Records for the given versions, in key order. Their keys interleave, some are deletions, and
/// some values span several pages.
fn registry_records(versions: Range<u64>) -> Vec<RegistryRecord> {
    let mut records: Vec<RegistryRecord> = versions
        .map(|version| {
            let value = match version % 4 {
                0 => None,
                1 => Some(vec![version as u8; 3_000]),
                _ => Some(vec![version as u8; version as usize]),
            };
            (format!("key_{}", version % 5), version, 10 * version, value)
        })
        .collect();
    records.sort();
    records
}

fn metrics_key(timestamp_nanos: u64) -> SubnetMetricsKey {
    SubnetMetricsKey {
        timestamp_nanos,
        subnet_id: Some(PrincipalId::new_subnet_test_id(1)),
    }
}

fn metrics_value(num_blocks_proposed_total: u64) -> SubnetMetricsValue {
    SubnetMetricsValue {
        nodes_metrics: vec![NodeMetrics {
            node_id: Some(PrincipalId::new_node_test_id(1)),
            num_blocks_proposed_total,
            num_blocks_failed_total: 2,
        }],
    }
}

// The canister's stable memory has the same layout with ic-stable-structures 0.6 and 0.7: each
// version reads what the other one wrote.
#[test]
fn stable_memory_is_compatible_with_ic_stable_structures_0_6() {
    let subnet_key = SubnetIdKey {
        subnet_id: Some(PrincipalId::new_subnet_test_id(1)),
    };
    let day_1 = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let day_2 = NaiveDate::from_ymd_opt(2025, 1, 2).unwrap();
    let memory = DefaultMemoryImpl::default();

    // Write with 0.6, at the memory IDs the canister uses.
    {
        let mm = MemoryManager0_6::init(memory.clone());
        // `StorableRegistryValue` is encoded as the `Option<Vec<u8>>` it wraps.
        let mut registry: BTreeMap0_6<V0_6<StorableRegistryKey>, Option<Vec<u8>>, _> =
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(0)));
        for (key, version, timestamp, value) in registry_records(0..40) {
            registry.insert(
                V0_6(StorableRegistryKey::new(key, version, timestamp)),
                value,
            );
        }
        BTreeMap0_6::init(mm.get(MemoryId0_6::new(1)))
            .insert(V0_6(metrics_key(100)), V0_6(metrics_value(5)));
        BTreeMap0_6::init(mm.get(MemoryId0_6::new(2))).insert(V0_6(subnet_key.clone()), 100_u64);
        Cell0_6::init(mm.get(MemoryId0_6::new(3)), None)
            .unwrap()
            .set(Some(V0_6(NaiveDateStorable(day_1))))
            .unwrap();
    }

    // Read and extend with 0.7, as the canister does.
    {
        let mm = MemoryManager::init(memory.clone());
        let mut registry: StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM> =
            StableBTreeMap::init(mm.get(REGISTRY_STORE_MEMORY_ID));
        let mut subnets_metrics: StableBTreeMap<SubnetMetricsKey, SubnetMetricsValue, VM> =
            StableBTreeMap::init(mm.get(SUBNETS_METRICS_MEMORY_ID));
        let mut last_timestamp_per_subnet: StableBTreeMap<SubnetIdKey, u64, VM> =
            StableBTreeMap::init(mm.get(LAST_TIMESTAMP_PER_SUBNET_MEMORY_ID));
        let mut last_day_synced: StableCell<Option<NaiveDateStorable>, VM> =
            StableCell::init(mm.get(LAST_DAY_SYNCED_MEMORY_ID), None);

        assert_eq!(
            registry
                .iter()
                .map(|entry| {
                    let (key, value) = entry.into_pair();
                    (key.key, key.version, key.timestamp_nanoseconds, value.0)
                })
                .collect::<Vec<_>>(),
            registry_records(0..40)
        );
        assert_eq!(
            subnets_metrics
                .iter()
                .map(|entry| entry.into_pair())
                .collect::<Vec<_>>(),
            vec![(metrics_key(100), metrics_value(5))]
        );
        assert_eq!(
            last_timestamp_per_subnet
                .iter()
                .map(|entry| entry.into_pair())
                .collect::<Vec<_>>(),
            vec![(subnet_key.clone(), 100)]
        );
        assert_eq!(last_day_synced.get().as_ref().map(|d| d.0), Some(day_1));

        for (key, version, timestamp, value) in registry_records(40..80) {
            registry.insert(
                StorableRegistryKey::new(key, version, timestamp),
                StorableRegistryValue(value),
            );
        }
        subnets_metrics.insert(metrics_key(200), metrics_value(6));
        last_timestamp_per_subnet.insert(subnet_key.clone(), 200);
        last_day_synced.set(Some(NaiveDateStorable(day_2)));
    }

    // Read with 0.6 what 0.7 wrote.
    let mm = MemoryManager0_6::init(memory);
    let registry: BTreeMap0_6<V0_6<StorableRegistryKey>, Option<Vec<u8>>, _> =
        BTreeMap0_6::init(mm.get(MemoryId0_6::new(0)));
    assert_eq!(
        registry
            .iter()
            .map(|(key, value)| (key.0.key, key.0.version, key.0.timestamp_nanoseconds, value))
            .collect::<Vec<_>>(),
        registry_records(0..80)
    );
    let subnets_metrics: BTreeMap0_6<V0_6<SubnetMetricsKey>, V0_6<SubnetMetricsValue>, _> =
        BTreeMap0_6::init(mm.get(MemoryId0_6::new(1)));
    assert_eq!(
        subnets_metrics
            .iter()
            .map(|(key, value)| (key.0, value.0))
            .collect::<Vec<_>>(),
        vec![
            (metrics_key(100), metrics_value(5)),
            (metrics_key(200), metrics_value(6)),
        ]
    );
    let last_timestamp_per_subnet: BTreeMap0_6<V0_6<SubnetIdKey>, u64, _> =
        BTreeMap0_6::init(mm.get(MemoryId0_6::new(2)));
    assert_eq!(
        last_timestamp_per_subnet
            .iter()
            .map(|(key, value)| (key.0, value))
            .collect::<Vec<_>>(),
        vec![(subnet_key, 200)]
    );
    let last_day_synced: Cell0_6<Option<V0_6<NaiveDateStorable>>, _> =
        Cell0_6::init(mm.get(MemoryId0_6::new(3)), None).unwrap();
    assert_eq!(last_day_synced.get().as_ref().map(|d| d.0.0), Some(day_2));
}
