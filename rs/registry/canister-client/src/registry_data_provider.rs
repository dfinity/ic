use std::borrow::Cow;
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::{DefaultMemoryImpl, StableVec, Storable};
use std::cell::RefCell;
use ic_stable_structures::storable::Bound;
use ic_registry_common_proto::pb::proto_registry::v1::ProtoRegistryRecord;
use crate::current_time;

type Memory = VirtualMemory<DefaultMemoryImpl>;


pub struct StorableRegistryRecord(ProtoRegistryRecord);
impl Storable for StorableRegistryRecord {
    fn to_bytes(&self) -> Cow<[u8]> {
        current_time()
        todo!()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        todo!()
    }

    const BOUND: Bound = Bound::Unbounded;
}
struct StableMemoryStore {
    records: RefCell<StableVec<ProtoRegistryRecord, Memory>>,
}
impl StableMemoryStore {
    fn insert_registry_record(&self, key: RegistryKey, value: Option<Vec<u8>>) {
        stable_memory::REGISTRY_STORED
            .with_borrow_mut(|registry_stored| registry_stored.insert(key, value));
    }

    fn insert_registry_version(&self, ts: u64, version: u64) {
        stable_memory::TS_REGISTRY_VERSIONS
            .with_borrow_mut(|versions| versions.insert(ts, version));
    }

    fn get_registry_versions(&self, start_ts: u64, end_ts: u64) -> Vec<u64> {
        stable_memory::TS_REGISTRY_VERSIONS.with_borrow(|versions| {
            versions
                .range(start_ts..=end_ts)
                .map(|(_, version)| version)
                .collect_vec()
        })
    }

    fn new() -> Self {
        Self
    }
}

impl RegistryDataProvider for StableMemoryStore {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        stable_memory::REGISTRY_STORED.with_borrow(|local_registry| {
            let next_version = version.get() + 1;
            let changelog = local_registry
                .range(
                    RegistryKey {
                        version: next_version,
                        key: MIN_STRING.clone(),
                    }..,
                )
                .collect_vec();

            let res: Vec<_> = changelog
                .iter()
                .map(
                    |(RegistryKey { version, key }, value)| RegistryTransportRecord {
                        version: RegistryVersion::from(*version),
                        key: key.clone(),
                        value: value.clone(),
                    },
                )
                .collect();
            Ok(res)
        })
    }
}
