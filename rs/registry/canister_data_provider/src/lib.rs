use candid::Principal;
use ic_cdk::println;
use ic_interfaces_registry::{
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_common_proto::pb::proto_registry::v1::ProtoRegistryRecord;
use ic_registry_nns_data_provider::registry::registry_deltas_to_registry_transport_records;
use ic_registry_transport::{
    deserialize_get_changes_since_response, serialize_get_changes_since_request,
};
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableVec, Storable};
use ic_types::registry::RegistryDataProviderError;
use ic_types::RegistryVersion;
use itertools::Itertools;
use prost::Message;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::marker::PhantomData;

const BYTE: u32 = 1;
const KB: u32 = 1024 * BYTE;

pub struct StorableRegistryRecord(ProtoRegistryRecord);

impl Storable for StorableRegistryRecord {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.0.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(ProtoRegistryRecord::decode(&bytes[..]).unwrap())
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: KB,
        is_fixed_size: false,
    };
}
type Memory = VirtualMemory<DefaultMemoryImpl>;

pub trait StableVecBorrower: Send + Sync {
    fn with_borrow<R>(f: impl FnOnce(&StableVec<StorableRegistryRecord, Memory>) -> R) -> R;
    fn with_borrow_mut<R>(f: impl FnOnce(&mut StableVec<StorableRegistryRecord, Memory>) -> R)
        -> R;
}
pub struct StableRegistryDataProvider<S: StableVecBorrower> {
    keys_to_retain: Option<HashSet<String>>,
    _store: PhantomData<S>,
}

impl<S: StableVecBorrower> StableRegistryDataProvider<S> {
    pub fn new(keys_to_retain: Option<HashSet<String>>) -> Self {
        Self {
            keys_to_retain,
            _store: PhantomData,
        }
    }

    async fn get_changes_since(
        &self,
        version: u64,
    ) -> anyhow::Result<Vec<RegistryTransportRecord>> {
        let buff = serialize_get_changes_since_request(version)?;
        let response = ic_cdk::api::call::call_raw(
            Principal::from(REGISTRY_CANISTER_ID),
            "get_changes_since",
            buff,
            0,
        )
        .await
        .unwrap();
        let (registry_delta, _) = deserialize_get_changes_since_response(response).unwrap();
        let registry_transport_record =
            registry_deltas_to_registry_transport_records(registry_delta)?;
        Ok(registry_transport_record)
    }

    pub async fn sync_registry_stored(&self) -> anyhow::Result<()> {
        let mut update_registry_version = self
            .get_local_version()
            .unwrap_or(ZERO_REGISTRY_VERSION.get());

        loop {
            let remote_latest_version = ic_nns_common::registry::get_latest_version().await;

            println!(
                "local version: {} remote version: {}",
                update_registry_version, remote_latest_version
            );

            match update_registry_version.cmp(&remote_latest_version) {
                Ordering::Less => {
                    println!(
                        "Registry version local {} < remote {}",
                        update_registry_version, remote_latest_version
                    );
                }
                Ordering::Equal => {
                    println!(
                        "Local Registry version {} is up to date",
                        update_registry_version
                    );
                    break;
                }
                Ordering::Greater => {
                    let message = format!(
                        "Registry version local {} > remote {}, this should never happen",
                        update_registry_version, remote_latest_version
                    );

                    ic_cdk::trap(message.as_str());
                }
            }

            if let Ok(mut registry_records) = self.get_changes_since(update_registry_version).await
            {
                registry_records.sort_by_key(|tr| tr.version);

                update_registry_version = registry_records
                    .last()
                    .map(|record| record.version.get())
                    .unwrap();

                registry_records.into_iter().for_each(|record| {
                    if let Some(keys) = &self.keys_to_retain {
                        if keys
                            .iter()
                            .any(|prefix| record.key.starts_with(prefix.as_str()))
                        {
                            self.insert_record(ProtoRegistryRecord {
                                key: record.key,
                                version: record.version.get(),
                                value: record.value,
                            });
                        }
                    }
                });
            }
        }
        Ok(())
    }

    fn insert_record(&self, record: ProtoRegistryRecord) {
        S::with_borrow_mut(|local_registry| {
            local_registry
                .push(&StorableRegistryRecord(record))
                .unwrap();
        })
    }

    fn get_local_version(&self) -> Option<u64> {
        S::with_borrow(|local_registry| {
            local_registry
                .iter()
                .last()
                .map(|last_record| last_record.0.version)
        })
    }
}

impl<S: StableVecBorrower> RegistryDataProvider for StableRegistryDataProvider<S> {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        S::with_borrow(|local_registry| {
            let since_version = version.get();
            let updates = local_registry
                .iter()
                .filter(|record| record.0.version > since_version)
                .map(|record| RegistryTransportRecord {
                    version: RegistryVersion::from(record.0.version),
                    key: record.0.key,
                    value: record.0.value,
                })
                .collect_vec();

            Ok(updates)
        })
    }
}
