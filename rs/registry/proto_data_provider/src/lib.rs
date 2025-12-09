use bytes::{Buf, BufMut};
use ic_interfaces_registry::{RegistryDataProvider, RegistryRecord, RegistryValue};
use ic_registry_common_proto::pb::proto_registry::v1::{ProtoRegistry, ProtoRegistryRecord};
use ic_registry_transport::pb::v1::registry_mutation::Type;
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use ic_registry_transport::upsert;
use ic_sys::fs::{Clobber, write_atomically};
use ic_types::{RegistryVersion, registry::RegistryDataProviderError};
use std::collections::HashMap;
use std::{
    io::Write,
    path::Path,
    sync::{Arc, RwLock},
};
use thiserror::Error;

pub const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

#[derive(Clone)]
pub struct ProtoRegistryDataProvider {
    records: Arc<RwLock<Vec<ProtoRegistryRecord>>>,
}

#[derive(Clone, Debug, Error)]
pub enum ProtoRegistryDataProviderError {
    #[error("key {key} already exists at version {version}")]
    KeyAlreadyExists {
        key: String,
        version: RegistryVersion,
    },
}

/// A simple RegistryDataProvider that can be used for tests and loading/storing
/// from/to a file.
impl ProtoRegistryDataProvider {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn is_empty(&self) -> bool {
        self.records.read().unwrap().is_empty()
    }

    pub fn add<T>(
        &self,
        key: &str,
        version: RegistryVersion,
        value: Option<T>,
    ) -> Result<(), ProtoRegistryDataProviderError>
    where
        T: RegistryValue,
    {
        assert!(version.get() > 0);
        let mut records = self.records.write().unwrap();

        let search_key = &(&version.get(), key);
        match records.binary_search_by_key(search_key, |r| (&r.version, &r.key)) {
            Ok(_) => Err(ProtoRegistryDataProviderError::KeyAlreadyExists {
                key: key.to_string(),
                version,
            }),
            Err(idx) => {
                let record = ProtoRegistryRecord {
                    key: key.to_string(),
                    version: version.get(),
                    value: value.map(|v| {
                        let mut buf: Vec<u8> = vec![];
                        v.encode(&mut buf)
                            .expect("can't fail, encoding is infallible");
                        buf
                    }),
                };
                records.insert(idx, record);
                Ok(())
            }
        }
    }

    /// Writes mutations to the initial Registry
    pub fn add_mutations(
        &self,
        mutations: Vec<RegistryMutation>,
    ) -> Result<(), ProtoRegistryDataProviderError> {
        let mut records = self.records.write().unwrap();
        let version = INITIAL_REGISTRY_VERSION;

        for mutation in mutations {
            let key = std::str::from_utf8(&mutation.key)
                .expect("Expected registry key to be utf8-encoded");

            let search_key = &(&version.get(), key);

            match records.binary_search_by_key(search_key, |r| (&r.version, &r.key)) {
                Ok(_) => {
                    return Err(ProtoRegistryDataProviderError::KeyAlreadyExists {
                        key: key.to_string(),
                        version,
                    });
                }
                Err(idx) => {
                    let record = ProtoRegistryRecord {
                        key: key.to_string(),
                        version: version.get(),
                        value: Some(mutation.value),
                    };
                    records.insert(idx, record);
                }
            }
        }

        Ok(())
    }

    pub fn decode<B: Buf>(buf: B) -> Self {
        Self::try_decode(buf).unwrap()
    }

    pub fn try_decode<B: Buf>(buf: B) -> Result<Self, String> {
        let registry = ProtoRegistry::decode(buf)
            .map_err(|err| format!("Could not decode protobuf registry: {}", err))?;

        Ok(Self {
            records: Arc::new(RwLock::new(registry.records)),
        })
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        let protobuf_registry = ProtoRegistry {
            records: self.records.read().unwrap().clone(),
        };
        protobuf_registry
            .encode(buf)
            .expect("Could not encode protobuf registry.");
    }

    pub fn load_from_file<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        let buf = std::fs::read(path.as_ref()).unwrap_or_else(|e| {
            panic!(
                "Could not read protobuf registry file at {:?}: {}",
                path.as_ref().to_str(),
                e
            )
        });
        Self::decode(buf.as_ref())
    }

    /// Write the state of this data provider to a file at `path`.
    pub fn write_to_file<P>(&self, path: P)
    where
        P: AsRef<Path>,
    {
        write_atomically(path, Clobber::Yes, |f| {
            let mut buf: Vec<u8> = vec![];
            self.encode(&mut buf);
            f.write_all(buf.as_slice())
        })
        .expect("Could not write to path.");
    }

    /// Useful to sync from other mutations
    pub fn apply_mutations_as_version(
        &self,
        mut mutations: Vec<RegistryMutation>,
        version: RegistryVersion,
    ) {
        let mut records = self.records.write().unwrap();

        mutations.sort_by(|l, r| l.key.cmp(&r.key));
        for m in mutations.iter_mut() {
            m.mutation_type = match Type::try_from(m.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => Type::Upsert,
                Type::Delete => {
                    unimplemented!("Need to implement Delete below to execute these mutations")
                }
            } as i32;
        }

        for mutation in mutations {
            let key = std::str::from_utf8(&mutation.key)
                .expect("Expected registry key to be utf8-encoded");

            let search_key = &(&version.get(), key);

            match records.binary_search_by_key(search_key, |r| (&r.version, &r.key)) {
                Ok(_) => {
                    panic!("Not sure this should happen in test context...");
                }
                Err(idx) => {
                    let record = ProtoRegistryRecord {
                        key: key.to_string(),
                        version: version.get(),
                        value: Some(mutation.value),
                    };
                    records.insert(idx, record);
                }
            }
        }
    }

    pub fn add_registry_records(&self, mut new_records: Vec<RegistryRecord>) {
        let mut records = self.records.write().unwrap();

        new_records.sort_by(|l, r| l.key.cmp(&r.key));

        for record in new_records {
            let search_key = &(&record.version.get(), &record.key);

            match records.binary_search_by_key(search_key, |r| (&r.version, &r.key)) {
                Ok(_) => {
                    panic!(
                        "A record for the same key {} already exists at the same version {}.",
                        record.key, record.version
                    );
                }
                Err(idx) => {
                    let record = ProtoRegistryRecord {
                        key: record.key,
                        version: record.version.get(),
                        value: record.value,
                    };
                    records.insert(idx, record);
                }
            }
        }
    }

    /// Useful to sync a new registry test instance with records from a fake data provider.
    pub fn export_versions_as_atomic_mutation_requests(&self) -> Vec<RegistryAtomicMutateRequest> {
        let mut records = self.records.read().unwrap().clone();
        records.sort_by(|a, b| Ord::cmp(&a.version, &b.version));
        let mut mutations_by_version: HashMap<u64, Vec<RegistryMutation>> = HashMap::new();

        for record in records {
            let version = record.version;
            let mutation = upsert(record.key, record.value.or_else(|| Some(vec![])).unwrap());

            if let Some(mutations_vec) = mutations_by_version.get_mut(&version) {
                mutations_vec.push(mutation);
            } else {
                let mutations = vec![mutation];
                mutations_by_version.insert(version, mutations);
            }
        }

        let mut mutations_by_version = mutations_by_version.iter().collect::<Vec<_>>();

        mutations_by_version.sort_by_key(|x| x.0);

        mutations_by_version
            .iter()
            .map(|(_, mutations)| RegistryAtomicMutateRequest {
                mutations: mutations.to_vec(),
                preconditions: vec![],
            })
            .collect()
    }

    /// Useful to determine level to apply mutations
    pub fn latest_version(&self) -> RegistryVersion {
        let records = self.records.read().unwrap().clone();
        let latest_version = records.iter().map(|x| x.version).max().unwrap();
        RegistryVersion::from(latest_version)
    }
}

impl Default for ProtoRegistryDataProvider {
    fn default() -> Self {
        Self {
            records: Arc::new(RwLock::new(vec![])),
        }
    }
}

impl RegistryDataProvider for ProtoRegistryDataProvider {
    /// This function only accesses internal state which is assumed to be valid,
    /// so it may neither panic nor return an error.
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        let records = self.records.read().unwrap();

        let records = records
            .iter()
            .filter(|r| r.version > version.get())
            .map(|r| RegistryRecord {
                key: r.key.clone(),
                version: RegistryVersion::new(r.version),
                value: r.value.to_owned(),
            })
            .collect();

        Ok(records)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
