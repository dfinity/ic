//! Access a local store through the standard `RegistryClient` trait. Hides the
//! complexities of syncing the local store with the NNS registry behind a
//! simple function call. Control over when the synchronization happens is left
//! to the user of `LocalRegistry`.
//!
//! # (Minor) Limitations
//!
//! Concurrently calling `sync_with_nns` might result in reordered updates to
//! the certified time stored in the local store. However, the certified time is
//! not exposed through the interface of `LocalRegistry`.

use std::{
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};

use ic_interfaces::registry::{RegistryClient, RegistryClientResult, ZERO_REGISTRY_VERSION};
use ic_protobuf::registry::node::v1::ConnectionEndpoint as PbConnectionEndpoint;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_common::local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_common::registry::RegistryCanister;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, registry::RegistryClientError, RegistryVersion,
    SubnetId,
};
use thiserror::Error;
use url::Url;

use ic_registry_client_helpers::{
    crypto::CryptoRegistry,
    subnet::{SubnetRegistry, SubnetTransportRegistry},
};

pub struct LocalRegistry {
    registry_cache: FakeRegistryClient,
    local_store_writer: LocalStoreImpl,
    // The `RegistryCanister` maintains one agent per available public endpoint
    // of the root subnet and each agent maintains a connection pool underneath.
    // We thus only update the registry canister when either the URLs or the
    // threshold public key of the root subnet changes.
    cached_registry_canister: RwLock<(RootSubnetInfo, RegistryCanister)>,
    query_timeout: Duration,
    tokio_runtime: tokio::runtime::Runtime,
}

impl LocalRegistry {
    /// Create a new instance of `LocalRegistry`.
    ///
    /// `local_store_path` is the path to the directory containing the local
    /// copy of the registry that this `LocalRegistry` maintains.
    ///
    /// `query_timeout` is the timeout that is used when querying the NNS
    /// canister.
    ///
    /// A new tokio-runtime is created to handle asynchronous code paths.
    ///
    /// # Panics
    ///
    /// This method panics if a tokio-runtime cannot be created.
    pub fn new<P: AsRef<Path>>(
        local_store_path: P,
        query_timeout: Duration,
    ) -> Result<Self, LocalRegistryError> {
        let tokio_runtime =
            tokio::runtime::Runtime::new().expect("Could not instantiate tokio runtime");
        Self::new_with_runtime(local_store_path, query_timeout, tokio_runtime)
    }

    /// Same as [new].
    ///
    /// `tokio_runtime` will be used to handle asynchronous code paths.
    pub fn new_with_runtime<P: AsRef<Path>>(
        local_store_path: P,
        query_timeout: Duration,
        tokio_runtime: tokio::runtime::Runtime,
    ) -> Result<Self, LocalRegistryError> {
        let local_store_reader = Arc::new(LocalStoreImpl::new(local_store_path.as_ref()));
        let local_store_writer = LocalStoreImpl::new(local_store_path.as_ref());
        let registry_cache = FakeRegistryClient::new(local_store_reader);

        registry_cache.update_to_latest_version();
        let latest_version = registry_cache.get_latest_version();
        let urls_and_pubkey = Self::get_root_subnet_info(&registry_cache, latest_version)?;
        let root_subnet_info = RootSubnetInfo {
            registry_version: latest_version,
            urls_and_pubkey: urls_and_pubkey.clone(),
        };
        let registry_canister =
            RegistryCanister::new_with_query_timeout(urls_and_pubkey.0, query_timeout);
        let cached_registry_canister = RwLock::new((root_subnet_info, registry_canister));

        Ok(Self {
            registry_cache,
            local_store_writer,
            cached_registry_canister,
            query_timeout,
            tokio_runtime,
        })
    }

    /// Synchronizes the local store with the NNS registry. The URLs and the
    /// public key of the NNS are read from the in-memory cache.
    ///
    /// *Note*: If called concurrently, updates to the certified time might be
    /// stored out of order.
    pub fn sync_with_nns(&self) -> Result<(), LocalRegistryError> {
        // The changelog entry for a given registry version never changes. As
        // the local store overwrites existing versions atomically, it follows
        // that even if multiple threads call this function concurrently,
        // invariants are retained.
        let latest_cached_version = self.registry_cache.get_latest_version();
        let (mut raw_changelog, certified_time) = {
            let guard = self.cached_registry_canister.read().unwrap();
            let (raw_changelog, _, t) = self
                .tokio_runtime
                .block_on(guard.1.get_certified_changes_since(
                    latest_cached_version.get(),
                    &guard.0.urls_and_pubkey.1,
                ))
                .map_err(LocalRegistryError::from)?;
            (raw_changelog, t)
        };
        // Persist changelog
        raw_changelog.sort_by_key(|tr| tr.version);
        let changelog = raw_changelog
            .iter()
            .fold(Changelog::default(), |mut cl, r| {
                let rel_version = (r.version - latest_cached_version).get();
                if cl.len() < rel_version as usize {
                    cl.push(ChangelogEntry::default());
                }
                cl.last_mut().unwrap().push(KeyMutation {
                    key: r.key.clone(),
                    value: r.value.clone(),
                });
                cl
            });
        changelog
            .into_iter()
            .enumerate()
            .try_for_each(|(i, cle)| {
                let v = latest_cached_version + RegistryVersion::from(i as u64 + 1);
                self.local_store_writer.store(v, cle)
            })
            .expect("Writing to the FS failed: Stop.");

        // update certified time
        self.local_store_writer
            .update_certified_time(certified_time.as_nanos_since_unix_epoch())
            .expect("Could not store certified time");
        self.sync_with_local_store()
    }

    /// Updates the in-memory cache with the current state of the local store.
    ///
    /// Note that the in-memory cache ignores the state of the local store
    /// unless this method is called.
    pub fn sync_with_local_store(&self) -> Result<(), LocalRegistryError> {
        // update cache to reflect state of the local store
        self.registry_cache.update_to_latest_version();
        let latest_version = self.registry_cache.get_latest_version();
        {
            // the write lock guarantees that updates to the registry canister
            // are ordered across all threads
            let mut guard = self.cached_registry_canister.write().unwrap();
            // invariant: the registry version of the memoized urls grows monotonically.
            // Thus, this is robust wrt. concurrent updates to the cache that
            // might have happend before we obtained the lock.
            if guard.0.registry_version < latest_version {
                let urls_and_pubkey =
                    Self::get_root_subnet_info(&self.registry_cache, latest_version)?;
                // if the root subnet topology has actually changed, we'll
                // recreate the registry canister
                if urls_and_pubkey != guard.0.urls_and_pubkey {
                    guard.1 = RegistryCanister::new_with_query_timeout(
                        urls_and_pubkey.0.clone(),
                        self.query_timeout,
                    );
                    guard.0.urls_and_pubkey = urls_and_pubkey;
                }
                guard.0.registry_version = latest_version;
            }
        }
        Ok(())
    }

    fn get_root_subnet_info(
        reg_client: &dyn RegistryClient,
        registry_version: RegistryVersion,
    ) -> Result<(Vec<Url>, ThresholdSigPublicKey), LocalRegistryError> {
        if registry_version == ZERO_REGISTRY_VERSION {
            return Err(LocalRegistryError::EmptyRegistry);
        }

        let root_subnet_id = registry_result_to_local_registry_error(
            registry_version,
            "get_root_subnet_id",
            reg_client.get_root_subnet_id(registry_version),
        )?;
        let pub_key = registry_result_to_local_registry_error(
            registry_version,
            "get_threshold_signing_public_key_for_subnet",
            reg_client
                .get_threshold_signing_public_key_for_subnet(root_subnet_id, registry_version),
        )?;
        let urls = Self::get_canonical_url_list(reg_client, root_subnet_id, registry_version)?;
        Ok((urls, pub_key))
    }

    fn get_canonical_url_list(
        reg_client: &dyn RegistryClient,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> Result<Vec<Url>, LocalRegistryError> {
        let t_infos = registry_result_to_local_registry_error(
            version,
            "get_subnet_transport_infos",
            reg_client.get_subnet_transport_infos(subnet_id, version),
        )?;
        let mut urls: Vec<Url> = t_infos
            .iter()
            .filter_map(|(_nid, n_record)| {
                n_record.http.as_ref().and_then(Self::http_endpoint_to_url)
            })
            .collect();
        // enforce canonical representation of the list
        urls.sort();
        Ok(urls)
    }

    fn http_endpoint_to_url(http: &PbConnectionEndpoint) -> Option<Url> {
        let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
            Ok(v) if v.is_ipv6() => format!("[{}]", v),
            Ok(v) => v.to_string(),
            Err(_) => http.ip_addr.clone(),
        };

        let url = format!("http://{}:{}/", host_str, http.port);
        Url::parse(&url).ok()
    }
}

impl RegistryClient for LocalRegistry {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> ic_interfaces::registry::RegistryClientVersionedResult<Vec<u8>> {
        self.registry_cache.get_versioned_value(key, version)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        self.registry_cache.get_key_family(key_prefix, version)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.registry_cache.get_latest_version()
    }

    fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<ic_types::Time> {
        self.registry_cache.get_version_timestamp(registry_version)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RootSubnetInfo {
    registry_version: RegistryVersion,
    urls_and_pubkey: (Vec<Url>, ThresholdSigPublicKey),
}

fn registry_result_to_local_registry_error<T>(
    version: RegistryVersion,
    description: &str,
    registry_result: RegistryClientResult<T>,
) -> Result<T, LocalRegistryError> {
    use LocalRegistryError::*;
    match registry_result {
        Ok(Some(v)) => Ok(v),
        Ok(None) => Err(ValueNotPresent {
            description: description.into(),
            version,
        }),
        Err(source) => Err(RegistryClientError {
            description: description.into(),
            version,
            source,
        }),
    }
}

#[derive(Error, Debug)]
pub enum LocalRegistryError {
    #[error("The provided registry is at version 0 (empty)")]
    EmptyRegistry,

    #[error("{description}: Missing value at registry version {version}")]
    ValueNotPresent {
        description: String,
        version: RegistryVersion,
    },

    #[error("{description}: RegistryClient returned at registry version {version}")]
    RegistryClientError {
        description: String,
        version: RegistryVersion,
        source: RegistryClientError,
    },

    #[error("Registry Transport Error")]
    RegistryTransportError {
        #[from]
        source: ic_registry_transport::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use ic_registry_client_helpers::subnet::SubnetListRegistry;
    use ic_registry_common::local_store::compact_delta_to_changelog;
    use ic_types::PrincipalId;
    use tempfile::TempDir;

    const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

    #[test]
    fn can_read_mainnet_data() {
        let (tmpdir, _store) = get_mainnet_delta_00_6d_c1();
        let local_registry = LocalRegistry::new(tmpdir.path(), DEFAULT_QUERY_TIMEOUT)
            .expect("Could not instantiate local registry with mainnet state.");

        let latest_version = local_registry.get_latest_version();
        assert_eq!(latest_version.get(), 0x6dc1);

        let root_subnet_id = local_registry
            .get_root_subnet_id(latest_version)
            .expect("Could not fetch root subnet id.")
            .unwrap();
        assert_eq!(root_subnet_id, expected_root_subnet_id());

        let subnet_ids = local_registry
            .get_subnet_ids(latest_version)
            .expect("Could not fetch subnet ids")
            .unwrap();
        assert_eq!(subnet_ids.len(), 29);

        let root_subnet_node_ids = local_registry
            .get_node_ids_on_subnet(root_subnet_id, latest_version)
            .expect("Could not retrieve root subnet node ids")
            .unwrap()
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(root_subnet_node_ids.len(), 37);
    }

    fn get_mainnet_delta_00_6d_c1() -> (TempDir, LocalStoreImpl) {
        let tempdir = TempDir::new().unwrap();
        let store = LocalStoreImpl::new(tempdir.path());
        let mainnet_delta_raw = include_bytes!("../../common/artifacts/mainnet_delta_00-6d-c1.pb");
        let changelog = compact_delta_to_changelog(&mainnet_delta_raw[..])
            .expect("")
            .1;

        for (v, changelog_entry) in changelog.into_iter().enumerate() {
            let v = RegistryVersion::from((v + 1) as u64);
            store.store(v, changelog_entry).unwrap();
        }
        (tempdir, store)
    }

    fn expected_root_subnet_id() -> SubnetId {
        SubnetId::new(
            PrincipalId::from_str(
                "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
            )
            .unwrap(),
        )
    }
}
