use std::{collections::BTreeMap, sync::Arc};

use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::SUBNET_RECORD_KEY_PREFIX;
use ic_registry_local_registry::LocalRegistry;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_types::RegistryVersion;
use slog::{error, info};
use tokio::runtime::Handle;

pub mod ensure_blessed_version;
pub mod update_subnet_type;

pub trait Step: Sync + Send {
    fn execute(&self, env: TestEnv, rt: Handle, registry: RegistryWrapper) -> anyhow::Result<()>;

    fn max_retries(&self) -> usize;

    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    fn do_step(&self, env: TestEnv, rt: Handle) -> anyhow::Result<()> {
        let logger = env.logger();
        info!(logger, "Running step: {}", self.name());

        let wrapper = RegistryWrapper::new(env.get_registry()?);
        rt.block_on(wrapper.sync_with_nns())?;

        let mut max_retries = self.max_retries();
        loop {
            max_retries -= 1;
            match self.execute(env.clone(), rt.clone(), wrapper.clone()) {
                Ok(_) => break,
                Err(e) => {
                    let formatted = format!("Step `{}` failed with error: {:?}", self.name(), e);
                    error!(logger, "{}", formatted);
                    if max_retries.eq(&0) {
                        env.emit_report(formatted);
                        return Err(e);
                    }
                }
            }
        }

        info!(
            logger,
            "Step `{}` finished successfully after {} retries",
            self.name(),
            self.max_retries() - max_retries
        );
        Ok(())
    }
}

trait RegistryEntry: RegistryValue {
    const KEY_PREFIX: &'static str;
}

impl RegistryEntry for BlessedReplicaVersions {
    const KEY_PREFIX: &'static str = "blessed_replica_versions";
}

impl RegistryEntry for SubnetRecord {
    const KEY_PREFIX: &'static str = SUBNET_RECORD_KEY_PREFIX;
}

#[derive(Clone)]
pub struct RegistryWrapper {
    inner: Arc<LocalRegistry>,
}

impl RegistryWrapper {
    fn new(registry: Arc<LocalRegistry>) -> Self {
        Self { inner: registry }
    }

    async fn sync_with_nns(&self) -> anyhow::Result<()> {
        self.inner
            .sync_with_nns()
            .await
            .map_err(anyhow::Error::from)
    }

    async fn sync_with_local_store(&self) -> anyhow::Result<()> {
        self.inner
            .sync_with_local_store()
            .await
            .map_err(anyhow::Error::from)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.inner.get_latest_version()
    }

    fn get_family_entries<T: RegistryEntry + Default>(
        &self,
    ) -> anyhow::Result<BTreeMap<String, T>> {
        let family = self.get_family_entries_versioned::<T>()?;
        Ok(family.into_iter().map(|(k, (_, v))| (k, v)).collect())
    }

    fn get_family_entries_versioned<T: RegistryEntry + Default>(
        &self,
    ) -> anyhow::Result<BTreeMap<String, (u64, T)>> {
        self.get_family_entries_of_version(self.get_latest_version())
    }

    fn get_family_entries_of_version<T: RegistryEntry + Default>(
        &self,
        version: RegistryVersion,
    ) -> anyhow::Result<BTreeMap<String, (u64, T)>> {
        let prefix_length = T::KEY_PREFIX.len();
        Ok(self
            .inner
            .get_key_family(T::KEY_PREFIX, version)?
            .iter()
            .filter_map(|key| {
                let r = self
                    .inner
                    .get_versioned_value(key, version)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to get entry {} for type {}",
                            key,
                            std::any::type_name::<T>()
                        )
                    });
                r.as_ref().map(|v| {
                    (
                        key[prefix_length..].to_string(),
                        (
                            r.version.get(),
                            T::decode(v.as_slice()).expect("Invalid registry value"),
                        ),
                    )
                })
            })
            .collect())
    }
}
