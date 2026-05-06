use crate::registry_helper::RegistryHelper;
use async_trait::async_trait;
use guest_upgrade_server::DiskEncryptionKeyExchangeServerAgent;
use ic_image_upgrader::{
    ImageUpgrader, ManagebootRunner,
    error::{UpgradeError, UpgradeResult},
};
use ic_logger::ReplicaLogger;
use ic_types::{NodeId, ReplicaVersion};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct GuestosVersion(pub ReplicaVersion);

impl std::fmt::Display for GuestosVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<ReplicaVersion> for GuestosVersion {
    fn as_ref(&self) -> &ReplicaVersion {
        &self.0
    }
}

// TODO: docs
// TODO: re-order fields naturally
pub(crate) struct GuestosUpgrade {
    prepared_upgrade_version: Option<GuestosVersion>,
    image_path: PathBuf,
    reboot_time_path: PathBuf,
    logger: ReplicaLogger,
    node_id: NodeId,
    manageboot_runner: Box<dyn ManagebootRunner>,
    registry: Arc<RegistryHelper>,
    disk_encryption_key_exchange_agent: Option<DiskEncryptionKeyExchangeServerAgent>,
}

impl GuestosUpgrade {
    pub(crate) fn new(
        image_path: PathBuf,
        reboot_time_path: PathBuf,
        logger: ReplicaLogger,
        node_id: NodeId,
        manageboot_runner: Box<dyn ManagebootRunner>,
        registry: Arc<RegistryHelper>,
        disk_encryption_key_exchange_agent: Option<DiskEncryptionKeyExchangeServerAgent>,
    ) -> Self {
        Self {
            prepared_upgrade_version: None,
            image_path,
            reboot_time_path,
            logger,
            node_id,
            manageboot_runner,
            registry,
            disk_encryption_key_exchange_agent,
        }
    }
}

#[async_trait]
impl ImageUpgrader<GuestosVersion> for GuestosUpgrade {
    fn get_prepared_version(&self) -> Option<&GuestosVersion> {
        self.prepared_upgrade_version.as_ref()
    }

    fn set_prepared_version(&mut self, version: Option<GuestosVersion>) {
        self.prepared_upgrade_version = version
    }

    fn download_path(&self) -> &Path {
        &self.image_path
    }

    fn restart_time_path(&self) -> &Path {
        &self.reboot_time_path
    }

    fn log(&self) -> &ReplicaLogger {
        &self.logger
    }

    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn manageboot_runner(&self) -> &dyn ManagebootRunner {
        self.manageboot_runner.as_ref()
    }

    fn get_release_package_urls_and_hash(
        &self,
        version: &GuestosVersion,
    ) -> UpgradeResult<(Vec<String>, Option<String>)> {
        let record = self
            .registry
            .get_replica_version_record(
                version.as_ref().clone(),
                self.registry.get_latest_version(),
            )
            .map_err(UpgradeError::from)?;

        Ok((
            record.release_package_urls,
            Some(record.release_package_sha256_hex),
        ))
    }

    async fn maybe_exchange_disk_encryption_key(&mut self) -> UpgradeResult<()> {
        if let Some(agent) = &self.disk_encryption_key_exchange_agent {
            agent
                .exchange_keys()
                .await
                .map_err(|e| UpgradeError::DiskEncryptionKeyExchangeError(e.to_string()))
        } else {
            Ok(())
        }
    }
}
