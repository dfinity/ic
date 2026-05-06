use crate::registry_helper::RegistryHelper;
use async_trait::async_trait;
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

pub(crate) struct BinariesUpgrade {
    prepared_upgrade_version: Option<ReplicaVersion>,
    download_path: PathBuf,
    restart_time_path: PathBuf,
    logger: ReplicaLogger,
    node_id: NodeId,
    manageboot_runner: Box<dyn ManagebootRunner>,
    registry: Arc<RegistryHelper>,
}

impl BinariesUpgrade {
    pub(crate) fn new(
        download_path: PathBuf,
        restart_time_path: PathBuf,
        logger: ReplicaLogger,
        node_id: NodeId,
        manageboot_runner: Box<dyn ManagebootRunner>,
        registry: Arc<RegistryHelper>,
    ) -> Self {
        Self {
            prepared_upgrade_version: None,
            download_path,
            restart_time_path,
            logger,
            node_id,
            manageboot_runner,
            registry,
        }
    }
}

#[async_trait]
impl ImageUpgrader<ReplicaVersion> for BinariesUpgrade {
    fn get_prepared_version(&self) -> Option<&ReplicaVersion> {
        self.prepared_upgrade_version.as_ref()
    }

    fn set_prepared_version(&mut self, version: Option<ReplicaVersion>) {
        self.prepared_upgrade_version = version
    }

    fn download_path(&self) -> &Path {
        &self.download_path
    }

    fn restart_time_path(&self) -> &Path {
        &self.restart_time_path
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
        version: &ReplicaVersion,
    ) -> UpgradeResult<(Vec<String>, Option<String>)> {
        let _record = self
            .registry
            .get_replica_version_record(version.clone(), self.registry.get_latest_version())
            .map_err(UpgradeError::from)?;

        // TODO:
        // Ok((record.ic_bins_url, Some(record.ic_bins_hash)))
        Ok((vec![], None))
    }

    async fn maybe_exchange_disk_encryption_key(&mut self) -> UpgradeResult<()> {
        Ok(())
    }
}
