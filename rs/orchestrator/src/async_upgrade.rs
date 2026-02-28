use crate::{
    error::{OrchestratorError, OrchestratorResult},
    registry_helper::RegistryHelper,
};
use backoff::{ExponentialBackoff, backoff::Backoff};
use guest_upgrade_server::DiskEncryptionKeyExchangeServerAgent;
use ic_http_utils::file_downloader::FileDownloader;
use ic_image_upgrader::{
    Rebooting,
    error::{UpgradeError, UpgradeResult},
};
use ic_logger::{ReplicaLogger, info, warn};
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_types::{NodeId, ReplicaVersion};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
enum AsyncUpgradeControlFlow {
    Stop,
    Continue,
}

pub(crate) struct AsyncUpgrader {
    registry: Arc<RegistryHelper>,
    guestos_version: ReplicaVersion,
    node_id: NodeId,
    image_path: PathBuf,
    ic_binary_dir: PathBuf,
    disk_encryption_key_exchange_agent: Option<Arc<DiskEncryptionKeyExchangeServerAgent>>,
    logger: ReplicaLogger,
}

impl AsyncUpgrader {
    #[allow(dead_code)]
    pub(crate) async fn new(
        registry: Arc<RegistryHelper>,
        guestos_version: ReplicaVersion,
        node_id: NodeId,
        release_content_dir: PathBuf,
        ic_binary_dir: PathBuf,
        disk_encryption_key_exchange_agent: Option<Arc<DiskEncryptionKeyExchangeServerAgent>>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            registry,
            guestos_version,
            node_id,
            image_path: release_content_dir.join("image.bin"),
            ic_binary_dir,
            disk_encryption_key_exchange_agent,
            logger,
        }
    }
}

impl AsyncUpgrader {
    /// Calls `check_for_upgrade()`, timing out after `timeout`, and waiting
    /// for `interval` between attempts. Awaiting this function blocks until
    /// `exit_signal` is set to `true`.
    pub async fn upgrade_loop(
        &mut self,
        cancellation_token: CancellationToken,
        mut backoff: ExponentialBackoff,
        liveness_timeout: Duration,
    ) {
        loop {
            match tokio::time::timeout(liveness_timeout, self.check_for_upgrade()).await {
                Ok(Ok(AsyncUpgradeControlFlow::Stop)) => cancellation_token.cancel(),
                Ok(Ok(AsyncUpgradeControlFlow::Continue)) => backoff.reset(),
                e => warn!(
                    &self.logger,
                    "Check for async GuestOS upgrade failed: {:?}", e
                ),
            }

            // NOTE: We currently do not and should not set `max_elapsed_time`,
            // so that we never run out of backoffs. If `max_elapsed_time` _is_
            // ever set, repeat the `max_interval` instead. This is technically
            // not the same behavior as if `max_elapsed_time` was unset, because
            // we will not be including jitter, but it should be close enough,
            // and safe.
            let safe_backoff = backoff.next_backoff().unwrap_or(backoff.max_interval);
            tokio::select! {
                _ = tokio::time::sleep(safe_backoff) => {}
                _ = cancellation_token.cancelled() => break
            };
        }
    }

    async fn check_for_upgrade(&mut self) -> OrchestratorResult<AsyncUpgradeControlFlow> {
        let latest_registry_version = self.registry.get_latest_version();

        let node_id = self.node_id;

        let node_guestos_version = self
            .registry
            .get_node_guestos_version(latest_registry_version)?;

        if let Some(node_guestos_version) = node_guestos_version
            && self.guestos_version != node_guestos_version
        {
            info!(
                self.logger,
                "Found GuestOS version '{node_guestos_version}' set for this node '{node_id}'",
            );
            info!(
                self.logger,
                "Starting async GuestOS upgrade at registry version {}: {} -> {}",
                latest_registry_version,
                self.guestos_version,
                node_guestos_version
            );
            return self
                .execute_upgrade(&node_guestos_version)
                .await
                .map_err(OrchestratorError::from)
                .map(|Rebooting| AsyncUpgradeControlFlow::Stop);
        }

        Ok(AsyncUpgradeControlFlow::Continue)
    }

    async fn execute_upgrade(&mut self, version: &ReplicaVersion) -> UpgradeResult<Rebooting> {
        let replica_version_record = self
            .registry
            .get_replica_version_record(version.clone(), self.registry.get_latest_version())?;

        let ReplicaVersionRecord {
            mut release_package_urls,
            release_package_sha256_hex: hash,
            ..
        } = replica_version_record;

        // Load-balance, by making each node rotate the `release_package_urls` by some number.
        // Note that the order is the same for everyone; only the starting point is different.
        // This is okay because we do expect the first attempt to be successful.
        let url_count = release_package_urls.len();
        release_package_urls.rotate_right(self.get_load_balance_number() % url_count);

        let mut error = UpgradeError::GenericError(
            "No download URLs are provided for version {version:?}".to_string(),
        );

        for release_package_url in release_package_urls.iter() {
            let result = self
                .try_run_async_upgrade(version, release_package_url, &hash)
                .await;

            match result {
                result @ Ok(_) => return result,
                Err(e) => {
                    info!(
                        &self.logger,
                        "Async upgrade failed using: '{release_package_url}'"
                    );
                    error = e;
                }
            }
        }

        Err(error)
    }

    fn get_load_balance_number(&self) -> usize {
        // XOR all the u8 in node_id:
        let principal = self.node_id.get().0;
        principal.as_slice().iter().fold(0, |acc, x| acc ^ x) as usize
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

    async fn try_run_async_upgrade(
        &mut self,
        version: &ReplicaVersion,
        release_package_url: &str,
        hash: &str,
    ) -> UpgradeResult<Rebooting> {
        let req = format!("Request to download image {version:?} from {release_package_url}");
        let file_downloader =
            FileDownloader::new_with_timeout(Some(self.logger.clone()), Duration::from_secs(60));
        let start_time = std::time::Instant::now();
        let download_result = file_downloader
            .download_file(
                release_package_url,
                &self.image_path,
                Some(hash.to_string()),
            )
            .await;
        let duration = start_time.elapsed();

        if let Err(e) = download_result {
            warn!(self.logger, "{} failed in {:?}: {}", req, duration, e);
            return Err(UpgradeError::from(e));
        } else {
            info!(self.logger, "{} processed in {:?}", req, duration);
        }

        let mut script = self.ic_binary_dir.clone();
        script.push("manageboot.sh");
        let mut c = Command::new(script.clone().into_os_string());
        let out = c
            .arg("guestos")
            .arg("upgrade-install")
            .arg(&self.image_path)
            .output()
            .await
            .map_err(|e| UpgradeError::file_command_error(e, &c))?;

        if !out.status.success() {
            warn!(self.logger, "upgrade-install has failed");
            return Err(UpgradeError::GenericError(
                "upgrade-install failed".to_string(),
            ));
        }

        self.maybe_exchange_disk_encryption_key().await?;

        // We could successfully unpack the file above, so we do not need the image anymore.
        std::fs::remove_file(&self.image_path)
            .map_err(|e| UpgradeError::IoError("Couldn't delete the image".to_string(), e))?;

        info!(self.logger, "Attempting to reboot");
        let script = self.ic_binary_dir.join("manageboot.sh");
        let mut cmd = Command::new(script.into_os_string());
        let out = cmd
            .arg("guestos")
            .arg("upgrade-commit")
            .output()
            .await
            .map_err(|e| UpgradeError::file_command_error(e, &cmd))?;

        if !out.status.success() {
            warn!(self.logger, "upgrade-commit has failed: {:?}", out.status);
            Err(UpgradeError::GenericError(
                "upgrade-commit failed".to_string(),
            ))
        } else {
            info!(self.logger, "Rebooting {:?}", out);
            Ok(Rebooting)
        }
    }
}
