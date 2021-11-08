use crate::metrics::NodeManagerMetrics;
use crate::registry_helper::RegistryHelper;
use ic_logger::{debug, info, warn, ReplicaLogger};
use std::sync::Arc;
use std::time::Duration;

const REGISTRY_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Continuously checks the Registry to determine if there has been a change in
/// the readonly and backup public key sets.If so, updates the accesss to the
/// node accordingly.
pub(crate) struct SshAccessManager {
    registry: Arc<RegistryHelper>,
    metrics: Arc<NodeManagerMetrics>,
    logger: ReplicaLogger,
    current_readonly_keys: Vec<String>,
    current_backup_keys: Vec<String>,

    // If false, do not start or terminate the background task
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl SshAccessManager {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        metrics: Arc<NodeManagerMetrics>,
        logger: ReplicaLogger,
    ) -> Self {
        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
        Self {
            registry,
            metrics,
            logger,
            current_readonly_keys: vec![],
            current_backup_keys: vec![],
            enabled,
        }
    }

    pub(crate) fn start(self) -> Arc<std::sync::atomic::AtomicBool> {
        let result = self.enabled.clone();
        tokio::spawn(background_task(self));
        result
    }

    /// Checks for changes in the keysets, and updates the node accordingly.
    pub(crate) async fn check_for_keyset_changes(&mut self) {
        let registry_version = self.registry.get_latest_version();
        debug!(
            self.logger,
            "Checking for the access keys in the registry version: {}", registry_version
        );

        let (new_readonly_keys, new_backup_keys) = match self
            .registry
            .get_own_readonly_and_backup_keysets(registry_version)
        {
            Err(error) => {
                warn!(
                    self.logger,
                    "Cannot retrieve the readonly & backup keysets from the registry {}", error
                );
                return;
            }
            Ok(keys) => keys,
        };

        // If keys are not changed, there is nothing to do.
        if (self.current_readonly_keys == new_readonly_keys)
            && (self.current_backup_keys == new_backup_keys)
        {
            return;
        }

        info!(
            self.logger,
            "New keysets are found at registry version {}, updating the access rights.",
            registry_version
        );

        // If successful, update the readonly & backup keys.
        // If not, log why.
        match self.update_access_keys(&new_readonly_keys, &new_backup_keys) {
            Err(error) => warn!(
                self.logger,
                "Could not update the access key due to a script failure: {}", error
            ),
            Ok(()) => {
                self.current_readonly_keys = new_readonly_keys;
                self.current_backup_keys = new_backup_keys;
                self.metrics
                    .ssh_access_registry_version
                    .set(registry_version.get() as i64);
            }
        }
    }

    fn update_access_keys(
        &mut self,
        _readonly_keys: &[String],
        _backup_keys: &[String],
    ) -> Result<(), String> {
        // CON-621: Call the script to update the keys
        Ok(())
    }
}

async fn background_task(mut manager: SshAccessManager) {
    loop {
        if !manager.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }

        manager.check_for_keyset_changes().await;
        tokio::time::sleep(REGISTRY_CHECK_INTERVAL).await;
    }
}
