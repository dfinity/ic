use async_trait::async_trait;
use ic_http_utils::file_downloader::FileDownloader;
use ic_logger::{ReplicaLogger, error, info, warn};
use std::str::FromStr;
use std::{
    fmt::Debug,
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime},
};
use tokio::process::Command;

use crate::error::{UpgradeError, UpgradeResult};

pub mod error;

/// Used to signal that the system is rebooting.
pub struct Rebooting;

const REBOOT_TIME_FILENAME: &str = "reboot_time.txt";

/// Defines the image upgrader trait and default implementation. It receives a generic version identifier `V`
/// and a return value `R` stemming from a periodically called `check_for_upgrade` function.
/// The lifecycle of an image can be described by:
/// 1. Confirming the boot of the current image using the `manageboot.sh` script. Cf. `confirm_boot()`
/// 2. Optionally collecting metrics of the reboot time from disk.
/// 3. Checking for new versions and executing upgrades in a loop, Cf. `upgrade_loop()`
///
/// ```ignore
/// // Version identifier
/// pub type Version = ...;
///
/// // Return value of `check_for_upgrade` to be handled in `upgrade_loop`
/// pub type Value = ...;
///
/// pub struct Upgrader {
///     ...
/// }
///
/// #[async_trait]
/// impl ImageUpgrader<Version, Value> for Upgrader {
///     ...
///
///     /// Called by `prepare_upgrade()` to download the image.
///     fn get_release_package_url_and_hash(
///         &self,
///         version: &Version,
///     ) -> UpgradeResult<(Vec<String>, Option<String>)> {
///         // Collect and return release package information, i.e. from registry.
///         ...
///     }
///
///     // Called periodically by `upgrade_loop()`
///     async fn check_for_upgrade(&mut self) -> UpgradeResult<Value> {
///         // Optional
///         // if latest_version != current_version {
///         //     self.prepare_upgrade(latest_version).await?;
///         // }
///         if latest_version != current_version && time_to_upgrade {
///             // Calls `prepare_upgrade` in case latest_version wasn't prepared
///             self.execute_upgrade(latest_version).await?;
///         }
///         Ok(value)
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     ...
///
///     let upgrade = Upgrader {...};
///
///     upgrade.confirm_boot().await;
///
///     upgrade.upgrade_loop(exit_signal, interval, timeout, |result| async {
///         match result {
///             Err(e) => ..., // timeout
///             Ok(Err(e)) => ..., // error while checking for upgrade
///             Ok(Ok(value)) => ..., // nominal check and no upgrade found
///         }
///     }).await;
/// }
/// ```
///
#[async_trait]
pub trait ImageUpgrader<V: Clone + Debug + PartialEq + Eq + Send + Sync>: Send + Sync {
    type UpgradeType;

    /// Return the currently prepared version, if there is one. Default is None.
    /// A version `v` is considered to be prepared if its release package was successfully
    /// downloaded and unpacked after a call to `prepare_upgrade(v)`.
    fn get_prepared_version(&self) -> Option<&V> {
        None
    }
    /// Set or unset the currently prepared version. Default is No-op.
    /// The prepared version is set during `prepare_upgrade()` and unset during the `execute_upgrade()` step.
    fn set_prepared_version(&mut self, _version: Option<V>) {}
    /// Path to the directory containing boot scripts.
    fn binary_dir(&self) -> &PathBuf;
    /// Path to the image image download and unpacking destination.
    fn image_path(&self) -> &PathBuf;
    /// Optional data path, used for storing latest reboot time. Default is None.
    fn data_dir(&self) -> Option<&PathBuf> {
        None
    }
    /// Return the logger to be passed to the upgrade functions.
    fn log(&self) -> &ReplicaLogger;
    /// Return the release package url and optional SHA256 hex string for the given version.
    /// Used to download the release package during `prepare_upgrade()`.
    fn get_release_package_urls_and_hash(
        &self,
        version: &V,
    ) -> UpgradeResult<(Vec<String>, Option<String>)>;

    /// Runs the disk encryption key exchange process if SEV is active. NOOP otherwise.
    async fn maybe_exchange_disk_encryption_key(&mut self) -> UpgradeResult<()>;

    /// Calls a corresponding script to "confirm" that the base OS could boot
    /// successfully. Without a confirmation the image will be reverted on the next
    /// restart.
    async fn confirm_boot(&self) {
        if let Err(err) = Command::new(self.binary_dir().join("manageboot.sh").into_os_string())
            .arg("guestos")
            .arg("confirm")
            .output()
            .await
        {
            error!(self.log(), "Could not confirm the boot: {:?}", err);
        }
    }

    /// Return a value that would differentiate the nodes (but not necessarily unique) in order
    /// to allow them to download the new release package from different URLs.
    fn get_load_balance_number(&self) -> usize;

    /// Downloads release package associated with the given version
    ///
    /// Releases are downloaded using [`FileDownloader::download_file()`] which
    /// returns immediately if the file with matching hash already exists.
    async fn download_release_package(&self, version: &V) -> UpgradeResult<()> {
        let (mut release_package_urls, hash) = self.get_release_package_urls_and_hash(version)?;

        let url_count = release_package_urls.len();
        if url_count == 0 {
            return Err(UpgradeError::GenericError(format!(
                "No download URLs are provided for version {version:?}"
            )));
        }

        // Load-balance, by making each node rotate the `release_package_urls` by some number.
        // Note that the order is the same for everyone; only the starting point is different.
        // This is okay because we do expect the first attempt to be successful.
        release_package_urls.rotate_right(self.get_load_balance_number() % url_count);

        // We return the last error if download attempts from all the URLs fail.
        // We will always either set `error`, or return `Ok` from this loop.
        let mut error = UpgradeError::GenericError("unreachable".to_string());
        for release_package_url in release_package_urls.iter() {
            let req = format!("Request to download image {version:?} from {release_package_url}");
            let file_downloader =
                FileDownloader::new_with_timeout(Some(self.log().clone()), Duration::from_secs(60));
            let start_time = std::time::Instant::now();
            let download_result = file_downloader
                .download_file(release_package_url, self.image_path(), hash.clone())
                .await;
            let duration = start_time.elapsed();

            if let Err(e) = download_result {
                warn!(self.log(), "{} failed in {:?}: {}", req, duration, e);
                error = UpgradeError::from(e);
            } else {
                info!(self.log(), "{} processed in {:?}", req, duration);
                return Ok(());
            }
        }

        Err(error)
    }

    /// Downloads release package associated with the given version,
    /// calls the node script that extracts it and copies it to the boot partition.
    /// This function is automatically called by `execute_upgrade()` unless `version`
    /// has already been prepared. Thus it may be called manually in advance, to minimize
    /// downtime of upgrades scheduled at a specific time.
    async fn prepare_upgrade(&mut self, version: &V) -> UpgradeResult<()> {
        // Return immediately if 'version' is already prepared for an upgrade.
        if self.get_prepared_version() == Some(version) {
            return Ok(());
        }

        self.download_release_package(version).await?;

        // The call to `manageboot.sh upgrade-install` could corrupt any previous upgrade preparation.
        // In case this function fails and we do want to leave `prepared_upgrade_version` set. Therefore,
        // clear it here.
        self.set_prepared_version(None);

        let mut script = self.binary_dir().clone();
        script.push("manageboot.sh");
        let mut c = Command::new(script.clone().into_os_string());
        let out = c
            .arg("guestos")
            .arg("upgrade-install")
            .arg(self.image_path())
            .output()
            .await
            .map_err(|e| UpgradeError::file_command_error(e, &c))?;

        if !out.status.success() {
            warn!(self.log(), "upgrade-install has failed");
            return Err(UpgradeError::GenericError(
                "upgrade-install failed".to_string(),
            ));
        }

        self.maybe_exchange_disk_encryption_key().await?;
        self.set_prepared_version(Some(version.clone()));
        Ok(())
    }

    /// Executes the node upgrade by unpacking the downloaded image (if it didn't happen yet)
    /// and rebooting the node.
    async fn execute_upgrade(&mut self, version: &V) -> UpgradeResult<Rebooting> {
        match self.get_prepared_version() {
            Some(v) if v == version => {
                info!(
                    self.log(),
                    "Replica version {:?} has already been prepared for upgrade.", v
                )
            }
            _ => self.prepare_upgrade(version).await?,
        };

        // If we ever retry this function, it means we encountered an issue somewhere.
        // To be safe, we should re-do all the steps.
        self.set_prepared_version(None);

        // Save the time of triggering the reboot if a path is provided.
        if let Err(e) = self.persist_time_of_triggering_reboot() {
            warn!(self.log(), "Cannot persist the time of reboot: {}", e);
        }

        // We could successfully unpack the file above, so we do not need the image anymore.
        std::fs::remove_file(self.image_path())
            .map_err(|e| UpgradeError::IoError("Couldn't delete the image".to_string(), e))?;

        info!(self.log(), "Attempting to reboot");
        let script = self.binary_dir().join("manageboot.sh");
        let mut cmd = Command::new(script.into_os_string());
        let out = cmd
            .arg("guestos")
            .arg("upgrade-commit")
            .output()
            .await
            .map_err(|e| UpgradeError::file_command_error(e, &cmd))?;

        if !out.status.success() {
            warn!(self.log(), "upgrade-commit has failed: {:?}", out.status);
            Err(UpgradeError::GenericError(
                "upgrade-commit failed".to_string(),
            ))
        } else {
            info!(self.log(), "Rebooting {:?}", out);
            Ok(Rebooting)
        }
    }

    /// Return the path of the reboot time file in the data directory.
    fn get_reboot_time_file_path(&self) -> UpgradeResult<PathBuf> {
        match self.data_dir() {
            Some(dir) => Ok(dir.join(REBOOT_TIME_FILENAME)),
            None => Err(UpgradeError::reboot_time_error(
                "`orchestrator_data_directory` is not provided",
            )),
        }
    }

    /// Write the current time to the reboot time file.
    fn persist_time_of_triggering_reboot(&self) -> UpgradeResult<()> {
        let path = self.get_reboot_time_file_path()?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(UpgradeError::reboot_time_error)?;
        let mut file = std::fs::File::create(path).map_err(UpgradeError::reboot_time_error)?;
        file.write_all(now.as_secs().to_string().as_bytes())
            .map_err(UpgradeError::reboot_time_error)?;
        Ok(())
    }

    /// Parse the latest reboot time and subtract it from the current time.
    fn get_time_since_last_reboot_trigger(&self) -> UpgradeResult<Duration> {
        let path = self.get_reboot_time_file_path()?;

        let content = std::fs::read(path).map_err(UpgradeError::reboot_time_error)?;
        let text = std::str::from_utf8(&content).map_err(UpgradeError::reboot_time_error)?;
        let then = Duration::new(
            u64::from_str(text).map_err(UpgradeError::reboot_time_error)?,
            0,
        );
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(UpgradeError::reboot_time_error)?;
        let elapsed_time = now - then;
        Ok(elapsed_time)
    }

    /// This function is called periodically by `upgrade_loop()`. An implementation should:
    /// * Check if an image upgrade is scheduled.
    /// * Optionally prepare the upgrade in advance using `prepare_upgrade`.
    /// * Once it is time to upgrade, execute it using `execute_upgrade`
    async fn check_for_upgrade(&mut self) -> Self::UpgradeType;
}
