use async_trait::async_trait;
use ic_http_utils::file_downloader::FileDownloader;
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_types::NodeId;
use std::ffi::OsStr;
use std::path::Path;
use std::str::FromStr;
use std::{
    fmt::Debug,
    io::Write,
    path::PathBuf,
    process::Output,
    time::{Duration, SystemTime},
};
use tokio::process::Command;

use crate::error::{UpgradeError, UpgradeResult};

pub mod error;

/// Trait for running manageboot.sh commands.
#[async_trait]
pub trait ManagebootRunner: Send + Sync {
    /// Run the given manageboot command and return its output.
    async fn run(&self, args: &[&OsStr]) -> std::io::Result<Output>;
}

/// Production implementation of [`ManagebootRunner`] that executes the command
/// as a child process.
pub struct ManagebootRunnerImpl {
    binary: PathBuf,
    system_type: String,
}

impl ManagebootRunnerImpl {
    pub fn new(binary: PathBuf, system_type: String) -> Self {
        Self {
            binary,
            system_type,
        }
    }
}

#[async_trait]
impl ManagebootRunner for ManagebootRunnerImpl {
    async fn run(&self, args: &[&OsStr]) -> std::io::Result<Output> {
        Command::new(&self.binary)
            .arg(&self.system_type)
            .args(args)
            .output()
            .await
    }
}

/// Used to signal that the system is rebooting/orchestrator is restarting.
pub struct Restarting;

/// Defines the image upgrader trait and default implementation. It receives a generic version identifier `V`.
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
/// impl Upgrader {
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
/// #[async_trait]
/// impl ImageUpgrader<Version> for Upgrader {
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
    /// Return the currently prepared version, if there is one.
    /// A version `v` is considered to be prepared if its release package was successfully
    /// downloaded and unpacked after a call to `prepare_upgrade(v)`.
    fn get_prepared_version(&self) -> Option<&V>;
    /// Set or unset the currently prepared version. Default is No-op.
    /// The prepared version is set during `prepare_upgrade()` and unset during the `execute_upgrade()` step.
    fn set_prepared_version(&mut self, _version: Option<V>) {}
    /// Path to the download destination.
    fn download_path(&self) -> &Path;
    /// Path used for storing the latest restart time.
    fn restart_time_path(&self) -> &Path;
    /// Return the logger to be passed to the upgrade functions.
    fn log(&self) -> &ReplicaLogger;
    /// Return the current node ID which is used to differentiate the nodes for load-balancing the
    /// download of release packages.
    fn node_id(&self) -> NodeId;
    /// Return the implementation of [`ManagebootRunner`] to be used for running the
    /// `manageboot.sh` commands.
    fn manageboot_runner(&self) -> &dyn ManagebootRunner;
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
        let args = ["confirm".as_ref()];
        if let Err(err) = self.manageboot_runner().run(&args).await {
            error!(self.log(), "Could not confirm the boot: {:?}", err);
        }
    }

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
        let principal = self.node_id().get().0;
        // XOR all the u8 in node_id:
        let load_balance_number = principal.as_slice().iter().fold(0, |acc, x| acc ^ x) as usize;
        release_package_urls.rotate_right(load_balance_number % url_count);

        // We return the last error if download attempts from all the URLs fail.
        // We will always either set `error`, or return `Ok` from this loop.
        let mut error = UpgradeError::GenericError("unreachable".to_string());
        for release_package_url in release_package_urls.iter() {
            let req = format!("Request to download image {version:?} from {release_package_url}");
            let file_downloader =
                FileDownloader::new_with_timeout(Some(self.log().clone()), Duration::from_secs(60));
            let start_time = std::time::Instant::now();
            let download_result = file_downloader
                .download_file(release_package_url, self.download_path(), hash.clone())
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

        let args = ["upgrade-install".as_ref(), self.download_path().as_ref()];
        let out = self
            .manageboot_runner()
            .run(&args)
            .await
            .map_err(|e| UpgradeError::manageboot_error(e, &args))?;

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
    /// and rebooting the node/restarting the orchestrator.
    // Only downloads the new image if it doesn't already exists locally, i.e. it
    // was previously downloaded by a previous call to `prepare_upgrade()`.
    async fn execute_upgrade(&mut self, version: &V) -> UpgradeResult<Restarting> {
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

        // Save the time of triggering the reboot/restart
        if let Err(e) = self.persist_time_of_triggering_reboot() {
            warn!(self.log(), "Cannot persist the time of restart: {}", e);
        }

        // We could successfully unpack the file above, so we do not need the image anymore.
        std::fs::remove_file(self.download_path())
            .map_err(|e| UpgradeError::IoError("Couldn't delete the image".to_string(), e))?;

        info!(self.log(), "Attempting to reboot/restart");
        let args = ["upgrade-commit".as_ref()];
        let out = self
            .manageboot_runner()
            .run(&args)
            .await
            .map_err(|e| UpgradeError::manageboot_error(e, &args))?;

        if !out.status.success() {
            warn!(self.log(), "upgrade-commit has failed: {:?}", out.status);
            Err(UpgradeError::GenericError(
                "upgrade-commit failed".to_string(),
            ))
        } else {
            info!(self.log(), "Rebooting/Restarting {:?}", out);
            Ok(Restarting)
        }
    }

    /// Write the current time to the reboot time file.
    fn persist_time_of_triggering_reboot(&self) -> UpgradeResult<()> {
        let path = self.restart_time_path();
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
        let path = self.restart_time_path();

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
}
