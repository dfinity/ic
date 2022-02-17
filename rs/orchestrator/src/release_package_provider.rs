use crate::error::{OrchestratorError, OrchestratorResult};
use crate::registry_helper::RegistryHelper;
use crate::utils;
use ic_http_utils::file_downloader::FileDownloader;
use ic_logger::{info, ReplicaLogger};
use ic_types::ReplicaVersion;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The maximum number of binaries to persist at any given time
const MAX_RELEASE_PACKAGES_TO_STORE: usize = 5;

/// Release packages will not be deleted for this time after being created.
/// Safeguards against deleting newly created packages before Orchestrator
/// has had the chance to start the binaries within them.
const MIN_RELEASE_PACKAGE_AGE: Duration = Duration::from_secs(60);

/// Provides release packages, which contain binaries and config files used to
/// run a new version of the IC
#[derive(Clone)]
pub(crate) struct ReleasePackageProvider {
    registry: Arc<RegistryHelper>,
    file_downloader: Arc<FileDownloader>,
    release_content_dir: PathBuf,
    _force_replica_binary: Option<String>,
    logger: ReplicaLogger,
}

impl ReleasePackageProvider {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        release_content_dir: PathBuf,
        _force_replica_binary: Option<String>,
        logger: ReplicaLogger,
    ) -> Self {
        let file_downloader = Arc::new(FileDownloader::new(Some(logger.clone())));

        Self {
            registry,
            file_downloader,
            release_content_dir,
            _force_replica_binary,
            logger,
        }
    }

    /// Downloads release package associated with the given version to
    /// `[self.release_content_dir]/[replica_version]/base-os.tar.gz`.
    ///
    /// Garbage collects old release packages while keeping
    /// `self.MAX_RELEASE_PACKAGES_TO_STORE` youngest entries and files younger
    /// than `self.MIN_RELEASE_PACKAGE_AGE`.
    ///
    /// Releases are downloaded using [`FileDownloader::download_file()`] which
    /// returns immediately if a file with correct hash already exists.
    pub(crate) async fn download_release_package(
        &self,
        replica_version: ReplicaVersion,
    ) -> OrchestratorResult<()> {
        // recent packages are persisted
        self.gc_release_packages();
        let version_dir = self.make_version_dir(&replica_version)?;
        let replica_version_record = self.registry.get_replica_version_record(
            replica_version.clone(),
            self.registry.get_latest_version(),
        )?;
        let tar_gz_path = version_dir.join("base-os.tar.gz");
        let start_time = std::time::Instant::now();
        // returns immediately if the file already exists with the given hash
        self.file_downloader
            .download_file(
                &replica_version_record.release_package_url,
                &tar_gz_path,
                Some(replica_version_record.release_package_sha256_hex),
            )
            .await
            .map_err(OrchestratorError::from)?;
        info!(
            self.logger,
            "Image downloading request for version {} processed in {:?}",
            replica_version.as_ref(),
            start_time.elapsed(),
        );
        Ok(())
    }

    /// Make a dir in `self.release_content_dir` to store a release package for
    /// the given replica version See [`fs::create_dir_all()`]
    pub(crate) fn make_version_dir(
        &self,
        replica_version: &ReplicaVersion,
    ) -> OrchestratorResult<PathBuf> {
        let version_dir = self.release_content_dir.join(replica_version.as_ref());
        fs::create_dir_all(&version_dir)
            .map_err(|e| OrchestratorError::dir_create_error(&version_dir, e))?;
        Ok(version_dir)
    }

    // Delete old release packages so that `release_content_dir` doesn't grow
    // unbounded
    fn gc_release_packages(&self) {
        utils::gc_dir(
            &self.logger,
            &self.release_content_dir,
            MAX_RELEASE_PACKAGES_TO_STORE,
            MIN_RELEASE_PACKAGE_AGE,
        )
        .unwrap_or(());
    }
}
