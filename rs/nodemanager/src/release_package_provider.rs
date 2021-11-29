use crate::error::{NodeManagerError, NodeManagerResult};
use crate::registry_helper::RegistryHelper;
use crate::utils;
use ic_http_utils::file_downloader::FileDownloader;
use ic_logger::{info, warn, ReplicaLogger};
use ic_release::release::ReleaseContent;
use ic_types::ReplicaVersion;
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The maximum number of binaries to persist at any given time
const MAX_RELEASE_PACKAGES_TO_STORE: usize = 5;

/// Release packages will not be deleted for this time after being created.
/// Safeguards against deleting newly created packages before Node
/// Manager has had the chance to start the binaries within them.
const MIN_RELEASE_PACKAGE_AGE: Duration = Duration::from_secs(60);

/// Provides release packages, which contain binaries and config files used to
/// run a new version of the IC
#[derive(Clone)]
pub(crate) struct ReleasePackageProvider {
    registry: Arc<RegistryHelper>,
    file_downloader: Arc<FileDownloader>,
    release_content_dir: PathBuf,
    force_replica_binary: Option<String>,
    logger: ReplicaLogger,
}

impl ReleasePackageProvider {
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        release_content_dir: PathBuf,
        force_replica_binary: Option<String>,
        logger: ReplicaLogger,
    ) -> Self {
        let file_downloader = Arc::new(FileDownloader::new(Some(logger.clone())));

        Self {
            registry,
            file_downloader,
            release_content_dir,
            force_replica_binary,
            logger,
        }
    }

    /// Return the release package associated with the given version
    ///
    /// If a dir already exists for the given replica version, we remove this
    /// dir and all of its contents. This prevents issues where the dir
    /// exists but contains unexpected files or is missing expected files.
    ///
    /// If no release package URL or hash is defined for the given replica
    /// version's ReplicaVersionRecord, we attempt to construct a release
    /// package from the record's replica and node manager URLs.
    ///
    /// Previously downloaded releases will be delete if redownload is set to
    /// true.
    pub(crate) async fn download_release_package(
        &self,
        replica_version: ReplicaVersion,
    ) -> NodeManagerResult<ReleaseContent> {
        self.gc_release_packages();

        let version_dir = self.make_version_dir(&replica_version)?;

        let replica_version_record = self.registry.get_replica_version_record(
            replica_version.clone(),
            self.registry.get_latest_version(),
        )?;

        let tar_gz_path = version_dir.join("base-os.tar.gz");
        info!(
            self.logger,
            "Downloading release package for replica version {} from {} to {:?}",
            replica_version.as_ref(),
            &replica_version_record.release_package_url,
            &tar_gz_path,
        );

        let tar_gz_path = version_dir.join("base-os.tar.gz");
        self.file_downloader
            .download_file(
                &replica_version_record.release_package_url,
                &tar_gz_path,
                Some(replica_version_record.release_package_sha256_hex),
            )
            .await
            .map_err(NodeManagerError::from)?;

        let content = ReleaseContent::try_from(version_dir.as_path());
        if let Err(e) = &content {
            warn!(
                self.logger,
                "Failed to create release content in download release package at {:?}: {:?}",
                version_dir,
                e
            );
        }
        content.map_err(NodeManagerError::ReleasePackageError)
    }

    /// Make a dir to store a release package for the given replica version
    ///
    /// Deletes the directory first if delete_first is setup, otherwise does
    /// nothing.
    pub(crate) fn make_version_dir(
        &self,
        replica_version: &ReplicaVersion,
    ) -> NodeManagerResult<PathBuf> {
        let version_dir = self.release_content_dir.join(replica_version.as_ref());
        fs::create_dir_all(&version_dir)
            .map_err(|e| NodeManagerError::dir_create_error(&version_dir, e))?;
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
