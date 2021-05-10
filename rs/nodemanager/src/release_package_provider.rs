use crate::error::{NodeManagerError, NodeManagerResult};
use crate::registry_helper::RegistryHelper;
use crate::utils;
use ic_http_utils::file_downloader::{FileDownloadError, FileDownloader};
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_release::release::ReleaseContent;
use ic_types::ReplicaVersion;
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

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

        if ReleasePackageProvider::release_package_is_available(&replica_version_record) {
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
        } else {
            info!(
                self.logger,
                "Downloading release for replica version {} from {} and {}",
                replica_version.as_ref(),
                &replica_version_record.binary_url,
                &replica_version_record.node_manager_binary_url,
            );

            self.download_binary(
                utils::REPLICA_BINARY_NAME,
                &replica_version_record.binary_url,
                &replica_version_record.sha256_hex,
                &version_dir,
            )
            .await?;

            self.download_binary(
                utils::NODE_MANAGER_BINARY_NAME,
                &replica_version_record.node_manager_binary_url,
                &replica_version_record.node_manager_sha256_hex,
                &version_dir,
            )
            .await?;
        }

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

    /// Download the given binary from the given URL and check its hash
    ///
    /// The file will only be generate if the downloaded file matches
    /// the given sha256 hex.
    async fn download_binary(
        &self,
        binary_name: &str,
        url: &str,
        sha256_hex: &str,
        target_dir: &PathBuf,
    ) -> NodeManagerResult<()> {
        if binary_name == utils::REPLICA_BINARY_NAME && self.force_replica_binary.is_some() {
            return Ok(());
        }

        if url.is_empty() || sha256_hex.is_empty() {
            return Ok(());
        }

        let target_path = target_dir.join(binary_name);
        if target_path.exists() {
            match utils::check_file_hash(&target_path, sha256_hex) {
                Err(e) => {
                    warn!(
                        self.logger,
                        "Deleting downloaded binary with incorrect hash: {:?}", e
                    );
                    fs::remove_file(&target_path)
                        .map_err(|e| FileDownloadError::file_remove_error(&target_path, e))?;
                }
                Ok(()) => {
                    return Ok(());
                }
            }
        };

        // Create temporary directory for downloading files to Do
        // *not* move this code in conditional branch, because
        // life-time will be too short.
        let temp_dir = tempdir().map_err(|e| {
            NodeManagerError::IoError("Failed to create temporary directory".to_string(), e)
        })?;

        let binary_path = if url.starts_with("file://") {
            // We already have the file locally, don't need to download
            PathBuf::from(&url["file://".len()..])
        } else {
            // Download to temporary file
            let temp_dir = temp_dir.path().to_path_buf();
            self.file_downloader
                .download_and_extract_tar_gz(url, &temp_dir, None)
                .await
                .map_err(NodeManagerError::from)?;

            temp_dir.join(binary_name)
        };

        utils::check_file_hash(&binary_path, sha256_hex)?;

        // Now that we know that the freshly downloaded file has the
        // correct hash, delete existing file if it exists.
        if target_path.exists() {
            if let Err(e) = fs::remove_file(&target_path) {
                warn!(
                    self.logger,
                    "Failed to delete old binary at {:?} - Error: {:?}", &target_path, e
                );
            }
        }

        fs::copy(&binary_path, &target_path)
            .map_err(|e| NodeManagerError::file_copy_error(&binary_path, &target_path, e))?;

        Ok(())
    }

    /// Make a dir to store a release package for the given replica version
    ///
    /// Deletes the directory first if delete_first is setup, otherwise does
    /// nothing.
    pub(crate) fn make_version_dir(
        &self,
        replica_version: &ReplicaVersion,
    ) -> NodeManagerResult<PathBuf> {
        let version_dir = self.get_version_dir(replica_version);

        if !version_dir.exists() {
            fs::create_dir(&version_dir)
                .map_err(|e| NodeManagerError::dir_create_error(&version_dir, e))?;
        }

        Ok(version_dir)
    }

    /// Return the directory where a release package for the given version
    /// should be stored
    pub(crate) fn get_version_dir(&self, replica_version: &ReplicaVersion) -> PathBuf {
        self.release_content_dir.join(replica_version.as_ref())
    }

    /// Delete old release packages so that `release_content_dir` doesn't grow
    /// unbounded
    fn gc_release_packages(&self) {
        utils::gc_dir(
            &self.logger,
            &self.release_content_dir,
            MAX_RELEASE_PACKAGES_TO_STORE,
            MIN_RELEASE_PACKAGE_AGE,
        )
        .unwrap_or(());
    }

    /// Return true iff a release package URL and hash are defined in the given
    /// record
    pub(crate) fn release_package_is_available(
        replica_version_record: &ReplicaVersionRecord,
    ) -> bool {
        !replica_version_record.release_package_url.is_empty()
            && !replica_version_record.release_package_sha256_hex.is_empty()
    }
}
