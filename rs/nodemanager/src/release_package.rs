use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::error::{NodeManagerError, NodeManagerResult};
use crate::nns_registry_replicator::NnsRegistryReplicator;
use crate::registry_helper::RegistryHelper;
use crate::release_package_provider::ReleasePackageProvider;
use crate::replica_process::ReplicaProcess;
use crate::utils;
use ic_http_utils::file_downloader::check_file_hash;
use ic_http_utils::file_downloader::FileDownloader;
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_registry_common::local_store::LocalStoreImpl;
use ic_types::consensus::catchup::CUPWithOriginalProtobuf;
use ic_types::{
    crypto::threshold_sig::{ni_dkg::NiDkgTag, ThresholdSigPublicKey},
    RegistryVersion, ReplicaVersion, SubnetId,
};
use std::convert::TryFrom;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{exit, Command};
use std::sync::{Arc, Mutex};

/// Continuously checks the Registry to determine if this node should upgrade
/// to a new release package, and if so, downloads and extracts this release
/// package and exec's the node manager binary contained within
pub(crate) struct ReleasePackage {
    registry: Arc<RegistryHelper>,
    replica_process: Arc<Mutex<ReplicaProcess>>,
    release_package_provider: Arc<ReleasePackageProvider>,
    cup_provider: Arc<CatchUpPackageProvider>,
    subnet_id: Option<SubnetId>,
    replica_version: Option<ReplicaVersion>,
    high_threshold_pub_key: Option<ThresholdSigPublicKey>,
    release_content_dir: PathBuf,
    force_replica_binary: Option<String>,
    replica_config_file: PathBuf,
    ic_binary_dir: PathBuf,
    current_node_manager_hash: String,
    fixed_version_mode: bool,
    nns_registry_replicator: Arc<NnsRegistryReplicator>,
    logger: ReplicaLogger,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl ReleasePackage {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        registry: Arc<RegistryHelper>,
        replica_process: Arc<Mutex<ReplicaProcess>>,
        release_package_provider: Arc<ReleasePackageProvider>,
        cup_provider: Arc<CatchUpPackageProvider>,
        release_content_dir: PathBuf,
        force_replica_binary: Option<String>,
        replica_config_file: PathBuf,
        ic_binary_dir: PathBuf,
        current_node_manager_hash: String,
        nns_registry_replicator: Arc<NnsRegistryReplicator>,
        logger: ReplicaLogger,
    ) -> Arc<std::sync::atomic::AtomicBool> {
        // For base OS upgrades, we determine the current version from a file packed
        // into the image.
        let mut version_file = ic_binary_dir.clone();
        version_file.push("version.txt");
        let contents = fs::read_to_string(version_file);
        let (fixed_version_mode, replica_version) = if let Ok(version) = contents {
            info!(logger, "Setting replica version ID to: {}", &version);
            let version = version.trim_end();
            (true, Some(ReplicaVersion::try_from(version).unwrap()))
        } else {
            info!(
                logger,
                "Could not read version.txt, current replica version set to None"
            );
            (false, None)
        };

        let high_threshold_pub_key = get_public_key(&registry, registry.get_latest_version()).await;

        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut release_package = Self {
            registry,
            replica_process,
            release_package_provider,
            cup_provider,
            subnet_id: None,
            high_threshold_pub_key,
            replica_version,
            release_content_dir,
            force_replica_binary,
            replica_config_file,
            ic_binary_dir,
            current_node_manager_hash,
            fixed_version_mode,
            nns_registry_replicator,
            logger,
            enabled: enabled.clone(),
        };
        release_package.check_for_upgrade_once().await;
        tokio::spawn(background_task(release_package));
        enabled
    }

    /// Checks for a new release package, and if found, upgrades to this release
    /// package
    ///
    /// Returns which version is running or error in case of error.
    pub(crate) async fn check_for_upgrade(
        &self,
    ) -> NodeManagerResult<(ReplicaVersion, Option<(SubnetId, ThresholdSigPublicKey)>)> {
        let latest_registry_version = self.registry.get_latest_version();
        let (latest_subnet_id, subnet_record) = self.get_subnet_record(latest_registry_version)?;

        // 0. Special case for when we are doing boostrap disaster recovery for
        // nns and replacing the local registry store. Because we replace the
        // contents of the local registry store in the process of doing this, we
        // will not perpetually hit this case, and thus it is not important to
        // check the height.
        if let Some(registry_store_uri) = self
            .registry
            .registry_client
            .get_cup_contents(latest_subnet_id, latest_registry_version)
            .ok()
            .and_then(|record| record.value.and_then(|v| v.registry_store_uri))
        {
            let cup = self
                .registry
                .get_registry_cup(latest_registry_version)
                .expect("A registry cup must be present in the the registry");

            self.cup_provider
                .persist_cup(&CUPWithOriginalProtobuf::from_cup(cup), latest_subnet_id)?;

            info!(
                self.logger,
                "Downloading registry data from {} with hash {}",
                registry_store_uri.uri,
                registry_store_uri.hash,
            );
            let downloader = FileDownloader::new(Some(self.logger.clone()));
            let local_store_location = tempfile::tempdir()
                .expect("temporary location for local store download could not be created")
                .into_path();
            std::fs::create_dir_all(&local_store_location).expect("Directory should be created");
            downloader
                .download_and_extract_tar_gz(
                    &registry_store_uri.uri,
                    &local_store_location,
                    Some(registry_store_uri.hash),
                )
                .await
                .expect("Download of registry cache should succeed");
            self.stop_replica()?;

            let new_local_store = LocalStoreImpl::new(local_store_location);
            self.nns_registry_replicator
                .stop_polling_and_set_local_registry_data(&new_local_store);

            utils::reexec_current_process(&self.logger);
        }

        // 1. Check if the subnet has changed based on the latest registry
        if let Some(current_subnet_id) = self.subnet_id {
            if latest_subnet_id != current_subnet_id {
                info!(
                    self.logger,
                    "Detected subnet migration from {:?} to {}",
                    current_subnet_id,
                    latest_subnet_id
                );
                // Subnet changes are currently not supported. At least two features are
                // missing:
                //
                // 1. A safe way for a replica to leave the old subnetwork (incl. leaving DKG
                // committee)
                //
                // 2. Delete state from old subnetwork
                panic!("Subnet changes currently not supported");
            }
        }

        // Determine version of release in the latest registry version.
        let latest_replica_version =
            RegistryHelper::get_replica_version_from_subnet_record(subnet_record)?;

        let latest_public_key = get_public_key(&self.registry, latest_registry_version).await;

        // If we are already running what is the latest version in the registry,
        // there cannot be an upgrade. No need to check for CUPs, simply return.
        // The exception to this is when we have a recovery CUP (which we can
        // detect by seeing that the public key of the subnet has changed).

        // Note that we do not allow version transitions v1 -> v2 -> v1.
        // Even without this optimization, the node manager would not trigger restarting
        // the replica (e.g. in cases we directly upgrade v1 -> v1).
        let current_replica_version = &self.replica_version;
        if Some(&latest_replica_version) == current_replica_version.as_ref()
            && (latest_public_key == self.high_threshold_pub_key ||
                // There are cases where during start() get_public_key() was
                // not yet available and it has been set to None. If that's
                // the case and it is now available, set it and return.
                    self.high_threshold_pub_key.is_none())
        {
            if self.fixed_version_mode && self.subnet_id.is_none() {
                // Confirm base OS has booted (so it does not get reverted on next boot).
                let mut script = self.ic_binary_dir.clone();
                script.push("manageboot.sh");
                let mut c = Command::new("sudo");
                c.arg(script.into_os_string())
                    .arg("confirm")
                    .output()
                    .map_err(|e| NodeManagerError::file_command_error(e, &c))?;

                // Get latest CUP
                let cup = self.cup_provider.get_latest_cup(latest_subnet_id).await?;

                let cup_public_key = cup
                    .cup
                    .content
                    .block
                    .get_value()
                    .payload
                    .as_ref()
                    .as_summary()
                    .current_transcript(&NiDkgTag::HighThreshold)
                    .public_key();

                // Now that we know we are upgrading, persist the CUP
                // again.  This is just to determine the path. It's a
                // bit ugly, but the API of the CUP package provider
                // currently doesn't easily allow to get the actual
                // path out. And persisting it again shouldn't break anything ..
                let cup_path = self.cup_provider.persist_cup(&cup, latest_subnet_id)?;

                let replica_version = self
                    .replica_version
                    .clone()
                    .expect("Replica version has to be known in fixed_version_mode");
                // Start new replica binary
                let mut replica_path = self.ic_binary_dir.clone();
                replica_path.push("replica");
                let replica_path = replica_path.into_os_string().into_string().unwrap();

                self.start_replica(replica_path, replica_version, cup_path, latest_subnet_id)?;

                return Ok((
                    latest_replica_version,
                    Some((latest_subnet_id, cup_public_key)),
                ));
            } else {
                debug!(
                    self.logger,
                    "Latest version from registry {} - already running, no CUP fetching",
                    latest_replica_version
                );
                return Ok((latest_replica_version, None));
            }
        }

        info!(
            self.logger,
            "Runnig upgrade loop. Latest IC version in registry: {} \
             - running IC version {:?} \
             - latest public key: {:?} \
             - running with public key: {:?}",
            latest_replica_version,
            self.replica_version.as_ref(),
            latest_public_key,
            self.high_threshold_pub_key,
        );

        // Attempt to pro-actively download the replica version for
        // the highest current registry version. Note that the current
        // subnetwork might not yet have executed that upgrade (in
        // which case the actual replica version to boot will be downloaded later)

        // We download that version, but don't actually do anything with it.
        // The code will not re-download a replica version that we have previously
        // downloaded.
        //
        // Do not abort here, since it is possible we want to upgrade to v2, but we try
        // to download v3. If download of v3 fails, we should still continue because
        // upgrade to v2 might succeed.
        //
        // We delete previously downloaded release packages, as we cannot be sure that
        // their content is correct (e.g. when redeploying on the same machine).
        let _ = self
            .release_package_provider
            .download_release_package(latest_replica_version.clone())
            .await;

        // 2. Check for upgrade based on the registry verison used in current subnet

        // Get latest CUP from peers & local CUPs on disk (fallback to registry)
        let cup = self.cup_provider.get_latest_cup(latest_subnet_id).await?;

        let cup_public_key = cup
            .cup
            .content
            .block
            .get_value()
            .payload
            .as_ref()
            .as_summary()
            .current_transcript(&NiDkgTag::HighThreshold)
            .public_key();

        let cup_registry_version = cup.cup.content.registry_version();

        // For the CUP's registry version, get replica version of current subnet.
        let subnet_record = self
            .registry
            .get_subnet_record(latest_subnet_id, cup_registry_version)?;
        let new_replica_version =
            &RegistryHelper::get_replica_version_from_subnet_record(subnet_record)?;

        // If that replica version matches what we are already running, do nothing.
        if let Some(current_replica_version) = current_replica_version {
            // Version is identical, no upgrade needed
            if new_replica_version == current_replica_version {
                info!(
                    self.logger,
                    "Expecting upgrade to version {}, but highest CUP has version {}, running {}",
                    latest_replica_version,
                    new_replica_version,
                    current_replica_version
                );
                return Ok((current_replica_version.clone(), None));
            }
        }

        // Now that we know we are upgrading, persist the CUP.
        let cup_path = self.cup_provider.persist_cup(&cup, latest_subnet_id)?;

        info!(
            self.logger,
            "Replica upgrade detected: old version {:?} -> new version {}",
            current_replica_version,
            new_replica_version
        );

        let replica_version_record = self.registry.get_replica_version_record(
            new_replica_version.clone(),
            self.registry.get_latest_version(),
        )?;

        if ReleasePackageProvider::release_package_is_available(&replica_version_record) {
            info!(self.logger, "Upgrade is guest-OS upgrade");
            // Download base OS upgrade
            let download_path = self
                .release_package_provider
                .make_version_dir(&new_replica_version)?
                .join("base-os.tar.gz");
            info!(self.logger, "Upgrading from {:?}", download_path);
            let _ = self
                .release_package_provider
                .download_release_package(new_replica_version.clone())
                .await?;
            // Better safe than sorry.
            check_file_hash(
                &download_path,
                &replica_version_record.release_package_sha256_hex,
            )
            .expect("Upgrade file with correct checksum needed here");

            let mut script = self.ic_binary_dir.clone();
            script.push("install-upgrade.sh");
            let mut c = Command::new("sudo");
            let out = c
                .arg(script.into_os_string())
                .arg(download_path)
                .output()
                .map_err(|e| NodeManagerError::file_command_error(e, &c))?;

            info!(self.logger, "Installing upgrade {:?}", out);
            if out.status.success() {
                let mut c = Command::new("sudo");
                let out = c
                    .arg("reboot")
                    .output()
                    .map_err(|e| NodeManagerError::file_command_error(e, &c))?;

                info!(self.logger, "Rebooting {:?}", out);

                exit(42);
            } else {
                warn!(self.logger, "Upgrade has failed");

                Err(NodeManagerError::UpgradeError("Upgrade failed".to_string()))
            }
        } else {
            info!(self.logger, "Upgrade is replica/nodemanager upgrade");
            // Download the replica version referred to by the CUP with
            // the new version. Note that we don't know which version we
            // have to upgrade to before we have the CUP.
            //
            // Example: If there are updates to versions v2 and v3 it
            // might be necessary to join v2 to produce a CUP rather than
            // directly joining v3. The only way to learn which version
            // should be booted is by considering CUPs that have been agreed upon by
            // consensus.
            let release_content = self
                .release_package_provider
                .download_release_package(new_replica_version.clone())
                .await?;

            // Release package has been downloaded, set symlink to mark as current
            self.set_current_symlink(&new_replica_version)?;

            // Ensure there is a replica binary available before starting a new Node Manager
            let replica_binary = match &self.force_replica_binary {
                Some(binary) => binary.clone(),
                None => release_content
                    .get_replica_binary()
                    .map(utils::path_to_string)
                    .map_err(NodeManagerError::ReleasePackageError)?,
            };

            if let Ok(node_manager_binary) = release_content.get_node_manager_binary() {
                // We fail if there is a node manager is part of the release package, but we
                // can't determine its sha256 hash.
                let release_node_manager_hash =
                    hex::encode(release_content.get_node_manager_hash().expect(
                        "Failed to determine sha256 hash for node manager in release content",
                    ));

                // Reboot the node manager if the hash of the binary does not match.
                // Will also reboot if the current node manager's binary has cannot be
                // determined.
                info!(
                    self.logger,
                    "release_node_manager_hash: {} current_node_manager_hash: {:?}",
                    release_node_manager_hash,
                    &self.current_node_manager_hash
                );
                if self.current_node_manager_hash != release_node_manager_hash {
                    info!(self.logger, "Restarting node manager due to hash mismatch");
                    self.stop_replica()?;
                    utils::exec_node_manager(&node_manager_binary, &self.logger);
                    // control never reaches this line due to calling 'exec'...
                }
            } else {
                info!(
                    self.logger,
                    "Not upgrading node manager - checksum did not change"
                );
            }

            // Start new replica binary
            self.start_replica(
                replica_binary,
                new_replica_version.clone(),
                cup_path,
                latest_subnet_id,
            )?;
            Ok((
                new_replica_version.clone(),
                Some((latest_subnet_id, cup_public_key)),
            ))
        }
    }

    fn stop_replica(&self) -> NodeManagerResult<()> {
        self.replica_process.lock().unwrap().stop().map_err(|e| {
            NodeManagerError::IoError(
                "Error when attempting to stop replica during upgrade".into(),
                e,
            )
        })
    }

    /// Return the subnet that this node belongs to at the given
    /// Registry version
    fn get_subnet_record(
        &self,
        registry_version: RegistryVersion,
    ) -> NodeManagerResult<(SubnetId, SubnetRecord)> {
        let new_subnet_id = self.registry.get_subnet_id(registry_version)?;
        let new_subnet_record = self
            .registry
            .get_subnet_record(new_subnet_id, registry_version)?;

        Ok((new_subnet_id, new_subnet_record))
    }

    /// Symlink "$replica_binary_dir/current" to the current release package
    ///
    /// On reboot, start-up scripts will use this symlink to start the most
    /// recent Node Manager, instead of a potentially ancient Node Manager
    fn set_current_symlink(&self, replica_version: &ReplicaVersion) -> NodeManagerResult<()> {
        let version_dir = self
            .release_package_provider
            .get_version_dir(replica_version);

        if version_dir.join("nodemanager").exists() {
            let current_dir = self.release_content_dir.join("current");

            // If we delete this, it's not atomic any more.
            // However, symlink does not seem to work if destination already exists.
            let _ = std::fs::remove_file(&current_dir);

            symlink(&version_dir, &current_dir)
                .map_err(|e| NodeManagerError::symlink_error(&version_dir, &current_dir, e))
        } else {
            Ok(())
        }
    }

    /// Stop the current Replica and start a new Replica command
    fn start_replica(
        &self,
        replica_binary: String,
        replica_version: ReplicaVersion,
        cup_path: PathBuf,
        subnet_id: SubnetId,
    ) -> NodeManagerResult<()> {
        info!(self.logger, "Starting new Replica process due to upgrade");
        let cmd = vec![
            format!("--replica-version={}", replica_version.as_ref()),
            format!(
                "--config-file={}",
                utils::path_to_string(self.replica_config_file.clone())
            ),
            format!("--catch-up-package={}", utils::path_to_string(cup_path)),
            format!("--force-subnet={}", subnet_id),
        ];

        self.replica_process
            .lock()
            .unwrap()
            .start(replica_binary, replica_version, cmd)
            .map_err(|e| {
                NodeManagerError::IoError("Error when attempting to start new replica".into(), e)
            })
    }

    async fn check_for_upgrade_once(&mut self) {
        debug!(self.logger, "Checking for release package");
        match self.check_for_upgrade().await {
            Ok((new_version, new_subnet)) => {
                self.replica_version = Some(new_version);
                // For subnet ID other than None, set that.
                if let Some((subnet_id, latest_public_key)) = new_subnet {
                    self.subnet_id = Some(subnet_id);
                    self.high_threshold_pub_key = Some(latest_public_key)
                }
            }
            Err(e) => info!(
                self.logger,
                "Failed to check for or upgrade to release package: {}", e
            ),
        };
    }
}

async fn background_task(mut release_package: ReleasePackage) {
    loop {
        if !release_package
            .enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        release_package.check_for_upgrade_once().await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn get_public_key(
    registry: &Arc<RegistryHelper>,
    registry_version: RegistryVersion,
) -> Option<ThresholdSigPublicKey> {
    registry.get_registry_cup(registry_version).ok().map(|cup| {
        cup.content
            .block
            .get_value()
            .payload
            .as_ref()
            .as_summary()
            .current_transcript(&NiDkgTag::HighThreshold)
            .public_key()
    })
}
