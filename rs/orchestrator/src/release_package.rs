use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::error::{OrchestratorError, OrchestratorResult};
use crate::nns_registry_replicator::NnsRegistryReplicator;
use crate::registry_helper::RegistryHelper;
use crate::release_package_provider::ReleasePackageProvider;
use crate::replica_process::ReplicaProcess;
use crate::utils;
use ic_http_utils::file_downloader::FileDownloader;
use ic_interfaces::registry::RegistryClient;
use ic_logger::{debug, error, info, warn, ReplicaLogger};
use ic_registry_client::helper::node::NodeRegistry;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_registry_client::helper::unassigned_nodes::UnassignedNodeRegistry;
use ic_registry_common::local_store::LocalStoreImpl;
use ic_types::consensus::catchup::CUPWithOriginalProtobuf;
use ic_types::consensus::CatchUpPackage;
use ic_types::consensus::HasHeight;
use ic_types::{NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::process::{exit, Command};
use std::sync::{Arc, Mutex};

/// Continuously checks the Registry to determine if this node should upgrade
/// to a new release package, and if so, downloads and extracts this release
/// package and exec's the orchestrator binary contained within
pub(crate) struct ReleasePackage {
    registry: Arc<RegistryHelper>,
    replica_process: Arc<Mutex<ReplicaProcess>>,
    release_package_provider: Arc<ReleasePackageProvider>,
    cup_provider: Arc<CatchUpPackageProvider>,
    replica_version: ReplicaVersion,
    replica_config_file: PathBuf,
    ic_binary_dir: PathBuf,
    nns_registry_replicator: Arc<NnsRegistryReplicator>,
    logger: ReplicaLogger,
    node_id: NodeId,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl ReleasePackage {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        registry: Arc<RegistryHelper>,
        replica_process: Arc<Mutex<ReplicaProcess>>,
        release_package_provider: Arc<ReleasePackageProvider>,
        cup_provider: Arc<CatchUpPackageProvider>,
        replica_version: ReplicaVersion,
        replica_config_file: PathBuf,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        nns_registry_replicator: Arc<NnsRegistryReplicator>,
        logger: ReplicaLogger,
    ) -> Arc<std::sync::atomic::AtomicBool> {
        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let release_package = Self {
            registry,
            replica_process,
            release_package_provider,
            cup_provider,
            node_id,
            replica_version,
            replica_config_file,
            ic_binary_dir,
            nns_registry_replicator,
            logger,
            enabled: enabled.clone(),
        };
        release_package.confirm_boot();
        release_package.check_for_upgrade_once().await;
        tokio::spawn(background_task(release_package));
        enabled
    }

    /// Checks for a new release package, and if found, upgrades to this release
    /// package
    pub(crate) async fn check_for_upgrade(&self) -> OrchestratorResult<()> {
        let latest_registry_version = self.registry.get_latest_version();
        // Determine the subnet_id using the local CUP.
        let (latest_subnet_id, local_cup) =
            if let Some(cup_with_proto) = self.cup_provider.get_local_cup() {
                let cup = cup_with_proto.cup;
                let subnet_id =
                    get_subnet_id(&*self.registry.registry_client, &cup).map_err(|err| {
                        OrchestratorError::UpgradeError(format!(
                            "Couldn't extract the subnet id from the local CUP: {:?}",
                            err
                        ))
                    })?;
                if should_node_become_unassigned(
                    &*self.registry.registry_client,
                    self.node_id,
                    subnet_id,
                    &cup,
                ) {
                    self.stop_replica()?;
                    remove_node_state(
                        self.replica_config_file.clone(),
                        self.cup_provider.get_cup_path(),
                    )
                    .map_err(OrchestratorError::UpgradeError)?;
                    info!(self.logger, "Subnet state removed");
                    return Ok(());
                }
                (subnet_id, Some(cup))
            } else {
                match self.registry.get_subnet_id(latest_registry_version) {
                    Ok(subnet_id) => (subnet_id, None),
                    // If no subnet is assigned to the node id, we're unassigned.
                    _ => return self.check_for_upgrade_as_unassigned().await,
                }
            };

        let cup = self.cup_provider.get_latest_cup(latest_subnet_id).await?;

        // If the latest CUP is newer than the local one, persist it.
        if Some(cup.cup.content.height()) > local_cup.map(|cup| cup.content.height()) {
            self.cup_provider.persist_cup(&cup)?;
        }

        // Now we know the subnet_id and we're assigned; start the replica if necessary.
        if !self.replica_process.lock().unwrap().is_running() {
            return self.start_replica(&self.replica_version, latest_subnet_id);
        }

        // 0. Special case for when we are doing boostrap subnet recovery for
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
                .get_registry_cup(latest_registry_version, latest_subnet_id)
                .expect("A registry cup must be present in the the registry");

            self.cup_provider
                .persist_cup(&CUPWithOriginalProtobuf::from_cup(cup))?;

            warn!(
                self.logger,
                "Downloading registry data from {} with hash {} for subnet recovery",
                registry_store_uri.uri,
                registry_store_uri.hash,
            );

            let downloader = FileDownloader::new(Some(self.logger.clone()));
            let local_store_location = tempfile::tempdir()
                .expect("temporary location for local store download could not be created")
                .into_path();
            std::fs::create_dir_all(&local_store_location).expect("Directory should be created");

            if let Err(e) = downloader
                .download_and_extract_tar_gz(
                    &registry_store_uri.uri,
                    &local_store_location,
                    Some(registry_store_uri.hash),
                )
                .await
            {
                warn!(
                    self.logger,
                    "Download of registry store for nns subnet recovery failed {}", e,
                );
                return Err(OrchestratorError::FileDownloadError(e));
            }

            if let Err(e) = self.stop_replica() {
                // Even though we fail to stop the replica, we should still
                // replace the registry local store, so we simply issue a warning.
                warn!(self.logger, "Failed to stop replica with error {:?}", e);
            }

            let new_local_store = LocalStoreImpl::new(local_store_location);
            self.nns_registry_replicator
                .stop_polling_and_set_local_registry_data(&new_local_store);

            utils::reexec_current_process(&self.logger);
        }

        let cup_registry_version = cup.cup.content.registry_version();

        let subnet_record = self
            .registry
            .get_subnet_record(latest_subnet_id, cup_registry_version)?;

        // Determine version of release in the latest registry version.
        let latest_replica_version =
            RegistryHelper::get_replica_version_from_subnet_record(subnet_record)?;

        // If we are already running what is the latest version in the registry,
        // there cannot be an upgrade. No need to check for CUPs, simply return.
        // The exception to this is when we have a recovery CUP (which we can
        // detect by seeing that the public key of the subnet has changed).

        // Note that we do not allow version transitions v1 -> v2 -> v1.
        // Even without this optimization, the orchestrator would not trigger restarting
        // the replica (e.g. in cases we directly upgrade v1 -> v1).
        if latest_replica_version == self.replica_version {
            debug!(
                self.logger,
                "Latest version from registry {} - already running, no CUP fetching",
                latest_replica_version
            );
            return Ok(());
        }

        info!(
            self.logger,
            "Runnig upgrade loop. Latest IC version in registry: {}, running IC version {:?}",
            latest_replica_version,
            self.replica_version.as_ref(),
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

        // For the CUP's registry version, get replica version of current subnet.
        let subnet_record = self
            .registry
            .get_subnet_record(latest_subnet_id, cup_registry_version)?;
        let new_replica_version =
            &RegistryHelper::get_replica_version_from_subnet_record(subnet_record)?;

        // Version is identical, no upgrade needed
        if new_replica_version == &self.replica_version {
            info!(
                self.logger,
                "Expecting upgrade to version {}, but highest CUP has version {}, running {}",
                latest_replica_version,
                new_replica_version,
                self.replica_version
            );
            return Ok(());
        }

        // Now that we know we are upgrading, persist the CUP.
        self.cup_provider.persist_cup(&cup)?;

        info!(
            self.logger,
            "Replica upgrade detected: old version {:?} -> new version {}",
            self.replica_version,
            new_replica_version
        );

        self.download_and_upgrade(new_replica_version).await
    }

    async fn check_for_upgrade_as_unassigned(&self) -> OrchestratorResult<()> {
        let registry = &self.registry.registry_client;
        match registry.get_unassigned_nodes_config(registry.get_latest_version()) {
            Ok(Some(record)) => {
                let replica_version = ReplicaVersion::try_from(record.replica_version.as_ref())
                    .map_err(|err| {
                        OrchestratorError::UpgradeError(format!(
                            "Couldn't parse the replica version: {}",
                            err
                        ))
                    })?;
                if self.replica_version == replica_version {
                    return Ok(());
                }
                info!(
                    self.logger,
                    "Replica upgrade on unassigned node detected: old version {}, new version {}",
                    self.replica_version,
                    replica_version
                );
                self.download_and_upgrade(&replica_version).await
            }
            _ => Err(OrchestratorError::UpgradeError(
                "No replica version for unassigned nodes found".to_string(),
            )),
        }
    }

    async fn download_and_upgrade<T>(
        &self,
        replica_version: &ReplicaVersion,
    ) -> OrchestratorResult<T> {
        let download_path = self
            .release_package_provider
            .make_version_dir(replica_version)?
            .join("base-os.tar.gz");
        info!(self.logger, "Upgrading from {:?}", download_path);
        let _ = self
            .release_package_provider
            .download_release_package(replica_version.clone())
            .await?;

        let mut script = self.ic_binary_dir.clone();
        script.push("install-upgrade.sh");
        let mut c = Command::new("sudo");
        let out = c
            .arg(script.into_os_string())
            .arg(download_path)
            .output()
            .map_err(|e| OrchestratorError::file_command_error(e, &c))?;

        info!(self.logger, "Installing upgrade {:?}", out);
        if out.status.success() {
            let mut c = Command::new("sudo");
            let out = c
                .arg("reboot")
                .output()
                .map_err(|e| OrchestratorError::file_command_error(e, &c))?;

            info!(self.logger, "Rebooting {:?}", out);

            exit(42);
        } else {
            warn!(self.logger, "Upgrade has failed");

            Err(OrchestratorError::UpgradeError(
                "Upgrade failed".to_string(),
            ))
        }
    }

    fn stop_replica(&self) -> OrchestratorResult<()> {
        self.replica_process.lock().unwrap().stop().map_err(|e| {
            OrchestratorError::IoError(
                "Error when attempting to stop replica during upgrade".into(),
                e,
            )
        })
    }

    // Stop the current Replica and start a new Replica command
    fn start_replica(
        &self,
        replica_version: &ReplicaVersion,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<()> {
        info!(self.logger, "Starting new replica process due to upgrade");
        let cup_path = self.cup_provider.get_cup_path();
        let replica_binary = self
            .ic_binary_dir
            .join("replica")
            .as_path()
            .display()
            .to_string();
        let cmd = vec![
            format!("--replica-version={}", replica_version.as_ref()),
            format!(
                "--config-file={}",
                self.replica_config_file.as_path().display().to_string()
            ),
            format!(
                "--catch-up-package={}",
                cup_path.as_path().display().to_string()
            ),
            format!("--force-subnet={}", subnet_id),
        ];

        self.replica_process
            .lock()
            .unwrap()
            .start(replica_binary, replica_version, cmd)
            .map_err(|e| {
                OrchestratorError::IoError("Error when attempting to start new replica".into(), e)
            })
    }

    async fn check_for_upgrade_once(&self) {
        info!(self.logger, "Checking for release package");
        if let Err(e) = self.check_for_upgrade().await {
            warn!(self.logger, "Check for upgrade failed: {}", e);
        };
    }

    // Calls a corresponding script to "confirm" that the base OS could boot
    // successfully. With a confirmation the image will be reverted on the next
    // restart.
    fn confirm_boot(&self) {
        if let Err(err) = Command::new("sudo")
            .arg(self.ic_binary_dir.join("manageboot.sh").into_os_string())
            .arg("confirm")
            .output()
        {
            error!(self.logger, "Could not confirm the boot: {:?}", err);
        }
    }
}

async fn background_task(release_package: ReleasePackage) {
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

// Returns the subnet id for the given CUP.
fn get_subnet_id(registry: &dyn RegistryClient, cup: &CatchUpPackage) -> Result<SubnetId, String> {
    let dkg_summary = &cup
        .content
        .block
        .get_value()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    // Note that although sometimes CUPs have no signatures (e.g. genesis and
    // recovery CUPs) they always have the signer id (the DKG id), which is taken
    // from the high-threshold transcript when we build a genesis/recovery CUP.
    let dkg_id = cup.signature.signer;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTargetSubnet;
    // If the DKG key material was signed by the subnet itself — use it, if not, get
    // the subnet id from the registry.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, than the local CUP is a genesis or recovery CUP of an application
        // subnet. We cannot derive the subnet id from it, so we use the registry version of
        // that CUP and the node id of one of the high-threshold committee members, to find
        // out to which subnet this node belongs to.
        NiDkgTargetSubnet::Remote(_) => {
            let node_id = dkg_summary
                .current_transcripts()
                .values()
                .next()
                .ok_or("No current transcript found")?
                .committee
                .get()
                .iter()
                .next()
                .ok_or("No nodes in current transcript committee found")?;
            match registry.get_subnet_id_from_node_id(*node_id, dkg_summary.registry_version) {
                Ok(Some(subnet_id)) => Ok(subnet_id),
                other => Err(format!(
                    "Couldn't get the subnet id from the registry for node {:?}: {:?}",
                    node_id, other
                )),
            }
        }
    }
}

// Checks if the node still belongs to the subnet it was assigned the last time.
// We decide this by checking the subnet membership starting from the oldest
// relevant version of the local CUP and ending with the latest registry
// version.
fn should_node_become_unassigned(
    registry: &dyn RegistryClient,
    node_id: NodeId,
    subnet_id: SubnetId,
    cup: &CatchUpPackage,
) -> bool {
    let dkg_summary = &cup
        .content
        .block
        .get_value()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    let oldest_relevant_version = dkg_summary.get_subnet_membership_version().get();
    let latest_registry_version = registry.get_latest_version().get();
    // Make sure that if the latest registry version is for some reason violating the
    // assumption that it's higher/equal than any other version used in the system, we still
    // do not remove the subnet state by a mistake.
    if latest_registry_version < oldest_relevant_version {
        return false;
    }
    for version in oldest_relevant_version..=latest_registry_version {
        if let Ok(Some(members)) =
            registry.get_node_ids_on_subnet(subnet_id, RegistryVersion::from(version))
        {
            if members.iter().any(|id| id == &node_id) {
                return false;
            }
        }
    }
    true
}

// Deletes the subnet state consisting of the consensus pool, execution state
// and the local CUP.
fn remove_node_state(replica_config_file: PathBuf, cup_path: PathBuf) -> Result<(), String> {
    use ic_config::{Config, ConfigSource};
    use std::fs::{remove_dir_all, remove_file};
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .map_err(|err| format!("Couldn't create a temporary directory: {:?}", err))?;
    let config = Config::load_with_tmpdir(
        ConfigSource::File(replica_config_file),
        tmpdir.path().to_path_buf(),
    );

    let consensus_pool_path = config.artifact_pool.consensus_pool_path;
    remove_dir_all(&consensus_pool_path).map_err(|err| {
        format!(
            "Couldn't delete the consensus pool at {:?}: {:?}",
            consensus_pool_path, err
        )
    })?;

    let state_path = config.state_manager.state_root();
    remove_dir_all(&state_path)
        .map_err(|err| format!("Couldn't delete the state at {:?}: {:?}", state_path, err))?;

    remove_file(&cup_path)
        .map_err(|err| format!("Couldn't delete the CUP at {:?}: {:?}", cup_path, err))?;

    Ok(())
}
