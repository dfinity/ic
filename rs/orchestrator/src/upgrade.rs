use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::error::{OrchestratorError, OrchestratorResult};
use crate::registry_helper::RegistryHelper;
use crate::release_package_provider::ReleasePackageProvider;
use crate::replica_process::ReplicaProcess;
use crate::utils;
use ic_http_utils::file_downloader::FileDownloader;
use ic_interfaces::registry::RegistryClient;
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_registry_client::helper::node::NodeRegistry;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_registry_client::helper::unassigned_nodes::UnassignedNodeRegistry;
use ic_registry_common::local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
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
pub(crate) struct Upgrade {
    registry: Arc<RegistryHelper>,
    replica_process: Arc<Mutex<ReplicaProcess>>,
    release_package_provider: Arc<ReleasePackageProvider>,
    cup_provider: Arc<CatchUpPackageProvider>,
    replica_version: ReplicaVersion,
    replica_config_file: PathBuf,
    ic_binary_dir: PathBuf,
    registry_replicator: Arc<RegistryReplicator>,
    logger: ReplicaLogger,
    node_id: NodeId,
}

impl Upgrade {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry: Arc<RegistryHelper>,
        replica_process: Arc<Mutex<ReplicaProcess>>,
        release_package_provider: Arc<ReleasePackageProvider>,
        cup_provider: Arc<CatchUpPackageProvider>,
        replica_version: ReplicaVersion,
        replica_config_file: PathBuf,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        registry_replicator: Arc<RegistryReplicator>,
        logger: ReplicaLogger,
    ) -> Self {
        let value = Self {
            registry,
            replica_process,
            release_package_provider,
            cup_provider,
            node_id,
            replica_version,
            replica_config_file,
            ic_binary_dir,
            registry_replicator,
            logger,
        };
        value.confirm_boot();
        value
    }

    /// Checks for a new release package, and if found, upgrades to this release
    /// package
    pub(crate) async fn check(&self) -> OrchestratorResult<()> {
        let latest_registry_version = self.registry.get_latest_version();
        // Determine the subnet_id using the local CUP.
        let (subnet_id, local_cup) = if let Some(cup_with_proto) = self.cup_provider.get_local_cup()
        {
            let cup = cup_with_proto.cup;
            let subnet_id =
                get_subnet_id(&*self.registry.registry_client, &cup).map_err(|err| {
                    OrchestratorError::UpgradeError(format!(
                        "Couldn't extract the subnet id from the local CUP: {:?}",
                        err
                    ))
                })?;
            (subnet_id, Some(cup))
        } else {
            match self.registry.get_subnet_id(latest_registry_version) {
                Ok(subnet_id) => {
                    info!(self.logger, "Assignment to subnet {} detected", subnet_id);
                    (subnet_id, None)
                }
                // If no subnet is assigned to the node id, we're unassigned.
                _ => return self.check_for_upgrade_as_unassigned().await,
            }
        };

        // When we arrived here, we are an assigned node.

        // Get the latest available cup from the disk, peears or registry and
        // if the latest CUP is newer than the local one, persist it.
        let cup = self.cup_provider.get_latest_cup(subnet_id).await?;
        if Some(cup.cup.content.height()) > local_cup.map(|cup| cup.content.height()) {
            self.cup_provider.persist_cup(&cup)?;
        }

        // Now when we have the most recent CUP, we check if we're still assigned.
        // If not, go into unassigned state.
        if should_node_become_unassigned(
            &*self.registry.registry_client,
            self.node_id,
            subnet_id,
            &cup.cup,
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

        // Check if we're in an NNS subnet recovery case.
        self.download_registry_and_restart_if_nns_subnet_recovery(
            subnet_id,
            latest_registry_version,
        )
        .await?;

        // If we arrived here, we have the newest CUP and we're still assigned.
        // Now we check if this CUP requires a new replica verison.
        let cup_registry_version = cup.cup.content.registry_version();
        let new_replica_version = self
            .registry
            .get_replica_version(subnet_id, cup_registry_version)?;
        if new_replica_version != self.replica_version {
            info!(
                self.logger,
                "Starting version upgrade: {} -> {}", self.replica_version, new_replica_version
            );
            return self.download_and_upgrade(&new_replica_version).await;
        }

        // This will start a new replica process if none is running.
        self.ensure_replica_is_running(&self.replica_version, subnet_id)?;

        // This will trigger an image download if one is already scheduled but we did not arrive at
        // the corresponding CUP yet.
        self.download_image_if_upgrade_scheduled(subnet_id).await?;

        Ok(())
    }

    // Special case for when we are doing boostrap subnet recovery for
    // nns and replacing the local registry store. Because we replace the
    // contents of the local registry store in the process of doing this, we
    // will not perpetually hit this case, and thus it is not important to
    // check the height.
    async fn download_registry_and_restart_if_nns_subnet_recovery(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        if let Some(registry_contents) = self
            .registry
            .registry_client
            .get_cup_contents(subnet_id, registry_version)
            .ok()
            .and_then(|record| record.value)
        {
            if let Some(registry_store_uri) = registry_contents.registry_store_uri {
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
                downloader
                    .download_and_extract_tar_gz(
                        &registry_store_uri.uri,
                        &local_store_location,
                        Some(registry_store_uri.hash),
                    )
                    .await
                    .map_err(OrchestratorError::FileDownloadError)?;
                if let Err(e) = self.stop_replica() {
                    // Even though we fail to stop the replica, we should still
                    // replace the registry local store, so we simply issue a warning.
                    warn!(self.logger, "Failed to stop replica with error {:?}", e);
                }
                let new_local_store = LocalStoreImpl::new(local_store_location);
                self.registry_replicator
                    .stop_polling_and_set_local_registry_data(&new_local_store);
                utils::reexec_current_process(&self.logger);
            }
        }
        Ok(())
    }

    // Checks if the subnet record for the given subnet_id contains a different replica version.
    // If it is the case, the image will be downloaded. This allows us to decrease the upgrade downtime.
    async fn download_image_if_upgrade_scheduled(
        &self,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<()> {
        let replica_version = self.registry.get_latest_version();
        let new_replica_version = self
            .registry
            .get_replica_version(subnet_id, replica_version)?;
        if new_replica_version != self.replica_version {
            info!(
                self.logger,
                "Version upgrade detected: {} -> {}", self.replica_version, new_replica_version
            );
            self.release_package_provider
                .download_release_package(new_replica_version)
                .await?;
        }
        Ok(())
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
        self.release_package_provider
            .download_release_package(replica_version.clone())
            .await?;
        let image_path = self
            .release_package_provider
            .make_version_dir(replica_version)?
            .join("base-os.tar.gz");
        let mut script = self.ic_binary_dir.clone();
        script.push("install-upgrade.sh");
        let mut c = Command::new("sudo");
        let out = c
            .arg(script.into_os_string())
            .arg(image_path)
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

    /// Stop the current replica process.
    pub fn stop_replica(&self) -> OrchestratorResult<()> {
        self.replica_process.lock().unwrap().stop().map_err(|e| {
            OrchestratorError::IoError(
                "Error when attempting to stop replica during upgrade".into(),
                e,
            )
        })
    }

    // Start the replica process if not running already
    fn ensure_replica_is_running(
        &self,
        replica_version: &ReplicaVersion,
        subnet_id: SubnetId,
    ) -> OrchestratorResult<()> {
        if self.replica_process.lock().unwrap().is_running() {
            return Ok(());
        }
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
                self.replica_config_file.as_path().display()
            ),
            format!("--catch-up-package={}", cup_path.as_path().display()),
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
