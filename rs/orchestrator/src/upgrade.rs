use crate::{
    catch_up_package_provider::CatchUpPackageProvider,
    error::{OrchestratorError, OrchestratorResult},
    metrics::OrchestratorMetrics,
    orchestrator::SubnetAssignment,
    process_manager::{Process, ProcessManager},
    registry_helper::RegistryHelper,
};
use async_trait::async_trait;
use guest_upgrade_server::DiskEncryptionKeyExchangeServerAgent;
use ic_consensus_dkg::get_vetkey_public_keys;
use ic_crypto::get_master_public_key_from_transcript;
use ic_http_utils::file_downloader::FileDownloader;
use ic_image_upgrader::{
    ImageUpgrader, State,
    error::{UpgradeError, UpgradeResult},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::proxy::try_from_option_field;
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_registry_client_helpers::{node::NodeRegistry, subnet::SubnetRegistry};
use ic_registry_local_store::{LocalStore, LocalStoreImpl};
use ic_registry_replicator::RegistryReplicator;
use ic_types::{
    Height, NodeId, RegistryVersion, ReplicaVersion, SubnetId,
    consensus::{CatchUpPackage, HasHeight},
    crypto::{
        canister_threshold_sig::MasterPublicKey,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTargetSubnet},
    },
};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

const KEY_CHANGES_FILENAME: &str = "key_changed_metric.cbor";

#[cfg(not(test))]
const TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR: Duration = Duration::from_secs(1800); // 30 minutes
// For ease of testing, we reduce this timeout in tests.
#[cfg(test)]
const TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR: Duration = Duration::from_secs(5);

#[must_use = "This may be a `Stop` variant, which should be handled"]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OrchestratorControlFlow {
    /// The node is assigned to the subnet with the given subnet id.
    Assigned(SubnetId),
    /// The node is in the process of leaving subnet with the given id.
    Leaving(SubnetId),
    /// The node is unassigned.
    Unassigned,
    /// The node should stop the orchestrator.
    Stop,
}

pub struct ReplicaProcess {
    version: ReplicaVersion,
    binary: String,
    args: Vec<String>,
}

impl Process for ReplicaProcess {
    const NAME: &'static str = "Replica";

    type Version = ReplicaVersion;

    fn get_version(&self) -> &Self::Version {
        &self.version
    }

    fn get_binary(&self) -> &str {
        &self.binary
    }

    fn get_args(&self) -> &[String] {
        &self.args
    }

    fn get_env(&self) -> HashMap<String, String> {
        HashMap::new()
    }
}

/// Trait for the registry replicator used by the upgrade module.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait RegistryReplicatorForUpgrade: Send + Sync {
    /// Stops polling and sets the local registry data to what is contained in the provided local store.
    async fn stop_polling_and_set_local_registry_data(&self, new_local_store: &dyn LocalStore);

    /// Returns true if the replicator has replicated all versions that were certified before the
    /// replicator was started.
    fn has_replicated_all_versions_certified_before_init(&self) -> bool;
}

#[async_trait]
impl RegistryReplicatorForUpgrade for RegistryReplicator {
    async fn stop_polling_and_set_local_registry_data(&self, new_local_store: &dyn LocalStore) {
        self.stop_polling_and_set_local_registry_data(new_local_store)
            .await
    }

    fn has_replicated_all_versions_certified_before_init(&self) -> bool {
        self.has_replicated_all_versions_certified_before_init()
    }
}

// TODO(NODE-1754): Remove the following trait after registry changes concerning recalled replica
// versions are merged. This temporary implementation is to test the code behaviour even though the
// registry does not yet support recalled replica versions.
// Remove this trait when the changes are merged.
#[cfg_attr(test, mockall::automock)]
pub trait RegistryHelperWithRecalledReplicaVersions: Send + Sync {
    fn get_recalled_replica_versions(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<Vec<ReplicaVersion>>;

    fn get_latest_version(&self) -> RegistryVersion;

    fn get_registry_client(&self) -> &dyn RegistryClient;

    fn get_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId>;

    fn get_root_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId>;

    fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion>;

    fn get_replica_version_record(
        &self,
        replica_version_id: ReplicaVersion,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersionRecord>;

    fn get_api_boundary_node_version(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion>;

    fn get_unassigned_replica_version(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion>;
}

impl RegistryHelperWithRecalledReplicaVersions for RegistryHelper {
    fn get_recalled_replica_versions(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<Vec<ReplicaVersion>> {
        self.get_recalled_replica_versions(subnet_id, registry_version)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.get_latest_version()
    }

    fn get_registry_client(&self) -> &dyn RegistryClient {
        self.get_registry_client()
    }

    fn get_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId> {
        self.get_subnet_id(version)
    }

    fn get_root_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId> {
        self.get_root_subnet_id(version)
    }

    fn get_replica_version(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        self.get_replica_version(subnet_id, registry_version)
    }

    fn get_replica_version_record(
        &self,
        replica_version_id: ReplicaVersion,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersionRecord> {
        self.get_replica_version_record(replica_version_id, version)
    }

    fn get_api_boundary_node_version(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        self.get_api_boundary_node_version(node_id, version)
    }

    fn get_unassigned_replica_version(
        &self,
        version: RegistryVersion,
    ) -> OrchestratorResult<ReplicaVersion> {
        self.get_unassigned_replica_version(version)
    }
}

/// Provides function to continuously check the Registry to determine if this
/// node should upgrade to a new release package, and if so, downloads and
/// extracts this release package and exec's the orchestrator binary contained
/// within.
pub(crate) struct Upgrade {
    pub registry: Arc<dyn RegistryHelperWithRecalledReplicaVersions>,
    pub metrics: Arc<OrchestratorMetrics>,
    replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
    cup_provider: CatchUpPackageProvider,
    subnet_assignment: Arc<RwLock<SubnetAssignment>>,
    replica_version: ReplicaVersion,
    replica_hash: String,
    replica_config_file: PathBuf,
    pub ic_binary_dir: PathBuf,
    pub image_path: PathBuf,
    pub replica_path: PathBuf,
    registry_replicator: Arc<dyn RegistryReplicatorForUpgrade>,
    init_time: Instant,
    pub logger: ReplicaLogger,
    node_id: NodeId,
    disk_encryption_key_exchange_agent: Option<DiskEncryptionKeyExchangeServerAgent>,
    /// The replica version that is prepared by 'prepare_upgrade' to upgrade to.
    pub prepared_upgrade_version: Option<ReplicaVersion>,
    pub orchestrator_data_directory: PathBuf,
}

impl Upgrade {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        registry: Arc<dyn RegistryHelperWithRecalledReplicaVersions>,
        metrics: Arc<OrchestratorMetrics>,
        replica_process: Arc<Mutex<ProcessManager<ReplicaProcess>>>,
        cup_provider: CatchUpPackageProvider,
        subnet_assignment: Arc<RwLock<SubnetAssignment>>,
        replica_version: ReplicaVersion,
        replica_hash: String,
        replica_config_file: PathBuf,
        node_id: NodeId,
        ic_binary_dir: PathBuf,
        registry_replicator: Arc<dyn RegistryReplicatorForUpgrade>,
        release_content_dir: PathBuf,
        logger: ReplicaLogger,
        orchestrator_data_directory: PathBuf,
        disk_encryption_key_exchange_agent: Option<DiskEncryptionKeyExchangeServerAgent>,
    ) -> Self {
        let init_time = Instant::now();

        let value = Self {
            registry,
            metrics,
            replica_process,
            cup_provider,
            subnet_assignment,
            node_id,
            replica_version,
            replica_hash,
            replica_config_file,
            ic_binary_dir,
            image_path: release_content_dir.join("image.bin"),
            replica_path: release_content_dir.join("replica"),
            registry_replicator,
            init_time,
            logger: logger.clone(),
            prepared_upgrade_version: None,
            orchestrator_data_directory,
            disk_encryption_key_exchange_agent,
        };
        if let Err(e) = value.report_reboot_time() {
            warn!(logger, "Cannot report the reboot time: {}", e);
        }
        if let Err(e) = report_master_public_key_changed_metric(
            value.orchestrator_data_directory.join(KEY_CHANGES_FILENAME),
            &value.metrics,
        ) {
            warn!(
                logger,
                "Cannot report master public key changed metric: {}", e
            );
        }
        value.confirm_boot().await;
        value
    }

    fn report_reboot_time(&self) -> OrchestratorResult<()> {
        let elapsed_time = self.get_time_since_last_reboot_trigger()?;
        self.metrics
            .reboot_duration
            .set(elapsed_time.as_secs() as i64);
        Ok(())
    }

    /// This function is responsible for:
    /// 1. Determining whether we are assigned to a subnet or unassigned. The field
    ///    `self.subnet_assignment` is updated accordingly for other tasks of the orchestrator to
    ///    use.
    /// 2. Detecting if a recovery is taking place (i.e. there is a CUP in the registry with higher
    ///    height than any available).
    /// 3. Downloading and upgrading to a new replica version if necessary.
    /// 4. Launching the replica process if assigned to a subnet.
    /// 5. Stopping the replica process and removing the node state if leaving the subnet.
    pub(crate) async fn check(&mut self) -> OrchestratorResult<OrchestratorControlFlow> {
        let latest_registry_version = self.registry.get_latest_version();

        let maybe_local_cup_proto = self.cup_provider.get_local_cup_proto();
        let maybe_local_cup = maybe_local_cup_proto.as_ref().and_then(|proto| {
            CatchUpPackage::try_from(proto)
                .inspect_err(|err| {
                    error!(self.logger, "Failed to deserialize CatchUpPackage: {}", err);
                })
                .ok()
        });
        // Determine the subnet_id using the local CUP.
        let subnet_id = match (&maybe_local_cup, &maybe_local_cup_proto) {
            (Some(cup), _) => {
                get_subnet_id(self.registry.get_registry_client(), cup).map_err(|err| {
                    OrchestratorError::UpgradeError(format!(
                        "Couldn't determine the subnet id: {err:?}"
                    ))
                })?
            }
            (None, Some(proto)) => {
                // We found a local CUP proto that we can't deserialize. This may only happen
                // if this is the first CUP we are reading on a new replica version after an
                // upgrade. This means we have to be an assigned node, otherwise we would have
                // left the subnet and deleted the CUP before upgrading to this version.
                // The only way to leave this branch is via subnet recovery.
                self.metrics.critical_error_cup_deserialization_failed.inc();

                // Try to find the subnet ID by deserializing only the NiDkgId. If it fails
                // we will have to recover using failover nodes.
                let nidkg_id: NiDkgId = try_from_option_field(proto.signer.clone(), "NiDkgId")
                    .map_err(|err| {
                        OrchestratorError::UpgradeError(format!(
                            "Couldn't deserialize NiDkgId to determine the subnet id: {err:?}"
                        ))
                    })?;

                match nidkg_id.target_subnet {
                    NiDkgTargetSubnet::Local => nidkg_id.dealer_subnet,
                    NiDkgTargetSubnet::Remote(_) => {
                        // If this CUP was created by a remote subnet, then it is a genesis/recovery
                        // CUP. This is the only case in the branch where we can trust the subnet ID
                        // of the latest registry version, as switching to a registry CUP "resets" the
                        // "oldest registry version in use" which is responsible for subnet membership.
                        match self.registry.get_subnet_id(latest_registry_version) {
                            Ok(subnet_id) => subnet_id,
                            Err(OrchestratorError::NodeUnassignedError(_, _)) => {
                                // If the registry says that we are unassigned, this unassignment
                                // must have happened after the registry CUP triggering the upgrade.
                                // Otherwise we would have left the subnet before upgrading. This means
                                // we will trust the registry and go ahead with removing the node's state
                                // including the broken local CUP.

                                *self.subnet_assignment.write().unwrap() =
                                    SubnetAssignment::Unassigned;

                                self.remove_state().await.inspect_err(|_| {
                                    self.metrics.critical_error_state_removal_failed.inc();
                                })?;

                                return Ok(OrchestratorControlFlow::Unassigned);
                            }
                            Err(other) => return Err(other),
                        }
                    }
                }
            }
            (None, None) => {
                // If there is no local CUP, we check the registry for subnet assignment.
                match self.registry.get_subnet_id(latest_registry_version) {
                    Ok(subnet_id) => {
                        info!(self.logger, "Assignment to subnet {} detected", subnet_id);
                        subnet_id
                    }
                    Err(OrchestratorError::NodeUnassignedError(_, _)) => {
                        // At this point, we know we are unassigned. We return from the function
                        // here, after checking for an upgrade as an unassigned node.
                        *self.subnet_assignment.write().unwrap() = SubnetAssignment::Unassigned;

                        return self
                            .check_for_upgrade_as_unassigned(latest_registry_version)
                            .await;
                    }
                    Err(other) => return Err(other),
                }
            }
        };

        // When we arrived here, we are an assigned node.
        *self.subnet_assignment.write().unwrap() = SubnetAssignment::Assigned(subnet_id);

        let old_cup_height = maybe_local_cup.as_ref().map(HasHeight::height);

        // Get the latest available CUP from the disk, peers or registry and
        // persist it if necessary.
        let latest_cup = self
            .cup_provider
            .get_latest_cup(maybe_local_cup_proto, subnet_id)
            .await?;

        // If we replaced the previous local CUP, compare potential threshold master public keys with
        // the ones in the new CUP, to make sure they haven't changed. Raise an alert if they did.
        if let Some(old_cup) = maybe_local_cup
            && old_cup.height() < latest_cup.height()
        {
            compare_master_public_keys(
                &old_cup,
                &latest_cup,
                self.metrics.as_ref(),
                self.orchestrator_data_directory.join(KEY_CHANGES_FILENAME),
                &self.logger,
            );
        }

        // If the CUP is unsigned, it's a registry CUP and we're in a genesis or subnet
        // recovery scenario. Check if we're in an NNS subnet recovery case and download
        // the new registry if needed.
        if !latest_cup.is_signed() {
            info!(
                self.logger,
                "The latest CUP (registry version={}, height={}) is unsigned: \
                a subnet genesis/recovery is in progress",
                latest_cup.content.registry_version(),
                latest_cup.height(),
            );

            self.download_registry_and_restart_if_nns_subnet_recovery(
                subnet_id,
                latest_registry_version,
            )
            .await?;
        }

        // Now when we have the most recent CUP, we check if we're still assigned.
        // If not, go into unassigned state.
        let flow = match should_node_become_unassigned(
            self.registry.get_registry_client(),
            latest_registry_version,
            self.node_id,
            subnet_id,
            &latest_cup,
        ) {
            UnassignmentDecision::StayInSubnet => OrchestratorControlFlow::Assigned(subnet_id),
            UnassignmentDecision::Later => OrchestratorControlFlow::Leaving(subnet_id),
            UnassignmentDecision::Now => {
                // We are no longer part of the subnet.
                *self.subnet_assignment.write().unwrap() = SubnetAssignment::Unassigned;

                self.stop_replica()?;

                self.remove_state().await.inspect_err(|_| {
                    self.metrics.critical_error_state_removal_failed.inc();
                })?;

                return Ok(OrchestratorControlFlow::Unassigned);
            }
        };

        // If we arrived here, we have the newest CUP and we're still assigned.
        // Now we check if this CUP requires a new replica version.
        let cup_registry_version = latest_cup.content.registry_version();
        let new_replica_version = self
            .registry
            .get_replica_version(subnet_id, cup_registry_version)?;

        if self.is_slow_upgrade(&new_replica_version)? {
            if new_replica_version != self.replica_version {
                self.ensure_upgrade_should_be_executed(
                    subnet_id,
                    latest_registry_version,
                    &new_replica_version,
                )?;

                info!(
                    self.logger,
                    "Starting version upgrade at CUP registry version {}: {} -> {}",
                    cup_registry_version,
                    self.replica_version,
                    new_replica_version
                );
                // Only downloads the new image if it doesn't already exists locally, i.e. it
                // was previously downloaded by `prepare_upgrade_if_scheduled()`, see
                // below.
                return self
                    .execute_upgrade(&new_replica_version, Some(&subnet_id))
                    .await
                    .map_err(OrchestratorError::from)
                    // Always reboot after "slow" upgrades
                    .map(|_rebooting| OrchestratorControlFlow::Stop);
            }
        } else {
            let (_url, new_replica_hash) = self.get_replica_urls_and_hash(&new_replica_version)?;
            let new_replica_hash = new_replica_hash.expect("Fast upgrades require hash to be set");
            if new_replica_hash != self.replica_hash {
                self.ensure_upgrade_should_be_executed(
                    subnet_id,
                    latest_registry_version,
                    &new_replica_version,
                )?;

                info!(
                    self.logger,
                    "Starting version upgrade at CUP registry version {}: {} -> {}",
                    cup_registry_version,
                    self.replica_hash,
                    new_replica_hash
                );
                // Only downloads the new image if it doesn't already exists locally, i.e. it
                // was previously downloaded by `prepare_upgrade_if_scheduled()`, see
                // below.
                match self
                    .execute_upgrade(&new_replica_version, Some(&subnet_id))
                    .await
                    .map_err(OrchestratorError::from)?
                {
                    State::Rebooting => return Ok(OrchestratorControlFlow::Stop),
                    State::Continue => return Ok(flow),
                }
            }
        }

        // If we arrive here, we are on the newest replica version.
        // Now we check if a subnet recovery is in progress.
        // If it is, we restart to pass the unsigned CUP to consensus.
        self.stop_replica_if_new_recovery_cup(&latest_cup, old_cup_height);

        // This will start a new replica process if none is running.
        self.ensure_replica_is_running(&self.replica_version, subnet_id)?;

        // This will trigger an image download if one is already scheduled but we did
        // not arrive at the corresponding CUP yet.
        self.prepare_upgrade_if_scheduled(subnet_id, latest_registry_version)
            .await?;

        Ok(flow)
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    // Special case for when we are doing bootstrap subnet recovery for
    // nns and replacing the local registry store. Because we replace the
    // contents of the local registry store in the process of doing this, we
    // will not perpetually hit this case, and thus it is not important to
    // check the height.
    async fn download_registry_and_restart_if_nns_subnet_recovery(
        &self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        let Some(registry_store_uri) = self
            .registry
            .get_registry_client()
            .get_cup_contents(subnet_id, registry_version)
            .ok()
            .and_then(|record| record.value)
            .and_then(|registry_contents| registry_contents.registry_store_uri)
        else {
            return Ok(());
        };

        warn!(
            self.logger,
            "Downloading registry data from {} with hash {} for subnet recovery",
            registry_store_uri.uri,
            registry_store_uri.hash,
        );
        let downloader = FileDownloader::new(Some(self.logger.clone()));
        let local_store_location = tempfile::tempdir()
            .expect("temporary location for local store download could not be created")
            .keep();
        downloader
            .download_and_extract_tar(
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
            .stop_polling_and_set_local_registry_data(&new_local_store)
            .await;
        // Restart the current process to pick up the new local store.
        // The call should not return. If it does, it is an error.
        Err(reexec_current_process(&self.logger))
    }

    async fn remove_state(&self) -> OrchestratorResult<()> {
        // Reset the key changed errors counter to not raise alerts in other subnets
        self.metrics.master_public_key_changed_errors.reset();
        remove_node_state(
            self.replica_config_file.clone(),
            self.cup_provider.get_cup_path(),
            self.orchestrator_data_directory.clone(),
        )
        .map_err(OrchestratorError::UpgradeError)?;
        info!(self.logger, "Subnet state removed");

        let instant = Instant::now();
        sync_and_trim_fs(&self.logger)
            .await
            .map_err(OrchestratorError::UpgradeError)?;
        let elapsed = instant.elapsed().as_millis();
        self.metrics.fstrim_duration.set(elapsed as i64);
        info!(
            self.logger,
            "Filesystem synced and trimmed in {}ms", elapsed
        );

        Ok(())
    }

    // Checks if the subnet record for the given subnet_id contains a different
    // replica version. If it is the case, the image will be downloaded. This
    // allows us to decrease the upgrade downtime.
    async fn prepare_upgrade_if_scheduled(
        &mut self,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<()> {
        let expected_replica_version = self
            .registry
            .get_replica_version(subnet_id, registry_version)?;

        if self.is_slow_upgrade(&expected_replica_version)? {
            if expected_replica_version != self.replica_version {
                info!(
                    self.logger,
                    "Replica version upgrade detected at registry version {}: {} -> {}",
                    registry_version,
                    self.replica_version,
                    expected_replica_version
                );
                self.prepare_upgrade(&expected_replica_version).await?
            }
        } else {
            let (_url, expected_replica_hash) =
                self.get_replica_urls_and_hash(&expected_replica_version)?;
            let expected_replica_hash =
                expected_replica_hash.expect("Fast upgrades require hash to be set");
            if expected_replica_hash != self.replica_hash {
                info!(
                    self.logger,
                    "Replica version upgrade detected at registry version {}: {} -> {}",
                    registry_version,
                    self.replica_hash,
                    expected_replica_hash
                );
                self.prepare_upgrade(&expected_replica_version).await?
            }
        }
        Ok(())
    }

    async fn check_for_upgrade_as_unassigned(
        &mut self,
        registry_version: RegistryVersion,
    ) -> OrchestratorResult<OrchestratorControlFlow> {
        // If the node is a boundary node, we upgrade to that version, otherwise we upgrade to the unassigned version
        let replica_version = self
            .registry
            .get_api_boundary_node_version(self.node_id, registry_version)
            .or_else(|err| match err {
                OrchestratorError::ApiBoundaryNodeMissingError(_, _) => self
                    .registry
                    .get_unassigned_replica_version(registry_version),
                err => Err(err),
            })?;

        if self.is_slow_upgrade(&replica_version)? {
            if self.replica_version == replica_version {
                return Ok(OrchestratorControlFlow::Unassigned);
            }

            info!(
                self.logger,
                "Replica upgrade on unassigned node detected: old version {}, new version {}",
                self.replica_version,
                replica_version
            );

            return self
                .execute_upgrade(&replica_version, None)
                .await
                .map_err(OrchestratorError::from)
                // Always reboot after "slow" upgrades
                .map(|_rebooting| OrchestratorControlFlow::Stop);
        } else {
            let (_url, replica_hash) = self.get_replica_urls_and_hash(&replica_version)?;
            let replica_hash = replica_hash.expect("Fast upgrades require hash to be set");
            if replica_hash != self.replica_hash {
                info!(
                    self.logger,
                    "Replica upgrade on unassigned node detected: old version {}, new version {:?}",
                    self.replica_hash,
                    replica_hash
                );

                match self
                    .execute_upgrade(&replica_version, None)
                    .await
                    .map_err(OrchestratorError::from)?
                {
                    State::Rebooting => return Ok(OrchestratorControlFlow::Stop),
                    State::Continue => return Ok(OrchestratorControlFlow::Unassigned),
                }
            }
        }

        Ok(OrchestratorControlFlow::Unassigned)
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

    /// Ensure that an upgrade to the given `new_replica_version` should be executed.
    /// Returns an error if the upgrade should be delayed or blocked, for example due to the new
    /// replica version being recalled.
    fn ensure_upgrade_should_be_executed(
        &self,
        subnet_id: SubnetId,
        latest_registry_version: RegistryVersion,
        new_replica_version: &ReplicaVersion,
    ) -> OrchestratorResult<()> {
        if subnet_id == self.registry.get_root_subnet_id(latest_registry_version)? {
            // Upgrades on the NNS subnet are never blocked or delayed.
            return Ok(());
        }

        // Until the replicator has caught up with the registry canister, we cannot be entirely sure
        // that the latest registry version that we have locally correctly reflects the recalled
        // replica versions. Thus, we delay the upgrade until then.
        // An exception is made after some time as a safeguard against staying stuck in this state
        // forever, for example if the NNS subnet is unreachable for an extended period of time.
        if !self
            .registry_replicator
            .has_replicated_all_versions_certified_before_init()
            && self.init_time.elapsed() < TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR
        {
            self.metrics
                .replica_version_upgrade_prevented
                .with_label_values(&[new_replica_version.as_ref(), "replicator_not_caught_up"])
                .inc();

            return Err(OrchestratorError::UpgradeError(format!(
                "Delaying upgrade to {} until registry data is recent enough. Latest registry version: {}",
                new_replica_version, latest_registry_version
            )));
        }

        let recalled_versions = self
            .registry
            .get_recalled_replica_versions(subnet_id, latest_registry_version)?;

        if recalled_versions.contains(new_replica_version) {
            // The new replica version has been recalled. Do not upgrade.
            self.metrics
                .replica_version_upgrade_prevented
                .with_label_values(&[new_replica_version.as_ref(), "version_recalled"])
                .inc();

            return Err(OrchestratorError::UpgradeError(format!(
                "Not upgrading to recalled replica version {} at registry version {}",
                new_replica_version, latest_registry_version
            )));
        }

        Ok(())
    }

    // Stop the replica if the given CUP is unsigned and higher than the given height.
    // Without restart, consensus would reject the unsigned artifact.
    // If stopping the replica fails, restart the current process instead.
    fn stop_replica_if_new_recovery_cup(
        &self,
        cup: &CatchUpPackage,
        old_cup_height: Option<Height>,
    ) {
        let new_height = cup.content.height();
        if !cup.is_signed() && old_cup_height.is_some() && Some(new_height) > old_cup_height {
            info!(
                self.logger,
                "Found higher unsigned CUP, restarting replica for subnet recovery..."
            );
            // Restarting the replica is enough to pass the unsigned CUP forward.
            // If we fail, restart the current process instead.
            if let Err(e) = self.stop_replica() {
                warn!(self.logger, "Failed to stop replica with error {:?}", e);
                reexec_current_process(&self.logger);
            }
        }
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
        info!(self.logger, "Starting new replica process");
        self.metrics.replica_process_start_attempts.inc();
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
            .start(ReplicaProcess {
                version: replica_version.clone(),
                binary: replica_binary,
                args: cmd,
            })
            .map_err(|e| {
                OrchestratorError::IoError("Error when attempting to start new replica".into(), e)
            })
    }
}

#[async_trait]
impl ImageUpgrader<ReplicaVersion, SubnetId> for Upgrade {
    type UpgradeType = OrchestratorControlFlow;

    fn get_prepared_version(&self) -> Option<&ReplicaVersion> {
        self.prepared_upgrade_version.as_ref()
    }

    fn set_prepared_version(&mut self, version: Option<ReplicaVersion>) {
        self.prepared_upgrade_version = version
    }

    fn binary_dir(&self) -> &PathBuf {
        &self.ic_binary_dir
    }

    fn image_path(&self) -> &PathBuf {
        &self.image_path
    }

    fn replica_path(&self) -> &PathBuf {
        &self.replica_path
    }

    fn data_dir(&self) -> Option<&PathBuf> {
        Some(&self.orchestrator_data_directory)
    }

    fn get_release_package_urls_and_hash(
        &self,
        version: &ReplicaVersion,
    ) -> UpgradeResult<(Vec<String>, Option<String>)> {
        let record = self
            .registry
            .get_replica_version_record(version.clone(), self.registry.get_latest_version())
            .map_err(UpgradeError::from)?;

        Ok((
            record.release_package_urls,
            Some(record.release_package_sha256_hex),
        ))
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

    fn get_replica_urls_and_hash(
        &self,
        version: &ReplicaVersion,
    ) -> UpgradeResult<(Vec<String>, Option<String>)> {
        let record = self
            .registry
            .get_replica_version_record(version.clone(), self.registry.get_latest_version())
            .map_err(UpgradeError::from)?;

        Ok((record.replica_urls, record.replica_sha256_hex))
    }

    fn log(&self) -> &ReplicaLogger {
        &self.logger
    }

    fn get_load_balance_number(&self) -> usize {
        // XOR all the u8 in node_id:
        let principal = self.node_id.get().0;
        principal.as_slice().iter().fold(0, |acc, x| acc ^ x) as usize
    }

    async fn check_for_upgrade(&mut self) -> UpgradeResult<OrchestratorControlFlow> {
        self.check().await.map_err(UpgradeError::from)
    }

    async fn shim_swap_restart_replica(
        &mut self,
        subnet_id: Option<&SubnetId>,
    ) -> UpgradeResult<State> {
        self.stop_replica()?;
        while self.replica_process.lock().unwrap().is_running() {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
        // NOTE: Replica looks for canister sandbox based on replica dir. For now, bind into place
        // self.ic_binary_dir = PathBuf::from("/opt/ic/bin/other-replica/");
        let mut bindmnt_cmd = tokio::process::Command::new("sudo");
        bindmnt_cmd
            .arg("/opt/ic/bin/swap-replica.sh")
            .arg(self.replica_path());
        info!(self.logger, "Running command '{:?}'...", bindmnt_cmd);
        if !bindmnt_cmd.status().await.unwrap().success() {
            return Err(UpgradeError::GenericError(
                "Failed to bindmnt the new replica".to_string(),
            ));
        }
        if let Some(&subnet_id) = subnet_id {
            self.ensure_replica_is_running(&self.replica_version, subnet_id)?;
        }

        Ok(State::Continue)
    }

    fn is_slow_upgrade(&self, version: &ReplicaVersion) -> UpgradeResult<bool> {
        let record = self
            .registry
            .get_replica_version_record(version.clone(), self.registry.get_latest_version())
            .map_err(UpgradeError::from)?;

        Ok(!record.fast_upgrade)
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
    let dkg_id = &cup.signature.signer;
    // If the DKG key material was signed by the subnet itself — use it, if not, get
    // the subnet id from the registry.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, then the local CUP is a genesis or recovery CUP of an application
        // subnet or of the NNS subnet recovered on failover nodes. We cannot derive the subnet id
        // from it, so we use the registry version of that CUP and the node id of one of the
        // high-threshold committee members, to find out to which subnet this node belongs to.
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
                    "Couldn't get the subnet id from the registry for node {:?} at registry version {}: {:?}",
                    node_id, dkg_summary.registry_version, other
                )),
            }
        }
    }
}

/// Represents the unassignment decision that the node should take.
#[derive(PartialEq, Eq, Debug)]
enum UnassignmentDecision {
    /// Unassign right now.
    ///
    /// This means that the node is no longer participating in consensus
    /// and can be deemed as unassigned as of now.
    Now,
    /// Unassign later.
    ///
    /// This means that the node is still pariticpating in consensus and
    /// it was only requested for the node to be unassigned in the
    /// registry. Here, the node is still participating in the subnet.
    Later,
    /// Stay in subnet.
    ///
    /// This means that the node is participating in consensus and
    /// there are no requests for this node to leave.
    StayInSubnet,
}

// Checks if the node still belongs to the subnet it was assigned the last time.
// We decide this by checking the subnet membership starting from the oldest
// relevant version of the local CUP and ending with the latest registry
// version.
fn should_node_become_unassigned(
    registry: &dyn RegistryClient,
    latest_registry_version: RegistryVersion,
    node_id: NodeId,
    subnet_id: SubnetId,
    cup: &CatchUpPackage,
) -> UnassignmentDecision {
    let oldest_relevant_version = cup.get_oldest_registry_version_in_use().get();
    let latest_registry_version = latest_registry_version.get();
    // Make sure that if the latest registry version is for some reason violating
    // the assumption that it's higher/equal than any other version used in the
    // system, we still do not remove the subnet state by a mistake.
    if latest_registry_version < oldest_relevant_version {
        return UnassignmentDecision::StayInSubnet;
    }

    // If the node is at the latest registry version in a subnet it shouldn't be unassigned.
    if node_is_in_subnet_at_version(registry, node_id, subnet_id, latest_registry_version) {
        return UnassignmentDecision::StayInSubnet;
    }

    for version in oldest_relevant_version..latest_registry_version {
        if node_is_in_subnet_at_version(registry, node_id, subnet_id, version) {
            return UnassignmentDecision::Later;
        }
    }

    UnassignmentDecision::Now
}

// Checks if the given node belongs to the given subnet at the given registry version, by looking
// at the corresponding subnet record's membership in the registry.
// If the record is missing, or there is any error (like a corrupted local store), then this
// function returns true, to avoid removing the subnet state by mistake, as a conservative
// approach. This function thus assumes that the caller has verified that the subnet ID exists.
fn node_is_in_subnet_at_version(
    registry: &dyn RegistryClient,
    node_id: NodeId,
    subnet_id: SubnetId,
    version: u64,
) -> bool {
    registry
        .get_node_ids_on_subnet(subnet_id, RegistryVersion::from(version))
        .map(|maybe_members| {
            maybe_members
                .map(|members| members.iter().any(|id| id == &node_id))
                .unwrap_or(true)
        })
        .unwrap_or(true)
}

// Call `sync` and `fstrim` on the data partition
async fn sync_and_trim_fs(logger: &ReplicaLogger) -> Result<(), String> {
    let mut fstrim_script = tokio::process::Command::new("/opt/ic/bin/sync_fstrim.sh");
    info!(logger, "Running command '{:?}'...", fstrim_script);
    match fstrim_script.status().await {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "Failed to run command '{fstrim_script:?}', return value: {status}"
                ))
            }
        }
        Err(err) => Err(format!(
            "Failed to run command '{fstrim_script:?}', error: {err}"
        )),
    }
}

// Deletes the subnet state consisting of the consensus pool, execution state,
// the local CUP and the persisted error metric of threshold key changes.
fn remove_node_state(
    replica_config_file: PathBuf,
    cup_path: PathBuf,
    orchestrator_data_directory: PathBuf,
) -> Result<(), String> {
    use ic_config::{Config, ConfigSource};
    use std::fs::{remove_dir_all, remove_file};
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .map_err(|err| format!("Couldn't create a temporary directory: {err:?}"))?;
    let config = Config::load_with_tmpdir(
        ConfigSource::File(replica_config_file),
        tmpdir.path().to_path_buf(),
    );

    let consensus_pool_path = config.artifact_pool.consensus_pool_path;
    remove_dir_all(&consensus_pool_path).map_err(|err| {
        format!("Couldn't delete the consensus pool at {consensus_pool_path:?}: {err:?}")
    })?;

    let state_path = config.state_manager.state_root();

    // We have to explicitly delete child sub-directories and files from the state_root,
    // instead of calling remove_dir_all(state_path) because
    // deleting the "page_deltas" directory results in a SELinux issue: upon deletion of
    // a directory/file, its SELinux class is not persisted if it's recreated. Upon
    // re-creation, the SELinux rights of the creator are applied, not the "old" ones.
    // Deleting the page_deltas directory would thus remove the sandbox capacity to
    // do IO in the page delta files.
    for entry in std::fs::read_dir(state_path.as_path()).map_err(|err| {
        format!(
            "Error iterating through dir {:?}, because {:?}",
            state_path.as_path(),
            err
        )
    })? {
        let en = entry
            .as_ref()
            .expect("Getting reference of dir entry failed.");
        // If this isn't the page deltas directory, it's safe to delete.
        if en
            .file_name()
            .into_string()
            .expect("Converting file name to string failed.")
            != config.state_manager.page_deltas_dirname()
        {
            if en
                .file_type()
                .expect("IO error fetching file type.")
                .is_dir()
            {
                remove_dir_all(en.path())
            } else {
                std::fs::remove_file(en.path())
            }
            .map_err(|err| {
                format!(
                    "Couldn't delete the path {:?}, because {:?}",
                    en.path(),
                    err
                )
            })?;
        } else {
            // Look into the page_deltas/ directory and delete any possible leftover files.
            for entry in std::fs::read_dir(
                state_path
                    .as_path()
                    .join(config.state_manager.page_deltas_dirname()),
            )
            .map_err(|err| {
                format!(
                    "Error iterating through dir {:?}, because {:?}",
                    state_path.as_path(),
                    err
                )
            })? {
                std::fs::remove_file(entry.expect("Error getting file under page_delta/.").path())
                    .map_err(|err| {
                        format!(
                            "Couldn't delete the file {:?}, because {:?}",
                            en.path(),
                            err
                        )
                    })?;
            }
        }
    }

    remove_file(&cup_path)
        .map_err(|err| format!("Couldn't delete the CUP at {cup_path:?}: {err:?}"))?;

    let key_changed_metric = orchestrator_data_directory.join(KEY_CHANGES_FILENAME);
    if key_changed_metric.try_exists().map_err(|err| {
        format!("Failed to check if {key_changed_metric:?} exists, because {err:?}")
    })? {
        remove_file(&key_changed_metric).map_err(|err| {
            format!("Couldn't delete the key changes metric at {key_changed_metric:?}: {err:?}")
        })?;
    }

    Ok(())
}

// Re-execute the current process, exactly as it was originally called.
fn reexec_current_process(logger: &ReplicaLogger) -> OrchestratorError {
    let args: Vec<String> = std::env::args().collect();
    info!(
        logger,
        "Restarting the current process with the same arguments it was originally executed with: {:?}",
        &args[..]
    );
    let error = exec::Command::new(&args[0]).args(&args[1..]).exec();
    OrchestratorError::ExecError(PathBuf::new(), error)
}

/// Return the threshold master public key of the given CUP, if it exists.
fn get_master_public_keys(
    cup: &CatchUpPackage,
    log: &ReplicaLogger,
) -> BTreeMap<MasterPublicKeyId, MasterPublicKey> {
    let payload = cup.content.block.get_value().payload.as_ref();

    let (mut public_keys, _) = get_vetkey_public_keys(&payload.as_summary().dkg, log);

    let Some(idkg) = payload.as_idkg() else {
        return public_keys;
    };

    for (key_id, key_transcript) in &idkg.key_transcripts {
        let Some(transcript) = key_transcript
            .current
            .as_ref()
            .and_then(|transcript_ref| idkg.idkg_transcripts.get(&transcript_ref.transcript_id()))
        else {
            continue;
        };

        match get_master_public_key_from_transcript(transcript) {
            Ok(public_key) => {
                public_keys.insert(key_id.clone().into(), public_key);
            }
            Err(err) => {
                warn!(
                    log,
                    "Failed to get the master public key for key id {}: {:?}", key_id, err,
                );
            }
        };
    }

    public_keys
}

/// Get threshold master public keys of both CUPs and make sure previous keys weren't changed
/// or deleted. Raise an alert if they were.
fn compare_master_public_keys(
    old_cup: &CatchUpPackage,
    new_cup: &CatchUpPackage,
    metrics: &OrchestratorMetrics,
    path: PathBuf,
    log: &ReplicaLogger,
) {
    let old_public_keys = get_master_public_keys(old_cup, log);
    if old_public_keys.is_empty() {
        return;
    }

    let new_public_keys = get_master_public_keys(new_cup, log);
    let mut changes = BTreeMap::new();

    for (key_id, old_public_key) in old_public_keys {
        let key_id_label = key_id.to_string();

        // Get the metric here already, which will initialize it with zero
        // even if keys haven't changed.
        let metric = metrics
            .master_public_key_changed_errors
            .get_metric_with_label_values(&[&key_id_label])
            .expect("Failed to get master public key changed metric");

        if let Some(new_public_key) = new_public_keys.get(&key_id) {
            if old_public_key != *new_public_key {
                error!(
                    log,
                    "Threshold master public key for {} has changed! Old: {:?}, New: {:?}",
                    key_id,
                    old_public_key,
                    new_public_key,
                );
                metric.inc();
                changes.insert(key_id_label.clone(), metric.get());
            }
        } else {
            error!(
                log,
                "Threshold master public key for {} has been deleted!", key_id,
            );
            metric.inc();
            changes.insert(key_id_label, metric.get());
        }
    }

    // We persist the latest value of the changed metrics, such that we can re-apply them
    // after the restart. As any increase in the value is enough to trigger the alert, it
    // is fine to reset the metric of keys that haven't changed.
    if let Err(e) = persist_master_public_key_changed_metric(path, changes) {
        warn!(
            log,
            "Failed to persist master public key changed metric: {}", e
        )
    }
}

/// Persist the given map of master public key changed metrics in `path`.
fn persist_master_public_key_changed_metric(
    path: PathBuf,
    changes: BTreeMap<String, u64>,
) -> OrchestratorResult<()> {
    let file = std::fs::File::create(path).map_err(OrchestratorError::key_monitoring_error)?;
    serde_cbor::to_writer(file, &changes).map_err(OrchestratorError::key_monitoring_error)
}

/// Increment the `master_public_key_changed_errors` metric by the values persisted in the given file.
fn report_master_public_key_changed_metric(
    path: PathBuf,
    metrics: &OrchestratorMetrics,
) -> OrchestratorResult<()> {
    // If the file doesn't exist then there is nothing to report.
    if !path
        .try_exists()
        .map_err(OrchestratorError::key_monitoring_error)?
    {
        return Ok(());
    }
    let file = std::fs::File::open(path).map_err(OrchestratorError::key_monitoring_error)?;
    let key_changes: BTreeMap<String, u64> =
        serde_cbor::from_reader(file).map_err(OrchestratorError::key_monitoring_error)?;

    for (key, count) in key_changes {
        metrics
            .master_public_key_changed_errors
            .with_label_values(&[&key])
            .inc_by(count);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::catch_up_package_provider::LocalCUPReader;
    use crate::catch_up_package_provider::tests::mock_tls_config;

    use super::*;
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants, generate_key_transcript,
    };
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_test_utils_ni_dkg::{
        NiDkgTestEnvironment, RandomNiDkgConfig, dummy_transcript_for_tests_with_params,
        run_ni_dkg_and_create_single_transcript,
    };
    use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
    use ic_interfaces_registry::{
        RegistryClientVersionedResult, RegistryDataProvider, RegistryVersionedRecord,
    };
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve, VetKdKeyId,
    };
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::log::log_entry::v1::LogEntry;
    use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
    use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
    use ic_protobuf::registry::{
        replica_version::v1::ReplicaVersionRecord, subnet::v1::SubnetRecord,
    };
    use ic_protobuf::types::v1 as pb;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{
        ROOT_SUBNET_ID_KEY, make_catch_up_package_contents_key, make_replica_version_key,
        make_subnet_record_key, make_unassigned_nodes_config_record_key,
    };
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_test_utilities_consensus::fake::{Fake, FakeContent};
    use ic_test_utilities_in_memory_logger::InMemoryReplicaLogger;
    use ic_test_utilities_in_memory_logger::assertions::LogEntriesAssert;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_list_record};
    use ic_test_utilities_types::ids::{NODE_1, SUBNET_1, SUBNET_42, node_test_id, subnet_test_id};
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTargetId;
    use ic_types::{
        PrincipalId, Time,
        batch::ValidationContext,
        consensus::{
            Block, BlockPayload, CatchUpContent, HashedBlock, HashedRandomBeacon, Payload,
            RandomBeacon, RandomBeaconContent, Rank, SummaryPayload,
            dkg::DkgSummary,
            idkg::{self, MasterKeyTranscript, TranscriptAttributes},
        },
        crypto::{
            AlgorithmId, CryptoHash, CryptoHashOf,
            canister_threshold_sig::idkg::IDkgTranscript,
            threshold_sig::ni_dkg::{NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTranscript},
        },
        registry::RegistryClientError,
        time::UNIX_EPOCH,
    };
    use mockall::mock;
    use prost::Message;
    use rand::RngCore;
    use rstest::rstest;
    use slog::Level;
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::{collections::BTreeMap, path::Path};
    use tempfile::{TempDir, tempdir};

    impl Upgrade {
        pub fn subnet_assignment(&self) -> SubnetAssignment {
            *self.subnet_assignment.read().unwrap()
        }
    }

    /// TODO(NODE-1754): Remove this mock implementation after registry changes concerning recalled
    /// replica verisons are merged. This temporary implementation is to test the code behaviour
    /// even though the registry does not yet support recalled replica versions.
    /// Once the changes are merged, we can use actual registry mutations instead of this mock.
    struct MockRegistryHelper {
        pub inner: Arc<RegistryHelper>,
        mock: MockRegistryHelperWithRecalledReplicaVersions,
    }
    impl MockRegistryHelper {
        fn new(
            inner: Arc<RegistryHelper>,
            mock: MockRegistryHelperWithRecalledReplicaVersions,
        ) -> Self {
            Self { inner, mock }
        }
    }
    impl RegistryHelperWithRecalledReplicaVersions for MockRegistryHelper {
        fn get_recalled_replica_versions(
            &self,
            subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> OrchestratorResult<Vec<ReplicaVersion>> {
            // Delegate to the mock implementation.
            self.mock
                .get_recalled_replica_versions(subnet_id, registry_version)
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.inner.get_latest_version()
        }

        fn get_registry_client(&self) -> &dyn RegistryClient {
            self.inner.get_registry_client()
        }

        fn get_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId> {
            self.inner.get_subnet_id(version)
        }

        fn get_root_subnet_id(&self, version: RegistryVersion) -> OrchestratorResult<SubnetId> {
            self.inner.get_root_subnet_id(version)
        }

        fn get_replica_version(
            &self,
            subnet_id: SubnetId,
            registry_version: RegistryVersion,
        ) -> OrchestratorResult<ReplicaVersion> {
            self.inner.get_replica_version(subnet_id, registry_version)
        }

        fn get_replica_version_record(
            &self,
            replica_version_id: ReplicaVersion,
            version: RegistryVersion,
        ) -> OrchestratorResult<ReplicaVersionRecord> {
            self.inner
                .get_replica_version_record(replica_version_id, version)
        }

        fn get_api_boundary_node_version(
            &self,
            node_id: NodeId,
            version: RegistryVersion,
        ) -> OrchestratorResult<ReplicaVersion> {
            self.inner.get_api_boundary_node_version(node_id, version)
        }

        fn get_unassigned_replica_version(
            &self,
            version: RegistryVersion,
        ) -> OrchestratorResult<ReplicaVersion> {
            self.inner.get_unassigned_replica_version(version)
        }
    }

    // Helper function to create a CUP with given height and summary payload.
    fn make_cup_with_summary(height: Height, summary_payload: SummaryPayload) -> CatchUpPackage {
        let block = Block::new(
            CryptoHashOf::from(CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(summary_payload),
            ),
            height,
            Rank(46),
            ValidationContext {
                registry_version: RegistryVersion::from(101),
                certified_height: Height::from(42),
                time: UNIX_EPOCH,
            },
        );

        CatchUpPackage::fake(CatchUpContent::new(
            HashedBlock::new(ic_types::crypto::crypto_hash, block),
            HashedRandomBeacon::new(
                ic_types::crypto::crypto_hash,
                RandomBeacon::fake(RandomBeaconContent::new(
                    height,
                    CryptoHashOf::from(CryptoHash(Vec::new())),
                )),
            ),
            CryptoHashOf::from(CryptoHash(Vec::new())),
            None,
        ))
    }

    // Create a CUP for a given subnet id and registry version.
    fn make_local_cup(
        height: Height,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> CatchUpPackage {
        let mut nidkg_summary = DkgSummary::fake();
        nidkg_summary.registry_version = registry_version;
        let mut nidkg_transcripts = nidkg_summary.current_transcripts().clone();
        for transcript in nidkg_transcripts.values_mut() {
            transcript.registry_version = registry_version;
        }
        nidkg_summary = nidkg_summary.with_current_transcripts(nidkg_transcripts);

        let summary_payload = SummaryPayload {
            dkg: nidkg_summary,
            idkg: None,
        };

        let mut cup = make_cup_with_summary(height, summary_payload);

        cup.signature.signer.target_subnet = NiDkgTargetSubnet::Local;
        cup.signature.signer.dealer_subnet = subnet_id;

        cup
    }

    // Create a CUP with a given key transcript.
    fn make_cup_with_key_transcript(
        height: Height,
        key_transcript: Option<(MasterPublicKeyId, KeyTranscript)>,
    ) -> CatchUpPackage {
        let mut nidkg_transcripts = BTreeMap::new();
        let mut idkg_transcripts = BTreeMap::new();
        let mut idkg_key_transcripts = Vec::new();

        if let Some((key_id, transcript)) = key_transcript {
            match (&key_id, transcript) {
                (MasterPublicKeyId::VetKd(_), KeyTranscript::NiDkg(transcript)) => {
                    nidkg_transcripts.insert(transcript.dkg_id.dkg_tag.clone(), transcript);
                }
                (MasterPublicKeyId::Ecdsa(_), KeyTranscript::IDkg(transcript))
                | (MasterPublicKeyId::Schnorr(_), KeyTranscript::IDkg(transcript)) => {
                    idkg_transcripts.insert(transcript.transcript_id, transcript.clone());
                    let unmasked = idkg::UnmaskedTranscriptWithAttributes::new(
                        transcript.to_attributes(),
                        idkg::UnmaskedTranscript::try_from((height, &transcript)).unwrap(),
                    );
                    idkg_key_transcripts.push(MasterKeyTranscript {
                        current: Some(unmasked),
                        next_in_creation: idkg::KeyTranscriptCreation::Begin,
                        master_key_id: key_id.clone().try_into().unwrap(),
                    });
                }
                _ => panic!("Unexpected key ID, transcript combination"),
            }
        }

        let mut idkg = idkg::IDkgPayload::empty(height, subnet_test_id(0), idkg_key_transcripts);
        idkg.idkg_transcripts = idkg_transcripts;

        let summary_payload = SummaryPayload {
            dkg: DkgSummary::fake().with_current_transcripts(nidkg_transcripts),
            idkg: Some(idkg),
        };

        make_cup_with_summary(height, summary_payload)
    }

    fn add_root_subnet_id_to_provider(
        data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        root_subnet_id: SubnetId,
    ) {
        data_provider
            .add(
                ROOT_SUBNET_ID_KEY,
                registry_version,
                Some(ic_types::subnet_id_into_protobuf(root_subnet_id)),
            )
            .unwrap();
    }

    fn add_replica_version_to_provider(
        data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        replica_version: &ReplicaVersion,
    ) {
        data_provider
            .add(
                &make_replica_version_key(replica_version),
                registry_version,
                Some(ReplicaVersionRecord {
                    release_package_sha256_hex: "sha256".to_string(),
                    release_package_urls: vec![],
                    guest_launch_measurements: None,
                }),
            )
            .unwrap();
    }

    fn initial_ni_dkg_transcript_for_tests(
        target_id: NiDkgTargetId,
        committee: &[NodeId],
        registry_version: RegistryVersion,
        tag: NiDkgTag,
    ) -> InitialNiDkgTranscriptRecord {
        let mut transcript = dummy_transcript_for_tests_with_params(
            committee.to_vec(),
            tag.clone(),
            tag.threshold_for_subnet_of_size(committee.len()) as u32,
            registry_version.get(),
        );
        transcript.dkg_id.target_subnet = NiDkgTargetSubnet::Remote(target_id);
        InitialNiDkgTranscriptRecord::from(transcript)
    }

    fn add_registry_cup_to_provider(
        data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        cup_scenario: &CUPScenario,
        membership: impl IntoIterator<Item = NodeId>,
    ) {
        let membership_vec = membership.into_iter().collect::<Vec<_>>();

        let rng = &mut reproducible_rng();
        let mut target_id_bytes = [0u8; 32];
        rng.fill_bytes(&mut target_id_bytes);
        let target_id = NiDkgTargetId::new(target_id_bytes);

        let high_initial_transcript = initial_ni_dkg_transcript_for_tests(
            target_id,
            &membership_vec,
            cup_scenario.registry_version,
            NiDkgTag::HighThreshold,
        );
        let low_initial_transcript = initial_ni_dkg_transcript_for_tests(
            target_id,
            &membership_vec,
            cup_scenario.registry_version,
            NiDkgTag::LowThreshold,
        );

        let cup_contents = CatchUpPackageContents {
            initial_ni_dkg_transcript_high_threshold: Some(high_initial_transcript),
            initial_ni_dkg_transcript_low_threshold: Some(low_initial_transcript),
            height: cup_scenario.height.get(),
            ..Default::default()
        };

        data_provider
            .add(
                &make_catch_up_package_contents_key(cup_scenario.subnet_id),
                registry_version,
                Some(cup_contents),
            )
            .unwrap();
    }

    fn add_subnet_record_to_provider(
        data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        subnet_id: SubnetId,
        membership: impl AsRef<[NodeId]>,
        replica_version: &ReplicaVersion,
    ) {
        let subnet_record = SubnetRecordBuilder::new()
            .with_membership(membership.as_ref())
            .with_replica_version(replica_version.as_ref())
            .build();

        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                registry_version,
                Some(subnet_record),
            )
            .unwrap();
    }

    fn add_unassigned_nodes_config_record(
        data_provider: &ProtoRegistryDataProvider,
        registry_version: RegistryVersion,
        replica_version: &ReplicaVersion,
    ) {
        let unassigned_conifg_record = UnassignedNodesConfigRecord {
            replica_version: replica_version.to_string(),
            ..Default::default()
        };

        data_provider
            .add(
                &make_unassigned_nodes_config_record_key(),
                registry_version,
                Some(unassigned_conifg_record),
            )
            .unwrap();
    }

    // Create a fake binary file with the given bash script content
    fn create_binary(binary_path: &Path, bash_script: &str) {
        let mut file = std::fs::File::create(binary_path).unwrap();
        file.write_all(bash_script.as_bytes()).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .unwrap();

        // The ugly hack below is to work around rstest running the tests in multiple threads but
        // in the same process. Each of them creates their own binary file and later executes it.
        // This means a parallel test might still have the file open for writing while the current
        // one is trying to execute it. This yields ETXTBSY errors on Linux. To avoid this, we use
        // the below hack, taken from https://github.com/rust-lang/rust/issues/114554, see
        // "Implementation of the `flock` algorithm"
        std::thread::sleep(std::time::Duration::from_micros(2));

        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        drop(file);

        let file = std::fs::File::open(binary_path).unwrap();
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
        drop(file);
    }

    async fn create_upgrade_for_test(
        dir: &Path,
        logger: ReplicaLogger,
        test_scenario: UpgradeTestScenario,
        _data_provider: Arc<dyn RegistryDataProvider>,
        // TODO(NODE-1754): Remove this argument and use `_data_provider` and build the registry
        // helper inside this function
        registry: Arc<MockRegistryHelper>,
    ) -> Upgrade {
        let UpgradeTestScenario {
            node_id,
            current_replica_version,
            has_local_cup,
            initial_subnet_assignment,
            ..
        } = test_scenario.clone();

        let metrics = Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new()));

        let ic_binary_dir = dir.join("ic_binary");
        std::fs::create_dir_all(&ic_binary_dir).unwrap();
        create_binary(&ic_binary_dir.join("replica"), "#!/bin/sh\nsleep 60\n");
        create_binary(&ic_binary_dir.join("manageboot.sh"), "#!/bin/sh\nexit 0\n");

        let replica_process = Arc::new(Mutex::new(ProcessManager::new(logger.clone())));
        // Start the replica process if the test scenario indicates so
        if test_scenario.was_replica_process_started_previously() {
            replica_process
                .lock()
                .unwrap()
                .start(ReplicaProcess {
                    version: current_replica_version.clone(),
                    binary: ic_binary_dir.join("replica").display().to_string(),
                    args: vec![],
                })
                .unwrap();
        }

        let cup_dir = dir.join("cups");
        std::fs::create_dir_all(&cup_dir).unwrap();
        if let Some(local_cup) = has_local_cup {
            let cup = make_local_cup(
                local_cup.height,
                local_cup.subnet_id,
                local_cup.registry_version,
            );
            let cup_proto = pb::CatchUpPackage::from(&cup);
            let cup_file = cup_dir.join("cup.types.v1.CatchUpPackage.pb");
            std::fs::write(&cup_file, cup_proto.encode_to_vec()).unwrap();
        }
        let cup_provider = CatchUpPackageProvider::new(
            Arc::clone(&registry.inner),
            LocalCUPReader::new(cup_dir, logger.clone()),
            Arc::new(CryptoReturningOk::default()),
            Arc::new(mock_tls_config()),
            logger.clone(),
            node_id,
        );

        let subnet_assignment = Arc::new(RwLock::new(initial_subnet_assignment));

        let replica_config_file = dir.join("ic.json5");

        let mut registry_replicator = MockRegistryReplicatorForUpgrade::new();
        registry_replicator
            .expect_has_replicated_all_versions_certified_before_init()
            .times(
                if test_scenario.should_call_has_replicated_all_versions_certified_before_init() {
                    1
                } else {
                    0
                },
            )
            .return_const(
                test_scenario
                    .upgrade_to
                    .as_ref()
                    .map(|upgrade| upgrade.has_replicated_versions_before_init)
                    .unwrap_or(false),
            );

        let release_content_dir = dir.join("images");
        std::fs::create_dir_all(&release_content_dir).unwrap();

        let orchestrator_data_dir = dir.join("orchestrator");
        std::fs::create_dir_all(&orchestrator_data_dir).unwrap();

        let mut upgrade_loop = Upgrade::new(
            registry,
            metrics,
            replica_process,
            cup_provider,
            subnet_assignment,
            current_replica_version.clone(),
            replica_config_file,
            node_id,
            ic_binary_dir,
            Arc::new(registry_replicator),
            release_content_dir,
            logger,
            orchestrator_data_dir,
            None,
        )
        .await;

        // If the node is supposed to upgrade, manually create a fake image file
        // and set the prepared version to avoid actually downloading the image.
        if let Some(upgrade) = &test_scenario.upgrade_to {
            std::fs::write(upgrade_loop.image_path(), b"fake image data").unwrap();
            upgrade_loop.set_prepared_version(Some(upgrade.replica_version.clone()));
        }

        upgrade_loop
    }

    // Parameters for a local or registry CUP in the test scenario
    #[derive(Clone, Debug)]
    struct CUPScenario {
        height: Height,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    }

    impl CUPScenario {
        // Returns the CUP with the higher height between `self` and `other`.
        fn max_height<'a>(&'a self, other: Option<&'a CUPScenario>) -> &'a CUPScenario {
            match other {
                Some(other) if other.height > self.height => other,
                _ => self,
            }
        }
    }

    // Parameters for a replica upgrade in the test scenario
    #[derive(Clone, Debug)]
    struct ReplicaUpgradeScenario {
        // The target replica version of the upgrade
        replica_version: ReplicaVersion,
        // The registry version where the upgrade is effective
        registry_version: RegistryVersion,
        // Whether the target replica version is recalled at the latest registry version
        is_recalled: bool,
        // Whether the replicator has replicated all registry versions that were certified before
        // the replicator was started
        has_replicated_versions_before_init: bool,
    }

    impl ReplicaUpgradeScenario {
        // Returns the expected control flow of the upgrade loop when when the upgrade is about to
        // be executed. We should indeed first check if the replica version was recalled.
        fn should_be_executed(&self) -> OrchestratorResult<OrchestratorControlFlow> {
            if !self.has_replicated_versions_before_init {
                // The replicator has not yet replicated all registry versions that
                // were certified before the replicator was started.
                // Thus, we cannot be sure whether the replica version was recalled
                // or not. We should thus wait until the replicator has caught up.
                Err(OrchestratorError::UpgradeError(format!(
                    "Delaying upgrade to {} until registry data is recent enough.",
                    self.replica_version,
                )))
            } else if self.is_recalled {
                // The replica version was recalled, so we should not upgrade
                Err(OrchestratorError::UpgradeError(format!(
                    "Not upgrading to recalled replica version {}",
                    self.replica_version,
                )))
            } else {
                // The replica version was not recalled, so we are expected to stop
                // and reboot
                Ok(OrchestratorControlFlow::Stop)
            }
        }
    }

    #[derive(Clone, Debug)]
    struct UpgradeTestScenario {
        // Node id of the node under test
        node_id: NodeId,
        // Current replica version of the running orchestrator
        current_replica_version: ReplicaVersion,
        // Whether the node is assigned to a subnet (<=> presence of local CUP)
        // `Some` includes some parameters for the local CUP.
        // `None` means no local CUP, i.e. unassigned.
        has_local_cup: Option<CUPScenario>,
        // Whether there is a registry CUP in the registry
        // For test scenarios with local CUPs, this corresopnds to a recovery CUP.
        // For test scenarios without local CUPs, this corresponds to a genesis CUP.
        // `Some` includes some parameters for the registry CUP.
        // It also contains the registry version where the CUP was added to the registry (which
        // could be different from the CUP's internal registry version).
        // `None` means no registry CUP.
        has_registry_cup: Option<(CUPScenario, RegistryVersion)>,
        // Subnet assignment at the start of the upgrade loop, i.e. the assignment from the previous
        // loop. In particular, `Unknown` means that the node has just rebooted.
        initial_subnet_assignment: SubnetAssignment,
        // Whether the node is leaving the subnet
        // `Some` includes the registry version where the node is removed from the subnet.
        // `None` means the node is staying in the subnet
        is_leaving: Option<RegistryVersion>,
        // Whether there is an upcoming upgrade (<=> different replica version at the CUP's registry
        // version or <=> different replica version for unassigned nodes at the latest registry
        // version)
        // `Some` includes some parameters for the upgrade.
        // `None` means no upgrade.
        upgrade_to: Option<ReplicaUpgradeScenario>,
    }

    impl UpgradeTestScenario {
        // Returns the CUP with the highest height among local and registry CUPs, if any.
        fn highest_cup(&self) -> Option<&CUPScenario> {
            match (&self.has_local_cup, &self.has_registry_cup) {
                (Some(local_cup), Some((registry_cup, _))) => {
                    Some(local_cup.max_height(Some(registry_cup)))
                }
                (Some(local_cup), None) => Some(local_cup),
                (None, Some((registry_cup, _))) => Some(registry_cup),
                (None, None) => None,
            }
        }

        // Starting with an `Assigned` subnet assignment *and* successfully persisting a local CUP
        // should mean that the replica process was started by a previous iteration of the upgrade
        // loop.
        fn was_replica_process_started_previously(&self) -> bool {
            matches!(
                self.initial_subnet_assignment,
                SubnetAssignment::Assigned(_)
            )
            && self.has_local_cup.is_some()
            // TODO(CON-1630): After mocking the process management, we can remove the condition below.
            // For now, we should not start the replica if a recovery CUP exists (with higher height)
            // since that would try to stop the replica process, which fails in the test
            // environment.
            && self.has_registry_cup.as_ref().map(|(cup, _)| cup.height)
                <= self.has_local_cup.as_ref().map(|cup| cup.height)
        }

        // Returns whether the upgrade loop should call
        // `has_replicated_all_versions_certified_before_init` based on the test scenario
        fn should_call_has_replicated_all_versions_certified_before_init(&self) -> bool {
            let Some(highest_cup) = self.highest_cup() else {
                return false;
            };

            let Some(upgrade) = &self.upgrade_to else {
                return false;
            };

            if highest_cup.registry_version < upgrade.registry_version {
                return false;
            }

            if highest_cup.subnet_id == SUBNET_42 {
                // We are on the NNS subnet, which should never trigger this check
                return false;
            }

            if let Some(leaving_registry_version) = &self.is_leaving {
                return &highest_cup.registry_version < leaving_registry_version;
            }

            true
        }

        // Sets up the registry according to the test scenario
        fn setup_registry(
            &self,
            logger: ReplicaLogger,
        ) -> (Arc<MockRegistryHelper>, Arc<ProtoRegistryDataProvider>) {
            let data_provider = Arc::new(ProtoRegistryDataProvider::new());

            let mut mock_helper = MockRegistryHelperWithRecalledReplicaVersions::new();

            // NNS subnet
            let nns_subnet_id = SUBNET_42;
            add_root_subnet_id_to_provider(&data_provider, RegistryVersion::from(1), nns_subnet_id);

            // Another node in the subnet (to avoid having an empty subnet in case the current node
            // leaves)
            let other_node_id = node_test_id(87654321);

            // Initialize the subnet list
            let mut subnet_list = BTreeSet::new();
            subnet_list.insert(nns_subnet_id);
            if let Some(local_cup) = &self.has_local_cup {
                subnet_list.insert(local_cup.subnet_id);
            }
            if let Some((registry_cup, _)) = &self.has_registry_cup {
                subnet_list.insert(registry_cup.subnet_id);
            }
            add_subnet_list_record(&data_provider, 1, subnet_list.into_iter().collect());

            // The current replica version must have been elected in the past
            add_replica_version_to_provider(
                &data_provider,
                RegistryVersion::from(1),
                &self.current_replica_version,
            );

            if let Some((registry_cup, registry_cup_registry_version)) = &self.has_registry_cup {
                // There is a registry CUP at the specified registry version
                add_registry_cup_to_provider(
                    &data_provider,
                    *registry_cup_registry_version,
                    registry_cup,
                    vec![self.node_id, other_node_id],
                );
            }

            if let Some(upgrade) = &self.upgrade_to {
                // Elect the new replica version
                add_replica_version_to_provider(
                    &data_provider,
                    // Usually, replica versions are elected before subnets are upgraded to them.
                    RegistryVersion::from(upgrade.registry_version.get() - 1),
                    &upgrade.replica_version,
                );

                // TODO(NODE-1754): Replace this mock expectation with actual registry mutations
                // once the registry changes concerning recalled replica versions are merged.
                let recalled_replica_versions = if upgrade.is_recalled {
                    vec![upgrade.replica_version.clone()]
                } else {
                    vec![]
                };
                mock_helper
                    .expect_get_recalled_replica_versions()
                    .returning(move |_, _| Ok(recalled_replica_versions.clone()));
            }

            if let Some(local_cup) = &self.has_local_cup {
                // The node is part of the subnet at the beginning, including the current replica
                // version
                // Also add another node, in case the current one will leave
                add_subnet_record_to_provider(
                    &data_provider,
                    RegistryVersion::from(1),
                    local_cup.subnet_id,
                    vec![self.node_id, other_node_id],
                    &self.current_replica_version,
                );

                match (&self.is_leaving, &self.upgrade_to) {
                    (None, None) => {
                        // No change, keep the current replica version and membership
                    }
                    (None, Some(upgrade)) => {
                        // Upgrade the subnet at the specified registry version
                        add_subnet_record_to_provider(
                            &data_provider,
                            upgrade.registry_version,
                            local_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                    (Some(leaving_registry_version), None) => {
                        // The node is leaving the subnet, so remove it from the membership at the
                        // specified registry version
                        add_subnet_record_to_provider(
                            &data_provider,
                            *leaving_registry_version,
                            local_cup.subnet_id,
                            vec![other_node_id],
                            &self.current_replica_version,
                        );
                    }
                    (Some(leaving_registry_version), Some(upgrade))
                        if leaving_registry_version < &upgrade.registry_version =>
                    {
                        // Remove the node from the membership
                        add_subnet_record_to_provider(
                            &data_provider,
                            *leaving_registry_version,
                            local_cup.subnet_id,
                            vec![other_node_id],
                            &self.current_replica_version,
                        );
                        // And later upgrade the subnet
                        add_subnet_record_to_provider(
                            &data_provider,
                            upgrade.registry_version,
                            local_cup.subnet_id,
                            vec![other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                    (Some(leaving_registry_version), Some(upgrade))
                        if leaving_registry_version == &upgrade.registry_version =>
                    {
                        // The node is leaving the subnet at the same registry version as the
                        // upgrade.
                        add_subnet_record_to_provider(
                            &data_provider,
                            *leaving_registry_version,
                            local_cup.subnet_id,
                            vec![other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                    (Some(leaving_registry_version), Some(upgrade)) => {
                        // Upgrade the subnet
                        add_subnet_record_to_provider(
                            &data_provider,
                            upgrade.registry_version,
                            local_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &upgrade.replica_version,
                        );
                        // And later remove the node from the membership
                        add_subnet_record_to_provider(
                            &data_provider,
                            *leaving_registry_version,
                            local_cup.subnet_id,
                            vec![other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                }
            } else {
                // Set the current replica version for unassigned nodes
                add_unassigned_nodes_config_record(
                    &data_provider,
                    RegistryVersion::from(1),
                    &self.current_replica_version,
                );

                match (&self.has_registry_cup, &self.upgrade_to) {
                    (None, None) => {
                        // No change, keep the current replica version and membership
                    }
                    (None, Some(upgrade)) => {
                        // Upgrade unassigned nodes at the specified registry version
                        add_unassigned_nodes_config_record(
                            &data_provider,
                            upgrade.registry_version,
                            &upgrade.replica_version,
                        );
                    }
                    (Some((registry_cup, registry_cup_registry_version)), None) => {
                        // There is a registry CUP targeting this unassigned node, which implies
                        // that the node is joining the subnet. Thus, adapt the subnet record.
                        add_subnet_record_to_provider(
                            &data_provider,
                            *registry_cup_registry_version,
                            registry_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &self.current_replica_version,
                        );
                    }
                    (Some((registry_cup, registry_cup_registry_version)), Some(upgrade))
                        if registry_cup_registry_version < &upgrade.registry_version =>
                    {
                        // Add the node to the subnet
                        add_subnet_record_to_provider(
                            &data_provider,
                            *registry_cup_registry_version,
                            registry_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &self.current_replica_version,
                        );
                        // And later upgrade the subnet
                        add_subnet_record_to_provider(
                            &data_provider,
                            upgrade.registry_version,
                            registry_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                    (Some((registry_cup, registry_cup_registry_version)), Some(upgrade))
                        if registry_cup_registry_version == &upgrade.registry_version =>
                    {
                        add_subnet_record_to_provider(
                            &data_provider,
                            *registry_cup_registry_version,
                            registry_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                    (Some((registry_cup, registry_cup_registry_version)), Some(upgrade)) => {
                        // Upgrade unassigned nodes at the specified registry version
                        add_unassigned_nodes_config_record(
                            &data_provider,
                            upgrade.registry_version,
                            &upgrade.replica_version,
                        );
                        // And later add the node to the subnet
                        add_subnet_record_to_provider(
                            &data_provider,
                            *registry_cup_registry_version,
                            registry_cup.subnet_id,
                            vec![self.node_id, other_node_id],
                            &upgrade.replica_version,
                        );
                    }
                }
            }

            // Finally, the local or registry CUP might have a registry version higher than the
            // latest registry version overall. We thus add a dummy registry record at the maximum
            // registry version that can be requested.
            let max_registry_version = [
                self.has_local_cup.as_ref().map(|cup| cup.registry_version),
                self.has_registry_cup
                    .as_ref()
                    .map(|(cup, _)| cup.registry_version),
                self.has_registry_cup
                    .as_ref()
                    .map(|(_, registry_version)| *registry_version),
                self.is_leaving,
                self.upgrade_to
                    .as_ref()
                    .map(|upgrade| upgrade.registry_version),
            ]
            .iter()
            .filter_map(|x| *x)
            .max()
            .unwrap_or(RegistryVersion::from(1));

            add_replica_version_to_provider(
                &data_provider,
                max_registry_version,
                &ReplicaVersion::try_from("dummy_replica_version").unwrap(),
            );

            let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
            let real_helper =
                RegistryHelper::new(self.node_id, registry_client.clone(), logger.clone());
            registry_client.update_to_latest_version();
            let registry_helper =
                Arc::new(MockRegistryHelper::new(Arc::new(real_helper), mock_helper));
            (registry_helper, data_provider)
        }

        // Returns the expected subnet assignment after the upgrade loop.
        // Additionally asserts whether the orchestrator has detected the subnet assignment while
        // unassigned
        fn expected_subnet_assignment(&self, logs: Vec<LogEntry>) -> SubnetAssignment {
            let needle_has_detected_subnet_assignment = "Assignment to subnet";
            let logs_assert = LogEntriesAssert::assert_that(logs);
            let assert_has_detected_subnet_assignment = || {
                logs_assert.has_only_one_message_containing(
                    &Level::Info,
                    needle_has_detected_subnet_assignment,
                );
            };
            let assert_has_not_detected_subnet_assignment = || {
                logs_assert.has_exactly_n_messages_containing(
                    0,
                    &Level::Info,
                    needle_has_detected_subnet_assignment,
                );
            };

            match &self.has_local_cup {
                Some(local_cup) => {
                    let highest_height_cup =
                        local_cup.max_height(self.has_registry_cup.as_ref().map(|(cup, _)| cup));

                    // The subnet assignment log only occurs when the node does not have a local CUP
                    // at the beginning of the upgrade loop.
                    assert_has_not_detected_subnet_assignment();

                    match &self.is_leaving {
                        None => SubnetAssignment::Assigned(local_cup.subnet_id),
                        Some(leaving_registry_version)
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            // The node is leaving the subnet, but the CUP's registry version has
                            // not reached the leaving registry version yet, so we are still
                            // assigned
                            SubnetAssignment::Assigned(local_cup.subnet_id)
                        }
                        Some(_leaving_registry_version) => {
                            // The node is leaving the subnet and the CUP's registry version has
                            // reached the leaving registry version, so we are expected to turn
                            // unassigned
                            SubnetAssignment::Unassigned
                        }
                    }
                }
                None => match &self.has_registry_cup {
                    None => {
                        assert_has_not_detected_subnet_assignment();
                        SubnetAssignment::Unassigned
                    }
                    Some((registry_cup, _)) => {
                        // There is a registry CUP, so the node should join the subnet
                        assert_has_detected_subnet_assignment();
                        SubnetAssignment::Assigned(registry_cup.subnet_id)
                    }
                },
            }
        }

        // Returns the expected control flow after the upgrade loop.
        // Additionally asserts whether the orchestrator has prepared for an upgrade
        // Additionally asserts whether the prepared version and image have been cleared
        fn expected_flow(
            &self,
            logs: Vec<LogEntry>,
            upgrade_loop: &Upgrade,
        ) -> OrchestratorResult<OrchestratorControlFlow> {
            let needle_has_prepared_upgrade =
                "Replica version upgrade detected at registry version";
            let logs_assert = LogEntriesAssert::assert_that(logs);
            let assert_has_prepared_upgrade = || {
                logs_assert
                    .has_only_one_message_containing(&Level::Info, needle_has_prepared_upgrade);
            };
            let assert_has_not_prepared_upgrade = || {
                logs_assert.has_exactly_n_messages_containing(
                    0,
                    &Level::Info,
                    needle_has_prepared_upgrade,
                );
            };
            let assert_has_cleared_version_and_image = || {
                assert_eq!(upgrade_loop.get_prepared_version(), None,);
                assert!(!upgrade_loop.image_path().exists());
            };
            let assert_has_not_cleared_version_and_image = |upgrade: &ReplicaUpgradeScenario| {
                assert_eq!(
                    upgrade_loop.get_prepared_version(),
                    Some(&upgrade.replica_version)
                );
                assert!(upgrade_loop.image_path().exists());
            };

            match &self.has_local_cup {
                Some(local_cup) => {
                    let highest_height_cup =
                        local_cup.max_height(self.has_registry_cup.as_ref().map(|(cup, _)| cup));

                    match (&self.is_leaving, &self.upgrade_to) {
                        (None, None) => {
                            assert_has_not_prepared_upgrade();
                            assert_has_cleared_version_and_image();
                            Ok(OrchestratorControlFlow::Assigned(local_cup.subnet_id))
                        }
                        (None, Some(upgrade))
                            if highest_height_cup.registry_version < upgrade.registry_version =>
                        {
                            // An upgrade is scheduled but the CUP's registry version has not
                            // reached the upgrade registry version yet, so we are expected not to
                            // stop and reboot
                            // Though, we should start to download it in advance
                            assert_has_prepared_upgrade();
                            assert_has_not_cleared_version_and_image(upgrade);
                            Ok(OrchestratorControlFlow::Assigned(local_cup.subnet_id))
                        }
                        (None, Some(upgrade)) => {
                            // An upgrade is scheduled and the CUP's registry version has reached
                            // the upgrade registry version.
                            let expected_flow = upgrade.should_be_executed();

                            assert_has_not_prepared_upgrade();
                            if expected_flow.is_ok() {
                                // The upgrade is going to be executed, so the prepared version and
                                // image should be cleared
                                assert_has_cleared_version_and_image();
                            } else {
                                assert_has_not_cleared_version_and_image(upgrade);
                            }

                            expected_flow
                        }
                        (Some(leaving_registry_version), None)
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            // The node is leaving the subnet, but the CUP's registry version has
                            // not reached the leaving registry version yet, so we are expected to
                            // be `Leaving`
                            assert_has_not_prepared_upgrade();
                            assert_has_cleared_version_and_image();
                            Ok(OrchestratorControlFlow::Leaving(local_cup.subnet_id))
                        }
                        (Some(_leaving_registry_version), None) => {
                            // The node is leaving the subnet and the CUP's registry version has
                            // reached the leaving registry version, so we are expected to be
                            // `Unassigned`
                            assert_has_not_prepared_upgrade();
                            assert_has_cleared_version_and_image();
                            Ok(OrchestratorControlFlow::Unassigned)
                        }
                        (Some(leaving_registry_version), Some(upgrade))
                            if &highest_height_cup.registry_version < leaving_registry_version
                                && highest_height_cup.registry_version
                                    < upgrade.registry_version =>
                        {
                            // Both leaving and upgrade are scheduled, but the CUP's registry version
                            // has not reached either of them yet, so we are expected to be `Leaving`
                            // Though, we should start to download the upgrade in advance
                            assert_has_prepared_upgrade();
                            assert_has_not_cleared_version_and_image(upgrade);
                            Ok(OrchestratorControlFlow::Leaving(local_cup.subnet_id))
                        }
                        (Some(leaving_registry_version), Some(upgrade))
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            // Both leaving and upgrade are scheduled, but the CUP's registry version
                            // has only reached the upgrade registry version, not the leaving registry
                            // version.
                            // We should now first check if the replica version was recalled.
                            let expected_flow = upgrade.should_be_executed();

                            assert_has_not_prepared_upgrade();
                            if expected_flow.is_ok() {
                                // The upgrade is going to be executed, so the prepared version and
                                // image should be cleared
                                assert_has_cleared_version_and_image();
                            } else {
                                assert_has_not_cleared_version_and_image(upgrade);
                            }

                            expected_flow
                        }
                        (Some(_leaving_registry_version), Some(upgrade)) => {
                            // Both leaving and upgrade are scheduled, and the CUP's registry
                            // version has reached the leaving registry version. Regardless of
                            // whether the upgrade registry version has been reached, leaving the
                            // subnet takes precedence, and we are expected to be `Unassigned`
                            assert_has_not_prepared_upgrade();
                            // In that case, the prepared image will be kept
                            assert_has_not_cleared_version_and_image(upgrade);
                            Ok(OrchestratorControlFlow::Unassigned)
                        }
                    }
                }
                None => match (&self.has_registry_cup, &self.upgrade_to) {
                    (None, None) => {
                        assert_has_not_prepared_upgrade();
                        assert_has_cleared_version_and_image();
                        Ok(OrchestratorControlFlow::Unassigned)
                    }
                    (None, Some(_upgrade)) => {
                        // An upgrade is scheduled. Unassigned nodes always instantly upgrade so we
                        // are expected to stop and reboot
                        assert_has_not_prepared_upgrade();
                        assert_has_cleared_version_and_image();
                        Ok(OrchestratorControlFlow::Stop)
                    }
                    (Some((registry_cup, _)), None) => {
                        // The node is joining a subnet, and there is no upgrade scheduled, so we
                        // are expected to turn `Assigned`
                        assert_has_not_prepared_upgrade();
                        assert_has_cleared_version_and_image();
                        Ok(OrchestratorControlFlow::Assigned(registry_cup.subnet_id))
                    }
                    (Some((registry_cup, _)), Some(upgrade))
                        if registry_cup.registry_version < upgrade.registry_version =>
                    {
                        // An upgrade is scheduled but the CUP's registry version has not
                        // reached the upgrade registry version yet, so we are expected to turn
                        // `Assigned` and not stop and reboot
                        // Though, we should start to download the upgrade in advance
                        assert_has_prepared_upgrade();
                        assert_has_not_cleared_version_and_image(upgrade);
                        Ok(OrchestratorControlFlow::Assigned(registry_cup.subnet_id))
                    }
                    (Some((_registry_cup, _)), Some(upgrade)) => {
                        // This scenario can be interpreted as the unassigned node having a
                        // different replica version than the subnet's
                        let expected_flow = upgrade.should_be_executed();

                        assert_has_not_prepared_upgrade();
                        if expected_flow.is_ok() {
                            // The upgrade is going to be executed, so the prepared version and
                            // image should be cleared
                            assert_has_cleared_version_and_image();
                        } else {
                            assert_has_not_cleared_version_and_image(upgrade);
                        }

                        expected_flow
                    }
                },
            }
        }

        // Returns the expected local CUP height *after* the upgrade loop.
        // Additionally asserts whether the orchestrator actively persisted the CUP.
        fn expected_local_cup_height(&self, logs: Vec<LogEntry>) -> Option<Height> {
            let needle_has_persisted_cup = "Persisting CUP";
            let logs_assert = LogEntriesAssert::assert_that(logs);
            let assert_has_persisted_cup = || {
                logs_assert.has_only_one_message_containing(&Level::Info, needle_has_persisted_cup);
            };
            let assert_has_not_persisted_cup = || {
                logs_assert.has_exactly_n_messages_containing(
                    0,
                    &Level::Info,
                    needle_has_persisted_cup,
                );
            };

            match &self.has_local_cup {
                Some(local_cup) => {
                    let highest_height_cup =
                        local_cup.max_height(self.has_registry_cup.as_ref().map(|(cup, _)| cup));

                    // The node was already assigned or has just restarted, the local CUP should
                    // always be persisted
                    assert_has_persisted_cup();

                    // The local CUP remains if not leaving, or leaving later
                    match &self.is_leaving {
                        None => Some(highest_height_cup.height),
                        Some(leaving_registry_version)
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            Some(highest_height_cup.height)
                        }
                        Some(_) => None,
                    }
                }
                None => {
                    match &self.has_registry_cup {
                        None => {
                            // Being unassigned, the local CUP remains absent
                            assert_has_not_persisted_cup();
                            None
                        }
                        Some((registry_cup, _)) => {
                            // There is a registry CUP, so the node is joining the subnet,
                            // and the local CUP should be persisted
                            assert_has_persisted_cup();
                            Some(registry_cup.height)
                        }
                    }
                }
            }
        }

        // Asserts whether the orchestrator has removed the local CUP and state if necessary.
        fn assert_removed_state_if_necessary(&self, logs: Vec<LogEntry>) {
            let needle_has_removed_state = "Subnet state removed";
            let logs_assert = LogEntriesAssert::assert_that(logs);
            let assert_has_removed_state = || {
                logs_assert.has_only_one_message_containing(&Level::Info, needle_has_removed_state);
            };
            let assert_has_not_removed_state = || {
                logs_assert.has_exactly_n_messages_containing(
                    0,
                    &Level::Info,
                    needle_has_removed_state,
                );
            };

            let Some(highest_cup) = self.highest_cup() else {
                // There is no CUP at all, so we are unassigned and the state is not actively
                // removed
                assert_has_not_removed_state();
                return;
            };

            // The state should be removed only when leaving
            let Some(leaving_registry_version) = &self.is_leaving else {
                assert_has_not_removed_state();
                return;
            };

            if &highest_cup.registry_version < leaving_registry_version {
                // The node is leaving later, so the state should not be removed now
                assert_has_not_removed_state();
                return;
            }

            // The node is leaving now, so the state should be removed
            assert_has_removed_state();
        }

        // Returns whether the replica process should be running after the upgrade loop.
        // Additionally asserts whether the orchestrator has started a *new* replica process
        fn should_replica_process_be_running(&self, logs: Vec<LogEntry>) -> bool {
            let needle_has_started_new_process = "Starting new replica process";
            let logs_assert = LogEntriesAssert::assert_that(logs);
            let assert_has_started_new_process = || {
                logs_assert
                    .has_only_one_message_containing(&Level::Info, needle_has_started_new_process);
            };
            let assert_has_not_started_new_process = || {
                logs_assert.has_exactly_n_messages_containing(
                    0,
                    &Level::Info,
                    needle_has_started_new_process,
                );
            };
            match &self.has_local_cup {
                Some(local_cup) => {
                    // If the initial subnet assignment was already `Assigned`, then the replica
                    // process should have been started by the previous iteration of the upgrade
                    // loop and should not be started again.
                    // Though, if there is a recovery CUP of a higher height than the local CUP,
                    // then the replica process should be started again to pick up the new CUP.
                    let assert_has_started_new_process_if_necessary =
                        || match (&self.has_registry_cup, &self.initial_subnet_assignment) {
                            (Some((registry_cup, _)), _)
                                if registry_cup.height >= local_cup.height =>
                            {
                                assert_has_started_new_process();
                            }
                            (_, SubnetAssignment::Assigned(_)) => {
                                assert_has_not_started_new_process();
                            }
                            (_, SubnetAssignment::Unassigned | SubnetAssignment::Unknown) => {
                                assert_has_started_new_process();
                            }
                        };

                    let highest_height_cup =
                        local_cup.max_height(self.has_registry_cup.as_ref().map(|(cup, _)| cup));

                    match (&self.is_leaving, &self.upgrade_to) {
                        (None, None) => {
                            // Not leaving, so the replica process should be started only if
                            // necessary
                            assert_has_started_new_process_if_necessary();
                            true
                        }
                        (None, Some(upgrade))
                            if highest_height_cup.registry_version < upgrade.registry_version =>
                        {
                            // An upgrade is scheduled but the CUP's registry version has not
                            // reached the upgrade registry version yet, so the replica process
                            // should be started only if not already running
                            assert_has_started_new_process_if_necessary();
                            true
                        }
                        (None, Some(_upgrade)) => {
                            // An upgrade is scheduled and the CUP's registry version has reached
                            // the upgrade registry version.
                            // Regardless of whether the upgrade version was recalled or not, note
                            // that the implementation does not stop the replica process, it either
                            // returns an error (if recalled) or just issues a reboot. Thus, in this
                            // unit test, we will assert that the replica process is in the same
                            // state as before.
                            assert_has_not_started_new_process();
                            self.was_replica_process_started_previously()
                        }
                        (Some(leaving_registry_version), None)
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            // The node is leaving the subnet, but the CUP's registry version has
                            // not reached the leaving registry version yet, so the replica process
                            // should be started only if not already running
                            assert_has_started_new_process_if_necessary();
                            true
                        }
                        (Some(_leaving_registry_version), None) => {
                            // The node is leaving the subnet and the CUP's registry version has
                            // reached the leaving registry version, so we are expected to stop the
                            // replica process
                            assert_has_not_started_new_process();
                            false
                        }
                        (Some(leaving_registry_version), Some(upgrade))
                            if &highest_height_cup.registry_version < leaving_registry_version
                                && highest_height_cup.registry_version
                                    < upgrade.registry_version =>
                        {
                            // Both leaving and upgrade are scheduled, but the CUP's registry version
                            // has not reached either of them yet, so the replica process should be
                            // started only if not already running
                            assert_has_started_new_process_if_necessary();
                            true
                        }
                        (Some(leaving_registry_version), Some(_upgrade))
                            if &highest_height_cup.registry_version < leaving_registry_version =>
                        {
                            // An upgrade is scheduled and the CUP's registry version has reached
                            // the upgrade registry version.
                            // Regardless of whether the upgrade version was recalled or not, note
                            // that the implementation does not stop the replica process, it either
                            // returns an error (if recalled) or just issues a reboot. Thus, in this
                            // unit test, we will assert that the replica process is in the same
                            // state as before.
                            assert_has_not_started_new_process();
                            self.was_replica_process_started_previously()
                        }
                        (Some(_leaving_registry_version), Some(_upgrade)) => {
                            // Both leaving and upgrade are scheduled, and the CUP's registry
                            // version has reached the leaving registry version. Regardless of
                            // whether the upgrade registry version has been reached, leaving the
                            // subnet takes precedence, and we are expected to stop the replica
                            // process
                            assert_has_not_started_new_process();
                            false
                        }
                    }
                }
                None => {
                    match &self.has_registry_cup {
                        None => {
                            // Being unassigned, the replica process should not be running
                            assert_has_not_started_new_process();
                            false
                        }
                        Some((registry_cup, _)) => {
                            // There is a registry CUP, so the node is joining the subnet

                            // But there could be an upgrade scheduled in the meantime
                            match &self.upgrade_to {
                                None => {
                                    // No upgrade is scheduled, so the replica process should be
                                    // *started*
                                    assert_has_started_new_process();
                                    true
                                }
                                Some(upgrade)
                                    if registry_cup.registry_version < upgrade.registry_version =>
                                {
                                    // An upgrade is scheduled but the CUP's registry version has
                                    // not reached the upgrade registry version yet, so the replica
                                    // process should be *started*
                                    assert_has_started_new_process();
                                    true
                                }
                                Some(_upgrade) => {
                                    // This scenario can be interpreted as the unassigned node
                                    // having a different replica version than the subnet's
                                    // We should upgrade before actually starting the replica
                                    // process (or return early if the version was recalled).
                                    assert_has_not_started_new_process();
                                    false
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn test_upgrade(test_scenario: UpgradeTestScenario) {
        let logger = InMemoryReplicaLogger::new();
        let replica_logger = ReplicaLogger::from(&logger);
        let (registry_helper, data_provider) = test_scenario.setup_registry(replica_logger.clone());

        let tmp_dir = tempdir().unwrap();
        let tmp_path = tmp_dir.path();
        let mut upgrade_loop = create_upgrade_for_test(
            tmp_path,
            replica_logger,
            test_scenario.clone(),
            data_provider,
            registry_helper,
        )
        .await;

        let flow_result = upgrade_loop.check().await;
        let logs = logger.drain_logs();

        // Check orchestrator control flow
        match (
            &flow_result,
            &test_scenario.expected_flow(logs.clone(), &upgrade_loop),
        ) {
            (Ok(actual_flow), Ok(expected_flow)) => {
                assert_eq!(actual_flow, expected_flow);
            }
            (
                Err(OrchestratorError::UpgradeError(actual_error)),
                Err(OrchestratorError::UpgradeError(expected_error)),
            ) => {
                // TODO(CON-1631): introduce distinct enum variants to better compare errors
                assert!(actual_error.contains(expected_error));
            }
            _ => {
                panic!("Upgrade loop flow result does not match expected flow");
            }
        }

        // Check new subnet assignment
        let new_subnet_assignment = upgrade_loop.subnet_assignment();
        assert_eq!(
            new_subnet_assignment,
            test_scenario.expected_subnet_assignment(logs.clone()),
        );

        // Check presence/absence of local CUP, including its height, which
        // tests the recovery case where the recovery CUP would overwrite the
        // local CUP
        let cup_file = tmp_path.join("cups").join("cup.types.v1.CatchUpPackage.pb");
        let local_cup_height = std::fs::read(cup_file)
            .map(|bytes| {
                CatchUpPackage::try_from(&pb::CatchUpPackage::decode(&bytes[..]).unwrap())
                    .unwrap()
                    .height()
            })
            .ok();
        assert_eq!(
            local_cup_height,
            test_scenario.expected_local_cup_height(logs.clone())
        );

        // Check that the state was removed if necessary
        test_scenario.assert_removed_state_if_necessary(logs.clone());

        // Check whether the replica process is running or not
        assert_eq!(
            upgrade_loop.replica_process.lock().unwrap().is_running(),
            test_scenario.should_replica_process_be_running(logs),
        );

        // Asserting further invariants:
        // - Consistent flow/subnet assignment:
        match flow_result {
            Ok(OrchestratorControlFlow::Assigned(flow_subnet_id))
            | Ok(OrchestratorControlFlow::Leaving(flow_subnet_id)) => {
                assert_matches!(new_subnet_assignment, SubnetAssignment::Assigned(assigned_subnet_id) if assigned_subnet_id == flow_subnet_id);
            }
            Ok(OrchestratorControlFlow::Unassigned) => {
                assert_matches!(new_subnet_assignment, SubnetAssignment::Unassigned);
            }
            Ok(OrchestratorControlFlow::Stop) => {
                assert_matches!(
                    new_subnet_assignment,
                    SubnetAssignment::Assigned(_) | SubnetAssignment::Unassigned
                )
            }
            Err(OrchestratorError::UpgradeError(_)) => {}
            Err(_) => {
                panic!("Unexpected error from upgrade loop");
            }
        }
        // - A successful upgrade loop means the subnet assignment cannot be
        // `Unknown`
        assert!(!matches!(new_subnet_assignment, SubnetAssignment::Unknown));
        // - There is a local CUP after the upgrade loop <=> the subnet assignment
        // must be `Assigned`
        assert_eq!(
            local_cup_height.is_some(),
            matches!(new_subnet_assignment, SubnetAssignment::Assigned(_))
        );
        // - The replica process is running <=> the new subnet assignment is
        // `Assigned` AND (EITHER we are not upgrading OR the replica was
        // already started beforehand)
        assert_eq!(
            upgrade_loop.replica_process.lock().unwrap().is_running(),
            matches!(new_subnet_assignment, SubnetAssignment::Assigned(_))
                && (matches!(
                    flow_result,
                    Ok(OrchestratorControlFlow::Assigned(_))
                        | Ok(OrchestratorControlFlow::Leaving(_))
                ) || test_scenario.was_replica_process_started_previously())
        );
        // - As an assigned node:
        if new_subnet_assignment != SubnetAssignment::Unassigned {
            // - If the replicator has not yet replicated all versions before init, then we should never
            // be rebooting
            assert!(
                test_scenario
                    .upgrade_to
                    .as_ref()
                    .map(|u| u.has_replicated_versions_before_init)
                    .is_some_and(|has_replicated| has_replicated)
                    || !matches!(flow_result, Ok(OrchestratorControlFlow::Stop))
            );
            // - If the upgrade version was recalled, then we should never be rebooting
            assert!(
                !test_scenario
                    .upgrade_to
                    .as_ref()
                    .map(|u| u.is_recalled)
                    .is_some_and(|is_recalled| is_recalled)
                    || !matches!(flow_result, Ok(OrchestratorControlFlow::Stop))
            );
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_upgrade_scenarios(
        #[values(NODE_1)] node_id: NodeId,
        #[values(ReplicaVersion::try_from("replica_version_0.1").unwrap())] current_replica_version: ReplicaVersion,
        #[values(
            None,
            Some(CUPScenario {
                height: Height::from(100),
                subnet_id: SUBNET_1,
                registry_version: RegistryVersion::from(10),
            }),
            Some(CUPScenario {
                height: Height::from(1000),
                subnet_id: SUBNET_1,
                registry_version: RegistryVersion::from(100),
            }),
        )]
        has_local_cup: Option<CUPScenario>,
        #[values(
            None,
            Some((
                CUPScenario {
                    height: Height::from(101),
                    subnet_id: SUBNET_1,
                    registry_version: RegistryVersion::from(51),
                },
                RegistryVersion::from(52),
            )),
            Some((
                CUPScenario {
                    height: Height::from(1001),
                    subnet_id: SUBNET_1,
                    registry_version: RegistryVersion::from(100),
                },
                RegistryVersion::from(101),
            )),
        )]
        has_registry_cup: Option<(CUPScenario, RegistryVersion)>,
        // Note: the initial subnet assignment should normally not be `Assigned` if the node has
        // no local CUP and vice versa. However, we still test these combinations to verify that
        // the code behaves correctly even if such invalid states occur.
        // For example, if the node left the subnet and thus set to `Unassigned` but failed to
        // delete the local CUP because of an IO error in the previous upgrade loop, then they would
        // start the loop with a local CUP but with an `Unassigned` initial subnet assignment.
        #[values(
            SubnetAssignment::Unknown,
            SubnetAssignment::Unassigned,
            SubnetAssignment::Assigned(SUBNET_1)
        )]
        initial_subnet_assignment: SubnetAssignment,
        #[values(
            None,
            Some(RegistryVersion::from(5)),
            Some(RegistryVersion::from(10)),
            Some(RegistryVersion::from(50)),
            Some(RegistryVersion::from(100)),
            Some(RegistryVersion::from(150))
        )]
        is_leaving: Option<RegistryVersion>,
        #[values(false, true)] does_upgrade: bool,
        #[values(ReplicaVersion::try_from("replica_version_0.2").unwrap())] upgrade_replica_version: ReplicaVersion,
        #[values(
            RegistryVersion::from(3),
            RegistryVersion::from(5),
            RegistryVersion::from(10),
            RegistryVersion::from(75),
            RegistryVersion::from(100),
            RegistryVersion::from(150),
            RegistryVersion::from(175)
        )]
        upgrade_registry_version: RegistryVersion,
        #[values(false, true)] upgrade_is_recalled: bool,
        #[values(false, true)] upgrade_has_replicated_versions_before_init: bool,
    ) {
        let upgrade_to = does_upgrade.then_some(ReplicaUpgradeScenario {
            replica_version: upgrade_replica_version,
            registry_version: upgrade_registry_version,
            is_recalled: upgrade_is_recalled,
            has_replicated_versions_before_init: upgrade_has_replicated_versions_before_init,
        });

        let test_scenario = UpgradeTestScenario {
            node_id,
            current_replica_version,
            has_local_cup,
            has_registry_cup,
            initial_subnet_assignment,
            is_leaving,
            upgrade_to,
        };

        if test_scenario.has_local_cup.is_none()
            && test_scenario.has_registry_cup.is_none()
            && matches!(
                test_scenario.initial_subnet_assignment,
                SubnetAssignment::Assigned(_)
            )
        {
            // Invalid scenario: having an `Assigned` initial subnet assignment
            // means that the node previously had a local or registry CUP
            return;
        }

        if test_scenario.has_local_cup.is_none()
            && test_scenario.has_registry_cup.is_some()
            && test_scenario.is_leaving.is_some()
        {
            // Untested scenario: being unassigned, seeing a genesis CUP but
            // instantly having to leave (unlikely in practice and complex to
            // test)
            return;
        }

        if let Some(highest_cup) = test_scenario.highest_cup()
            && let Some(leaving_registry_version) = test_scenario.is_leaving
            && highest_cup.registry_version >= leaving_registry_version
        {
            // TODO(CON-1630): leaving scenario is untested for now as it involves
            // mocking state removal and process (replica) management
            return;
        }

        test_upgrade(test_scenario).await;
    }

    #[tokio::test]
    async fn test_ignore_recalled_versions_if_nns() {
        let test_scenario = UpgradeTestScenario {
            node_id: NODE_1,
            current_replica_version: ReplicaVersion::try_from("replica_version_0.1").unwrap(),
            has_local_cup: Some(CUPScenario {
                height: Height::from(100),
                // Set as the NNS subnet in `setup_registry`
                subnet_id: SUBNET_42,
                registry_version: RegistryVersion::from(10),
            }),
            has_registry_cup: None,
            initial_subnet_assignment: SubnetAssignment::Unknown,
            is_leaving: None,
            upgrade_to: Some(ReplicaUpgradeScenario {
                replica_version: ReplicaVersion::try_from("replica_version_0.2").unwrap(),
                registry_version: RegistryVersion::from(10),
                is_recalled: true,
                has_replicated_versions_before_init: false,
            }),
        };

        let logger = InMemoryReplicaLogger::new();
        let replica_logger = ReplicaLogger::from(&logger);
        let (registry_helper, data_provider) = test_scenario.setup_registry(replica_logger.clone());

        let tmp_dir = tempdir().unwrap();
        let tmp_path = tmp_dir.path();
        let mut upgrade_loop = create_upgrade_for_test(
            tmp_path,
            replica_logger,
            test_scenario.clone(),
            data_provider,
            registry_helper,
        )
        .await;

        let flow_result = upgrade_loop.check().await;

        // Assert that despite the replicator not having replicated all versions before init,
        // and the version being recalled, we proceed with upgrading as it is the NNS subnet.
        assert_matches!(flow_result, Ok(OrchestratorControlFlow::Stop));
    }

    #[tokio::test]
    async fn test_ignore_up_to_date_replicator_after_timeout() {
        let test_scenario = UpgradeTestScenario {
            node_id: NODE_1,
            current_replica_version: ReplicaVersion::try_from("replica_version_0.1").unwrap(),
            has_local_cup: Some(CUPScenario {
                height: Height::from(100),
                subnet_id: SUBNET_1,
                registry_version: RegistryVersion::from(10),
            }),
            has_registry_cup: None,
            initial_subnet_assignment: SubnetAssignment::Unknown,
            is_leaving: None,
            upgrade_to: Some(ReplicaUpgradeScenario {
                replica_version: ReplicaVersion::try_from("replica_version_0.2").unwrap(),
                registry_version: RegistryVersion::from(10),
                is_recalled: true,
                has_replicated_versions_before_init: false,
            }),
        };

        let logger = InMemoryReplicaLogger::new();
        let replica_logger = ReplicaLogger::from(&logger);
        let (registry_helper, data_provider) = test_scenario.setup_registry(replica_logger.clone());

        let tmp_dir = tempdir().unwrap();
        let tmp_path = tmp_dir.path();
        let mut upgrade_loop = create_upgrade_for_test(
            tmp_path,
            replica_logger,
            test_scenario.clone(),
            data_provider,
            registry_helper,
        )
        .await;

        // Ensure we hit the timeout
        tokio::time::sleep(TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR + Duration::from_secs(2)).await;

        let flow_result = upgrade_loop.check().await;

        // Assert that despite the replicator not having replicated all versions before init,
        // we proceed with the our own view of the registry after the timeout.
        assert_matches!(flow_result, Err(OrchestratorError::UpgradeError(err)) if err.contains("Not upgrading to recalled replica version"));
    }

    fn make_ecdsa_key_id() -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "some_ecdsa_key".to_string(),
        })
    }

    fn make_schnorr_key_id() -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "some_eddsa_key".to_string(),
        })
    }

    fn make_vetkd_key_id() -> MasterPublicKeyId {
        MasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "some_vetkd_key".to_string(),
        })
    }

    fn make_key_ids_for_all_schemes() -> Vec<MasterPublicKeyId> {
        vec![
            make_ecdsa_key_id(),
            make_schnorr_key_id(),
            make_vetkd_key_id(),
        ]
    }

    fn clone_key_id_with_name(key_id: &MasterPublicKeyId, name: &str) -> MasterPublicKeyId {
        let mut key_id = key_id.clone();
        match key_id {
            MasterPublicKeyId::Ecdsa(ref mut key_id) => key_id.name = name.into(),
            MasterPublicKeyId::Schnorr(ref mut key_id) => key_id.name = name.into(),
            MasterPublicKeyId::VetKd(ref mut key_id) => key_id.name = name.into(),
        }
        key_id
    }

    #[derive(Clone)]
    enum KeyTranscript {
        IDkg(IDkgTranscript),
        NiDkg(NiDkgTranscript),
    }

    fn get_master_key_changed_metric(
        key: &MasterPublicKeyId,
        metrics: &OrchestratorMetrics,
    ) -> u64 {
        metrics
            .master_public_key_changed_errors
            .get_metric_with_label_values(&[&key.to_string()])
            .unwrap()
            .get()
    }

    struct Setup {
        rng: ReproducibleRng,
        tmp: TempDir,
        nidkg_registry_version: Option<u64>,
    }

    impl Setup {
        fn new() -> Self {
            Self::new_with_nidkg_registry_version(None)
        }

        fn new_with_nidkg_registry_version(nidkg_registry_version: Option<u64>) -> Self {
            let tmp = tempdir().expect("Unable to create temp directory");
            let rng = reproducible_rng();
            Self {
                rng,
                tmp,
                nidkg_registry_version,
            }
        }

        fn generate_key_transcript(
            &mut self,
            key_id: &MasterPublicKeyId,
        ) -> (MasterPublicKeyId, KeyTranscript) {
            let transcript = match key_id {
                MasterPublicKeyId::Ecdsa(ecdsa_key_id) => match ecdsa_key_id.curve {
                    EcdsaCurve::Secp256k1 => {
                        self.generate_idkg_key_transcript(AlgorithmId::ThresholdEcdsaSecp256k1)
                    }
                },
                MasterPublicKeyId::Schnorr(schnorr_key_id) => match schnorr_key_id.algorithm {
                    SchnorrAlgorithm::Bip340Secp256k1 => {
                        self.generate_idkg_key_transcript(AlgorithmId::ThresholdSchnorrBip340)
                    }

                    SchnorrAlgorithm::Ed25519 => {
                        self.generate_idkg_key_transcript(AlgorithmId::ThresholdEd25519)
                    }
                },
                MasterPublicKeyId::VetKd(_) => self.generate_nidkg_key_transcript(key_id),
            };
            (key_id.clone(), transcript)
        }

        fn generate_idkg_key_transcript(&mut self, alg: AlgorithmId) -> KeyTranscript {
            let env = CanisterThresholdSigTestEnvironment::new(1, &mut self.rng);
            let (dealers, receivers) = env.choose_dealers_and_receivers(
                &IDkgParticipants::AllNodesAsDealersAndReceivers,
                &mut self.rng,
            );
            KeyTranscript::IDkg(generate_key_transcript(
                &env,
                &dealers,
                &receivers,
                alg,
                &mut self.rng,
            ))
        }

        fn generate_nidkg_key_transcript(&mut self, key_id: &MasterPublicKeyId) -> KeyTranscript {
            let MasterPublicKeyId::VetKd(vetkd_key_id) = key_id.clone() else {
                panic!("Can't generate nidkg transcript for {key_id}");
            };
            let mut config = RandomNiDkgConfig::builder()
                .dkg_tag(NiDkgTag::HighThresholdForKey(
                    NiDkgMasterPublicKeyId::VetKd(vetkd_key_id),
                ))
                .subnet_size(4);

            if let Some(version) = self.nidkg_registry_version {
                config = config.registry_version(RegistryVersion::new(version));
            }

            let config = config.build(&mut self.rng);
            let env =
                NiDkgTestEnvironment::new_for_config_with_remote_vault(config.get(), &mut self.rng);
            KeyTranscript::NiDkg(run_ni_dkg_and_create_single_transcript(
                config.get(),
                &env.crypto_components,
            ))
        }

        fn path(&self) -> PathBuf {
            self.tmp.path().join(KEY_CHANGES_FILENAME)
        }
    }

    #[test]
    fn test_key_deletion_raises_alert_all_schemes() {
        for key_id in make_key_ids_for_all_schemes() {
            test_key_deletion_raises_alert(key_id)
        }
    }

    fn test_key_deletion_raises_alert(key_id: MasterPublicKeyId) {
        with_test_replica_logger(|log| {
            let mut setup = Setup::new();
            let key = setup.generate_key_transcript(&key_id);

            let c1 = make_cup_with_key_transcript(Height::from(10), Some(key));
            let c2 = make_cup_with_key_transcript(Height::from(100), None);

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id, &metrics);

            assert_eq!(before + 1, after);

            let metrics_new = OrchestratorMetrics::new(&MetricsRegistry::new());
            report_master_public_key_changed_metric(setup.path(), &metrics_new).unwrap();
            let after_restart = get_master_key_changed_metric(&key_id, &metrics_new);

            assert_eq!(after_restart, after);

            // If there are no persisted metrics we should not report anything
            let metrics_new = OrchestratorMetrics::new(&MetricsRegistry::new());
            let path = setup.path().parent().unwrap().join("test");
            report_master_public_key_changed_metric(path, &metrics_new).unwrap();
            let non_existent = get_master_key_changed_metric(&key_id, &metrics_new);

            assert_eq!(non_existent, 0);
        });
    }

    #[test]
    fn test_key_change_raises_alert_all_schemes() {
        for key_id in make_key_ids_for_all_schemes() {
            test_key_change_raises_alert(key_id)
        }
    }

    fn test_key_change_raises_alert(key_id: MasterPublicKeyId) {
        with_test_replica_logger(|log| {
            let mut setup = Setup::new();
            let key1 = setup.generate_key_transcript(&key_id);
            let key2 = setup.generate_key_transcript(&key_id);

            let c1 = make_cup_with_key_transcript(Height::from(10), Some(key1));
            let c2 = make_cup_with_key_transcript(Height::from(100), Some(key2));

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id, &metrics);

            assert_eq!(before + 1, after);
        });
    }

    #[test]
    fn test_key_unchanged_does_not_raise_alert_all_schemes() {
        for key_id in make_key_ids_for_all_schemes() {
            test_key_unchanged_does_not_raise_alert(key_id)
        }
    }

    fn test_key_unchanged_does_not_raise_alert(key_id: MasterPublicKeyId) {
        with_test_replica_logger(|log| {
            let mut setup = Setup::new();
            let key = setup.generate_key_transcript(&key_id);

            let c1 = make_cup_with_key_transcript(Height::from(10), Some(key.clone()));
            let c2 = make_cup_with_key_transcript(Height::from(100), Some(key));

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id, &metrics);

            assert_eq!(before, after);
        });
    }

    #[test]
    fn test_key_id_change_raises_alert_all_schemes() {
        for key_id in make_key_ids_for_all_schemes() {
            test_key_id_change_raises_alert(key_id)
        }
    }

    fn test_key_id_change_raises_alert(key_id1: MasterPublicKeyId) {
        with_test_replica_logger(|log| {
            let mut setup = Setup::new();
            let key = setup.generate_key_transcript(&key_id1);
            let c1 = make_cup_with_key_transcript(Height::from(10), Some(key.clone()));

            let key_id2 = clone_key_id_with_name(&key_id1, "other_key");
            let c2 = if let (MasterPublicKeyId::VetKd(key_id), KeyTranscript::NiDkg(transcript)) =
                (&key_id2, &key.1)
            {
                let mut transcript2 = transcript.clone();
                transcript2.dkg_id.dkg_tag =
                    NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id.clone()));
                make_cup_with_key_transcript(
                    Height::from(100),
                    Some((key_id2, KeyTranscript::NiDkg(transcript2))),
                )
            } else {
                make_cup_with_key_transcript(Height::from(100), Some((key_id2, key.1)))
            };

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id1, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id1, &metrics);

            assert_eq!(before + 1, after);
        });
    }

    #[test]
    fn test_key_created_does_not_raise_alert_all_schemes() {
        for key_id in make_key_ids_for_all_schemes() {
            test_key_created_does_not_raise_alert(key_id)
        }
    }

    fn test_key_created_does_not_raise_alert(key_id: MasterPublicKeyId) {
        with_test_replica_logger(|log| {
            let mut setup = Setup::new();
            let key = setup.generate_key_transcript(&key_id);

            let c1 = make_cup_with_key_transcript(Height::from(10), None);
            let c2 = make_cup_with_key_transcript(Height::from(100), Some(key));

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id, &metrics);

            assert_eq!(before, after);
        });
    }

    #[test]
    fn test_no_keys_created_does_not_raise_alert() {
        with_test_replica_logger(|log| {
            let setup = Setup::new();
            let key_id = make_ecdsa_key_id();

            let c1 = make_cup_with_key_transcript(Height::from(10), None);
            let c2 = make_cup_with_key_transcript(Height::from(100), None);

            let metrics = OrchestratorMetrics::new(&MetricsRegistry::new());

            let before = get_master_key_changed_metric(&key_id, &metrics);
            compare_master_public_keys(&c1, &c2, &metrics, setup.path(), &log);
            let after = get_master_key_changed_metric(&key_id, &metrics);

            assert_eq!(before, after);
        });
    }

    mock! {
        pub FakeRegistryClient{}

        impl RegistryClient for FakeRegistryClient {
                fn get_versioned_value(
                    &self,
                    key: &str,
                    version: RegistryVersion,
                ) -> RegistryClientVersionedResult<Vec<u8>>;

                fn get_key_family(
                    &self,
                    key_prefix: &str,
                    version: RegistryVersion,
                ) -> Result<Vec<String>, RegistryClientError>;

                fn get_latest_version(&self) -> RegistryVersion;
                fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time>;
        }
    }

    #[derive(Debug)]
    enum NodeInSubnetOnVersion {
        No,
        Yes { from: u64, to: u64 },
    }

    #[test]
    fn test_unassignment_decision() {
        let key_id = make_vetkd_key_id();
        let node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));

        let empty_subnet = Ok(RegistryVersionedRecord {
            key: "".to_string(),
            version: RegistryVersion::new(0),
            value: Some(SubnetRecord::default().encode_to_vec()),
        });
        let subnet_with_node = Ok(RegistryVersionedRecord {
            key: "".to_string(),
            version: RegistryVersion::new(0),
            value: Some(
                SubnetRecord {
                    membership: vec![node_id.get().to_vec()],
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        });

        let latest_registry_version = RegistryVersion::from(10);
        for (oldest_relevant_version, node_in_subnet, expected_decision) in [
            // Latest registry version is behind the oldest relevant version
            (
                15,
                NodeInSubnetOnVersion::No,
                UnassignmentDecision::StayInSubnet,
            ),
            // Node is in a subnet at latest registry version
            (
                10,
                NodeInSubnetOnVersion::Yes { from: 5, to: 10 },
                UnassignmentDecision::StayInSubnet,
            ),
            // Node isn't in a subnet at latest registry version
            // but it was between oldest relevant version and latest
            // registry version
            (
                5,
                NodeInSubnetOnVersion::Yes { from: 5, to: 7 },
                UnassignmentDecision::Later,
            ),
            // Node isn't in a subnet at latest registry version
            // and it wasn't from oldest relevant version until
            // the latest registry version
            (
                5,
                NodeInSubnetOnVersion::Yes { from: 1, to: 4 },
                UnassignmentDecision::Now,
            ),
            // Node wasn't ever in a subnet
            (5, NodeInSubnetOnVersion::No, UnassignmentDecision::Now),
        ] {
            let mut registry_client = MockFakeRegistryClient::new();

            let mut setup = Setup::new_with_nidkg_registry_version(Some(oldest_relevant_version));
            let key_transcript = setup.generate_key_transcript(&key_id);
            let cup = make_cup_with_key_transcript(Height::from(15), Some(key_transcript));

            println!(
                "Use-case: {oldest_relevant_version}, {node_in_subnet:?}, {expected_decision:?}"
            );
            match node_in_subnet {
                NodeInSubnetOnVersion::No => registry_client
                    .expect_get_versioned_value()
                    .return_const(empty_subnet.clone()),
                NodeInSubnetOnVersion::Yes { from, to } => {
                    let subnet_with_node = subnet_with_node.clone();
                    let empty_subnet = empty_subnet.clone();
                    registry_client
                        .expect_get_versioned_value()
                        .returning(move |_key, ver| {
                            if from <= ver.get() && ver.get() <= to {
                                subnet_with_node.clone()
                            } else {
                                empty_subnet.clone()
                            }
                        })
                }
            };

            let response = should_node_become_unassigned(
                &registry_client,
                latest_registry_version,
                node_id,
                subnet_id,
                &cup,
            );

            assert!(
                response == expected_decision,
                "Expected {expected_decision:?} but got: {response:?}"
            );
        }
    }

    #[test]
    fn test_stay_in_subnet_on_subnet_missing() {
        let node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let version = 10;

        let mut registry_client = MockFakeRegistryClient::new();
        registry_client
            .expect_get_versioned_value()
            .once()
            .return_const(Ok(RegistryVersionedRecord {
                key: make_subnet_record_key(subnet_id),
                version: RegistryVersion::new(0),
                value: None,
            }));

        assert!(node_is_in_subnet_at_version(
            &registry_client,
            node_id,
            subnet_id,
            version
        ))
    }

    #[test]
    fn test_stay_in_subnet_on_registry_error() {
        let node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let version = 10;

        let mut registry_client = MockFakeRegistryClient::new();
        registry_client
            .expect_get_versioned_value()
            .once()
            .return_const(Err(RegistryClientError::VersionNotAvailable {
                version: RegistryVersion::new(version),
            }));

        assert!(node_is_in_subnet_at_version(
            &registry_client,
            node_id,
            subnet_id,
            version
        ))
    }
}
