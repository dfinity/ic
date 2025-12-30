use crate::{
    RecoveryArgs, RecoveryResult,
    cli::{
        consent_given, print_height_info, read_optional, read_optional_data_location,
        read_optional_version,
    },
    error::{GracefulExpect, RecoveryError},
    recovery_iterator::RecoveryIterator,
    registry_helper::RegistryPollingStrategy,
    util::{DataLocation, SshUser},
};
use clap::Parser;
use ic_base_types::SubnetId;
use ic_types::ReplicaVersion;
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::{iter::Peekable, net::IpAddr, net::Ipv6Addr, path::PathBuf};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumMessage, EnumString};
use url::Url;

use crate::{Recovery, Step};

#[derive(
    Copy,
    Clone,
    PartialEq,
    Debug,
    Deserialize,
    EnumIter,
    EnumMessage,
    EnumString,
    Serialize,
    strum_macros::Display,
)]
pub enum StepType {
    /// Before we can start the recovery process, we need to prevent the subnet from attempting to
    /// finalize new blocks. There is no way of halting the NNS subnet like we do for application
    /// subnets (by issuing a proposal), so this is a requirement before starting the recovery. As a
    /// fail-safe, this first step will stop the replica process on the given admin node.
    StopReplica,
    /// In order to determine whether we had a possible state divergence during the subnet failure,
    /// we need to pull the certification pools from as many nodes as possible.
    DownloadCertifications,
    /// In this step we will merge all found certifications and determine whether it is safe to
    /// continue without a manual intervention. In most cases, when a subnet happened due to a
    /// replica bug and not due to malicious actors, this step should not reveal any problems.
    MergeCertificationPools,
    /// In this step we will download all finalized consensus artifacts. For that we should use a
    /// node, that is up to date with the highest finalization height because this node will contain
    /// all required artifacts for the recovery.
    DownloadConsensusPool,
    /// In this step we will download the subnet state from a node that is sufficiently up to date
    /// with the rest of the subnet, i.e. not behind by more than 1 DKG interval. To avoid
    /// transferring the state over the network, it is recommended to perform the recovery directly
    /// on one of the nodes of the subnet and input "local" at this step. The node needs to have
    /// admin access because a readonly key cannot be deployed, like we do in application subnet
    /// recoveries.
    DownloadState,
    /// In this step we will take the latest persisted subnet state downloaded in the previous step
    /// and apply the finalized consensus artifacts on it via the deterministic state machine part
    /// of the replica to hopefully obtain the exact state which existed in the memory of all subnet
    /// nodes at the moment when a subnet issue has occurred. Note that if the cause of this recovery
    /// is a panic in the deterministic state machine when executing a certain height, we can specify
    /// a "target replay height" in this step. This target height should be chosen such that it is
    /// below the height causing the panic, but above or equal to the height of the last certification
    /// (share).
    /// This step will also add ingress messages to the registry canister to: (optionally) add and
    /// bless an upgrade version, and update the NNS subnet record to point to this new version.
    /// ic-replay will stop at the given height (+ the added heights for the ingress messages) and
    /// create a checkpoint, which will then be used to create the recovery CUP.
    ICReplay,
    /// Now we want to verify that the height of the locally obtained execution state matches the
    /// highest finalized height which was agreed upon by the subnet (+ the added heights for the
    /// ingress messages).
    ValidateReplayOutput,
    /// This step creates a new registry local store corresponding to the registry canister state
    /// at the height of the recovery CUP. This will later indicate to nodes to upgrade to the
    /// upgrade version.
    UpdateRegistryLocalStore,
    /// This step creates a tarball of the updated registry local store created in the previous
    /// step.
    CreateRegistryTar,
    /// This step creates a recovery CUP with the state hash corresponding to the checkpoint created
    /// in the ICReplay step. The DKG transcripts are the exact same ones as the last CUP of the
    /// subnet before the stall.
    GetRecoveryCUP,
    /// In this step we will create the recovery artifacts archive containing the recovery CUP and
    /// the registry archive created in the previous steps. After this step, the recovery artifacts
    /// should be uploaded to a well-known location that the rest of the subnet nodes will download
    /// from using guestos-recovery-upgrader and guestos-recovery-engine. They will overwrite their
    /// CUP and local store with the ones provided in this archive.
    CreateArtifacts,
    /// Our subnet should know by now that it's supposed to restart the computation from a state
    /// with the hash which we have written into the recovery CUP in the previous step. But the
    /// state with this hash only exists on our current machine. By uploading this state to any
    /// valid subnet node, we allow all other nodes to find and sync this state to their local
    /// disks. The node will be chosen as the one given in StopReplica or DownloadState step (the
    /// admin node).
    UploadState,
    /// The following step is optional but recommended. It will perform the action of the
    /// guestos-recovery-engine by overwriting the CUP and registry local store on the admin node.
    /// It is recommended to execute this step to ensure the upgrade is detected and the CUP is
    /// fetchable (done in the next step).
    UploadCUPAndRegistry,
    /// The following step is optional and executed only if the previous step was executed. It will
    /// poll the admin node until the recovery CUP is served. This is the sign of a successful
    /// upgrade to the upgrade version.
    WaitForCUP,
    /// This step deletes the working directory with all data. This step is safe to run if the
    /// recovery went smooth and no teams need data for further debugging. In particular, this will
    /// delete the recovery artifacts archive if using the default output directory.
    Cleanup,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct NNSRecoverySameNodesArgs {
    /// Id of the broken subnet
    #[clap(long, value_parser=crate::util::subnet_id_from_str)]
    pub subnet_id: SubnetId,

    /// Replica version to upgrade the broken subnet to
    #[clap(long)]
    pub upgrade_version: Option<ReplicaVersion>,

    /// URL of the upgrade image
    #[clap(long)]
    pub upgrade_image_url: Option<Url>,

    /// SHA256 hash of the upgrade image
    #[clap(long)]
    pub upgrade_image_hash: Option<String>,

    /// Whether to add and bless the upgrade version before upgrading the subnet to it.
    #[clap(long)]
    pub add_and_bless_upgrade_version: Option<bool>,

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    /// IP address of the node to download the consensus pool from.
    #[clap(long)]
    pub download_pool_node: Option<IpAddr>,

    /// The location of the node with admin access. Possible values are either `local` (for a local
    /// recovery on the admin node) or the ipv6 address of the source node. Local recoveries allow
    /// us to skip a potentially expensive data transfer.
    #[clap(long, value_parser=crate::util::data_location_from_str)]
    pub admin_access_location: Option<DataLocation>,

    /// If the downloaded state should be backed up locally
    #[clap(long)]
    pub keep_downloaded_state: Option<bool>,

    /// IP address of the node used to upload the recovery CUP and registry local store to and poll
    /// for the CUP
    #[clap(long)]
    pub wait_for_cup_node: Option<IpAddr>,

    /// The path to a file containing the private key that has backup access to all nodes in the subnet.
    #[clap(long)]
    pub backup_key_file: Option<PathBuf>,

    /// The output directory where the recovery artifacts (and its hash) will be stored.
    /// IMPORTANT: this directory must be in a shared mount of the node if doing the recovery
    /// locally (like /var/lib/ic/data) because the UploadCUPAndRegistry step (which happens after
    /// the artifacts are created) upgrades the node and thus swaps partitions. If not in a shared
    /// mount, the recovery artifacts will be lost after the upgrade.
    #[clap(long)]
    pub output_dir: Option<PathBuf>,

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,

    /// Which steps to skip
    #[clap(long)]
    pub skip: Option<Vec<StepType>>,
}

pub struct NNSRecoverySameNodes {
    step_iterator: Peekable<StepTypeIter>,
    pub params: NNSRecoverySameNodesArgs,
    pub recovery_args: RecoveryArgs,
    pub recovery: Recovery,
    logger: Logger,
}

impl NNSRecoverySameNodes {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        subnet_args: NNSRecoverySameNodesArgs,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            RecoveryArgs {
                // ic-admin is not needed for NNS recovery on same nodes so we force this argument
                // to true to avoid downloading it.
                use_local_binaries: true,
                ..recovery_args.clone()
            },
            /*neuron_args=*/ None,
            recovery_args.nns_url.clone(),
            RegistryPollingStrategy::OnlyOnInit,
        )
        .expect_graceful("Failed to init recovery");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            recovery,
            logger,
        }
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for NNSRecoverySameNodes {
    fn get_step_iterator(&mut self) -> &mut Peekable<StepTypeIter> {
        &mut self.step_iterator
    }

    fn store_next_step(&mut self, step_type: Option<StepType>) {
        self.params.next_step = step_type;
    }

    fn get_logger(&self) -> &Logger {
        &self.logger
    }

    fn interactive(&self) -> bool {
        !self.recovery_args.skip_prompts
    }

    fn get_skipped_steps(&self) -> Vec<StepType> {
        self.params.skip.clone().unwrap_or_default()
    }

    fn read_step_params(&mut self, step_type: StepType) {
        // Depending on the next step we might require some user interaction before we can execute
        // it.
        match step_type {
            StepType::StopReplica | StepType::DownloadState | StepType::UploadState => {
                if self.params.admin_access_location.is_none() {
                    self.params.admin_access_location = read_optional_data_location(
                        &self.logger,
                        "Enter state download/upload location (admin access required) [local/<ipv6>]:",
                    );
                }
            }
            _ => {}
        }
        match step_type {
            StepType::DownloadConsensusPool => {
                if self.params.download_pool_node.is_none() {
                    // We could pick a node with highest finalization height automatically, but we
                    // might have a preference between nodes of the same finalization height.
                    print_height_info(
                        &self.logger,
                        &self.recovery.registry_helper,
                        self.params.subnet_id,
                    );

                    self.params.download_pool_node = read_optional(
                        &self.logger,
                        "Enter consensus pool download IP (backup access required):",
                    );
                }
            }

            StepType::DownloadState => {
                if self.params.keep_downloaded_state.is_none()
                    && let Some(&DataLocation::Remote(_)) =
                        self.params.admin_access_location.as_ref()
                {
                    self.params.keep_downloaded_state = Some(consent_given(
                        &self.logger,
                        "Preserve original downloaded state locally?",
                    ));
                }
            }

            StepType::ICReplay => {
                if self.params.upgrade_version.is_none() {
                    self.params.upgrade_version =
                        read_optional_version(&self.logger, "Upgrade version: ");
                };
                if self.params.upgrade_version.is_some()
                    && self.params.add_and_bless_upgrade_version.is_none()
                {
                    self.params.add_and_bless_upgrade_version = Some(consent_given(
                        &self.logger,
                        "Add and bless the upgrade version before upgrading the subnet?",
                    ));
                }

                if self.params.replay_until_height.is_none() {
                    self.params.replay_until_height =
                        read_optional(&self.logger, "Replay until height: ");
                }
            }

            StepType::CreateArtifacts => {
                if self.params.output_dir.is_none() {
                    self.params.output_dir = read_optional(
                        &self.logger,
                        &format!(
                            "Enter output directory for recovery artifacts (must be in a shared mount if doing local recovery, default: {}):",
                            self.recovery.recovery_dir.join("output").display()
                        ),
                    );
                }
            }

            StepType::UploadCUPAndRegistry => {
                if self.params.wait_for_cup_node.is_none() {
                    self.params.wait_for_cup_node = if let Some(DataLocation::Remote(ip)) =
                        self.params.admin_access_location
                    {
                        consent_given(
                            &self.logger,
                            &format!(
                                "Would you like to recover the admin node now, i.e. upload the CUP and registry local store to it? ({ip})"
                            ),
                            ).then_some(ip)
                    } else {
                        read_optional(
                            &self.logger,
                            "If you would like to recover the admin node now, i.e. upload the CUP and registry local store to it, enter its IP address:",
                        )
                    };
                }
            }

            _ => {}
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        match step_type {
            StepType::StopReplica => {
                if let Some(method) = self.params.admin_access_location {
                    let node_ip = match method {
                        DataLocation::Remote(ip) => ip,
                        DataLocation::Local => IpAddr::V6(Ipv6Addr::LOCALHOST),
                    };
                    Ok(Box::new(self.recovery.get_stop_replica_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadCertifications => {
                Ok(Box::new(self.recovery.get_download_certs_step(
                    self.params.subnet_id,
                    SshUser::Backup,
                    self.params.backup_key_file.clone(),
                    !self.interactive(),
                )))
            }

            StepType::MergeCertificationPools => {
                Ok(Box::new(self.recovery.get_merge_certification_pools_step()))
            }

            StepType::DownloadConsensusPool => {
                if let Some(node_ip) = self.params.download_pool_node {
                    Ok(Box::new(self.recovery.get_download_consensus_pool_step(
                        node_ip,
                        SshUser::Backup,
                        self.params.backup_key_file.clone(),
                    )?))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadState => match self.params.admin_access_location {
                Some(DataLocation::Local) => {
                    Ok(Box::new(self.recovery.get_copy_local_state_step()))
                }
                Some(DataLocation::Remote(node_ip)) => {
                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        SshUser::Admin,
                        self.recovery.admin_key_file.clone(),
                        self.params.keep_downloaded_state == Some(true),
                    )?))
                }
                None => Err(RecoveryError::StepSkipped),
            },

            StepType::ICReplay => {
                if let Some(upgrade_version) = self.params.upgrade_version.clone() {
                    let params = self.params.clone();
                    let (url, hash) = params
                        .upgrade_image_url
                        .and_then(|url| params.upgrade_image_hash.map(|hash| (url, hash)))
                        .or_else(|| Recovery::get_img_url_and_sha(&upgrade_version).ok())
                        .ok_or(RecoveryError::UnexpectedError(
                            "couldn't retrieve the upgrade image params".into(),
                        ))?;
                    Ok(Box::new(self.recovery.get_replay_with_upgrade_step(
                        self.params.subnet_id,
                        upgrade_version,
                        url,
                        hash,
                        params.add_and_bless_upgrade_version == Some(true),
                        self.params.replay_until_height,
                        !self.interactive(),
                    )?))
                } else {
                    Ok(Box::new(self.recovery.get_replay_step(
                        self.params.subnet_id,
                        None,
                        None,
                        self.params.replay_until_height,
                        !self.interactive(),
                    )))
                }
            }
            StepType::ValidateReplayOutput => Ok(Box::new(self.recovery.get_validate_replay_step(
                self.params.subnet_id,
                u64::from(self.params.upgrade_version.is_some()),
            ))),

            StepType::UpdateRegistryLocalStore => {
                if self.params.upgrade_version.is_none() {
                    Err(RecoveryError::StepSkipped)
                } else {
                    Ok(Box::new(self.recovery.get_update_local_store_step(
                        self.params.subnet_id,
                        !self.interactive(),
                    )))
                }
            }

            StepType::CreateRegistryTar => {
                Ok(Box::new(self.recovery.get_create_registry_tar_step()))
            }

            StepType::GetRecoveryCUP => Ok(Box::new(
                self.recovery
                    .get_recovery_cup_step(self.params.subnet_id, !self.interactive())?,
            )),

            StepType::CreateArtifacts => Ok(Box::new(
                self.recovery
                    .get_create_nns_recovery_tar_step(self.params.output_dir.clone()),
            )),

            StepType::UploadState => {
                if let Some(method) = self.params.admin_access_location {
                    Ok(Box::new(
                        self.recovery.get_upload_state_and_restart_step(method),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UploadCUPAndRegistry => {
                if let Some(node_ip) = self.params.wait_for_cup_node {
                    Ok(Box::new(self.recovery.get_upload_cup_and_tar_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::WaitForCUP => {
                if let Some(node_ip) = self.params.wait_for_cup_node {
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
