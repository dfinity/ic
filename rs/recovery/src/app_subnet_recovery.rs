use crate::{
    DataLocation, NeuronArgs, Recovery, RecoveryArgs, RecoveryResult, Step,
    cli::{
        consent_given, print_height_info, read_optional, read_optional_data_location,
        read_optional_node_ids, read_optional_subnet_id, read_optional_version,
        wait_for_confirmation,
    },
    error::{GracefulExpect, RecoveryError},
    recovery_iterator::RecoveryIterator,
    registry_helper::RegistryPollingStrategy,
    util::SshUser,
};
use clap::Parser;
use ic_base_types::{NodeId, SubnetId};
use ic_types::ReplicaVersion;
use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use std::{iter::Peekable, net::IpAddr, path::PathBuf};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};
use url::Url;

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
    /// finalize new blocks. This step issues a simple ic-admin command creating a proposal halting
    /// the consensus of the subnet we try to recover. It is recommended to add an SSH key which
    /// will be deployed to all nodes for a read-only access. This access will be needed later to
    /// download the subnet state from the most up to date node.
    Halt,
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
    /// on one of the nodes of the subnet and input "local" at this step.
    DownloadState,
    /// In this step we will take the latest persisted subnet state downloaded in the previous step
    /// and apply the finalized consensus artifacts on it via the deterministic state machine part
    /// of the replica to hopefully obtain the exact state which existed in the memory of all subnet
    /// nodes at the moment when a subnet issue has occurred. Note that if the cause of this recovery
    /// is a panic in the deterministic state machine when executing a certain height, we can specify
    /// a "target replay height" in this step. This target height should be chosen such that it is
    /// below the height causing the panic, but above or equal to the height of the last certification
    /// (share). Specifying this parameter will instruct ic-replay to stop at the given height and
    /// create a checkpoint, which will then be used to propose the recovery CUP.
    ICReplay,
    /// Now we want to verify that the height of the locally obtained execution state matches the
    /// highest finalized height, which was agreed upon by the subnet.
    ValidateReplayOutput,
    /// This step is only required if we want to deploy a new replica version to the troubled subnet
    /// before we resume its computation. Obviously, this step should not be skipped if the subnet
    /// has stalled due to a deterministic bug. You can continue with this step, if a problem was
    /// already identified, fixed and a hotfix version is ready to be proposed as a blessed version.
    /// If a version exists that does not need to be blessed, this step can be skipped, as the
    /// actual subnet upgrade will happen in the next step.
    BlessVersion,
    /// This step issues an ic-admin command that will create an upgrade proposal for the troubled
    /// subnet. Note that the subnet nodes will only upgrade after we proposed the corresponding
    /// recovery CUP referencing the new registry version.
    UpgradeVersion,
    /// Now we are ready to restart the subnet's computation. In order to do that, we need to
    /// instruct the subnet to start the computation from a specific height and state with a
    /// specific hash. We can only do this by writing a special message for the subnet into the
    /// registry. This step generates an ic-admin command creating a proposal with such an
    /// instruction for the subnet containing the hash of the state we obtained in the previous
    /// step and with a height strictly higher that the latest finalized height. Potentially, if
    /// we want to recover the subnet on a new set of nodes, their IDs can be specified as well.
    /// If the subnet has any Chain keys, we also need to specify a backup subnet to reshare the
    /// key from.
    ProposeCup,
    /// Our subnet should know by now that it's supposed to restart the computation from a state
    /// with the hash which we have written into the registry in the previous step. But the state
    /// with this hash only exists on our current machine. By uploading this state to any valid
    /// subnet node, we allow all other nodes to find and sync this state to their local disks.
    /// Pick a node where you have the admin access via SSH.
    UploadState,
    /// In the next step we verify that the upload node has received the message from the registry
    /// and it is aware that computation needs to be restarted.
    WaitForCUP,
    /// This step generates the last ic-admin command which creates a proposal instructing the
    /// subnet to resume its computation. This step is safe to execute even if not all nodes have
    /// synced the correct state we previously uploaded. If that's the case, the subnet will simply
    /// wait until enough nodes have synced the state and the subnet can finalize new blocks. This
    /// command also removes read-only SSH keys from all nodes of the subnet.
    Unhalt,
    /// This step deletes the working directory with all data. This step is safe to run if the
    /// recovery went smooth and no teams need data for further debugging.
    Cleanup,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct AppSubnetRecoveryArgs {
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

    #[clap(long, num_args(1..), value_parser=crate::util::node_id_from_str)]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<NodeId>>,

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    /// Public ssh key to be deployed to the subnet for read only access
    #[clap(long)]
    pub readonly_pub_key: Option<String>,

    /// The path to a file containing the private key associated with `readonly_pub_key`.
    #[clap(long)]
    pub readonly_key_file: Option<PathBuf>,

    /// IP address of the node to download the consensus pool from.
    #[clap(long)]
    pub download_pool_node: Option<IpAddr>,

    /// The method of downloading state. Possible values are either `local` (for a
    /// local recovery on the admin node) or the ipv6 address of the source node.
    /// Local recoveries allow us to skip a potentially expensive data transfer.
    #[clap(long, value_parser=crate::util::data_location_from_str)]
    pub download_state_method: Option<DataLocation>,

    /// If the downloaded state should be backed up locally
    #[clap(long)]
    pub keep_downloaded_state: Option<bool>,

    /// The method of uploading state. Possible values are either `local` (for a
    /// local recovery on the admin node) or the ipv6 address of the target node.
    /// Local recoveries allow us to skip a potentially expensive data transfer.
    #[clap(long, value_parser=crate::util::data_location_from_str)]
    pub upload_method: Option<DataLocation>,

    /// IP address of the node used to poll for the recovery CUP
    #[clap(long)]
    pub wait_for_cup_node: Option<IpAddr>,

    /// Id of the chain key subnet used for resharing chain keys to the subnet to be recovered
    #[clap(long, value_parser=crate::util::subnet_id_from_str)]
    pub chain_key_subnet_id: Option<SubnetId>,

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,

    /// Which steps to skip
    #[clap(long)]
    pub skip: Option<Vec<StepType>>,
}

pub struct AppSubnetRecovery {
    step_iterator: Peekable<StepTypeIter>,
    pub params: AppSubnetRecoveryArgs,
    pub recovery_args: RecoveryArgs,
    pub neuron_args: Option<NeuronArgs>,
    recovery: Recovery,
    logger: Logger,
}

impl AppSubnetRecovery {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_args: AppSubnetRecoveryArgs,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            neuron_args.clone(),
            recovery_args.nns_url.clone(),
            RegistryPollingStrategy::OnlyOnInit,
        )
        .expect_graceful("Failed to init recovery");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            neuron_args,
            recovery,
            logger,
        }
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for AppSubnetRecovery {
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
            StepType::Halt => {
                if self.params.readonly_pub_key.is_none() {
                    self.params.readonly_pub_key = read_optional(
                        &self.logger,
                        "Enter public key to add readonly SSH access to subnet. Ensure the right format.\n\
                        Format:   ssh-ed25519 <pubkey> <identity>\n\
                        Example:  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwS/0S6xH0g/xLDV0Tz7VeMZE9AKPeSbLmCsq9bY3F1 foo@dfinity.org\n\
                        Enter your key: ",
                    );
                }
            }

            StepType::DownloadCertifications => {
                info!(&self.logger, "Ensure subnet is halted.");
                // This can hardly be automated as currently the notion of "subnet is halted" is
                // unclear, especially in the presence of failures.
                wait_for_confirmation(&self.logger);
            }

            StepType::DownloadConsensusPool => {
                if self.params.download_pool_node.is_none() {
                    // We could pick a node with highest finalization height automatically, but we
                    // might have a preference between nodes of the same finalization height.
                    print_height_info(
                        &self.logger,
                        &self.recovery.registry_helper,
                        self.params.subnet_id,
                    );

                    self.params.download_pool_node =
                        read_optional(&self.logger, "Enter consensus pool download IP:");
                }
            }

            StepType::DownloadState => {
                if self.params.download_state_method.is_none() {
                    self.params.download_state_method = read_optional_data_location(
                        &self.logger,
                        "Enter location of the subnet state to be recovered [local/<ipv6>]:",
                    );
                }

                if self.params.keep_downloaded_state.is_none()
                    && let Some(&DataLocation::Remote(_)) =
                        self.params.download_state_method.as_ref()
                {
                    self.params.keep_downloaded_state = Some(consent_given(
                        &self.logger,
                        "Preserve original downloaded state locally?",
                    ));
                }
            }

            StepType::ICReplay => {
                if self.params.replay_until_height.is_none() {
                    self.params.replay_until_height =
                        read_optional(&self.logger, "Replay until height: ");
                }
            }

            StepType::BlessVersion => {
                if self.params.upgrade_version.is_none() {
                    self.params.upgrade_version =
                        read_optional_version(&self.logger, "Upgrade version: ");
                }
            }

            StepType::ProposeCup => {
                if self.params.replacement_nodes.is_none() {
                    self.params.replacement_nodes = read_optional_node_ids(
                        &self.logger,
                        "Enter space separated list of replacement nodes: ",
                    );
                }
                if self.params.chain_key_subnet_id.is_none() {
                    self.params.chain_key_subnet_id = read_optional_subnet_id(
                        &self.logger,
                        "Enter ID of subnet to reshare Chain keys from: ",
                    );
                }
            }

            StepType::UploadState => {
                if self.params.upload_method.is_none() {
                    self.params.upload_method = read_optional_data_location(
                        &self.logger,
                        "Are you performing a local recovery directly on the node, or a remote recovery? [local/<ipv6>]",
                    );
                }
            }

            StepType::WaitForCUP => {
                if self.params.wait_for_cup_node.is_none() {
                    if let Some(DataLocation::Remote(ip)) = self.params.upload_method {
                        self.params.wait_for_cup_node = Some(ip);
                    } else {
                        self.params.wait_for_cup_node = read_optional(
                            &self.logger,
                            "Enter IP of the node to be polled for the recovery CUP:",
                        );
                    }
                }
            }

            _ => {}
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        match step_type {
            StepType::Halt => {
                let keys = if let Some(pub_key) = &self.params.readonly_pub_key {
                    vec![pub_key.clone()]
                } else {
                    vec![]
                };
                Ok(Box::new(self.recovery.halt_subnet(
                    self.params.subnet_id,
                    true,
                    &keys,
                )))
            }

            StepType::DownloadCertifications => {
                if self.params.readonly_pub_key.is_some() {
                    Ok(Box::new(self.recovery.get_download_certs_step(
                        self.params.subnet_id,
                        SshUser::Readonly,
                        self.params.readonly_key_file.clone(),
                        !self.interactive(),
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::MergeCertificationPools => {
                if self.params.readonly_pub_key.is_some() {
                    Ok(Box::new(self.recovery.get_merge_certification_pools_step()))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadConsensusPool => {
                if let Some(node_ip) = self.params.download_pool_node {
                    let (ssh_user, key_file) = if self.params.readonly_pub_key.is_some() {
                        (SshUser::Readonly, self.params.readonly_key_file.clone())
                    } else {
                        (SshUser::Admin, self.recovery.admin_key_file.clone())
                    };

                    Ok(Box::new(self.recovery.get_download_consensus_pool_step(
                        node_ip, ssh_user, key_file,
                    )?))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadState => match self.params.download_state_method {
                Some(DataLocation::Local) => {
                    Ok(Box::new(self.recovery.get_copy_local_state_step()))
                }
                Some(DataLocation::Remote(node_ip)) => {
                    let (ssh_user, key_file) = if self.params.readonly_pub_key.is_some() {
                        (SshUser::Readonly, self.params.readonly_key_file.clone())
                    } else {
                        (SshUser::Admin, self.recovery.admin_key_file.clone())
                    };

                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        ssh_user,
                        key_file,
                        self.params.keep_downloaded_state == Some(true),
                    )?))
                }
                None => Err(RecoveryError::StepSkipped),
            },

            StepType::ICReplay => Ok(Box::new(self.recovery.get_replay_step(
                self.params.subnet_id,
                None,
                None,
                self.params.replay_until_height,
                !self.interactive(),
            ))),

            StepType::ValidateReplayOutput => Ok(Box::new(
                self.recovery
                    .get_validate_replay_step(self.params.subnet_id, 0),
            )),

            StepType::UploadState => {
                if let Some(method) = self.params.upload_method {
                    Ok(Box::new(
                        self.recovery.get_upload_state_and_restart_step(method),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::BlessVersion => {
                if let Some(upgrade_version) = &self.params.upgrade_version {
                    let params = self.params.clone();
                    let (url, hash) = params
                        .upgrade_image_url
                        .and_then(|url| params.upgrade_image_hash.map(|hash| (url, hash)))
                        .or_else(|| Recovery::get_img_url_and_sha(upgrade_version).ok())
                        .ok_or(RecoveryError::UnexpectedError(
                            "couldn't retrieve the upgrade image params".into(),
                        ))?;
                    let step = self
                        .recovery
                        .elect_replica_version(upgrade_version, url, hash)?;
                    Ok(Box::new(step))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UpgradeVersion => {
                if let Some(upgrade_version) = &self.params.upgrade_version {
                    Ok(Box::new(self.recovery.deploy_guestos_to_all_subnet_nodes(
                        self.params.subnet_id,
                        upgrade_version,
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ProposeCup => {
                let state_params = self.recovery.get_replay_output()?;
                let recovery_height = Recovery::get_recovery_height(state_params.height);
                let default = vec![];
                Ok(Box::new(self.recovery.update_recovery_cup(
                    self.params.subnet_id,
                    recovery_height,
                    state_params.hash,
                    self.params.replacement_nodes.as_ref().unwrap_or(&default),
                    None,
                    self.params.chain_key_subnet_id,
                )?))
            }

            StepType::WaitForCUP => {
                if let Some(node_ip) = self.params.wait_for_cup_node {
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::Unhalt => Ok(Box::new(self.recovery.halt_subnet(
                self.params.subnet_id,
                false,
                &["".to_string()],
            ))),

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
