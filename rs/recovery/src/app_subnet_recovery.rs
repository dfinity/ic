use crate::{
    cli::{
        consent_given, print_height_info, read_optional, read_optional_node_ids,
        read_optional_subnet_id, read_optional_version, wait_for_confirmation,
    },
    error::RecoveryError,
    recovery_iterator::RecoveryIterator,
    registry_helper::RegistryPollingStrategy,
    NeuronArgs, Recovery, RecoveryArgs, RecoveryResult, Step, CUPS_DIR,
};
use clap::Parser;
use ic_base_types::{NodeId, SubnetId};
use ic_types::ReplicaVersion;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::{iter::Peekable, net::IpAddr};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};
use url::Url;

#[derive(
    Debug, Copy, Clone, PartialEq, EnumIter, EnumString, Serialize, Deserialize, EnumMessage,
)]
pub enum StepType {
    /// Before we can start the recovery process, we need to prevent the subnet from attempting to
    /// finalize new blocks. This step issues a simple ic-admin command creating a proposal halting
    /// the consensus of the subnet we try to recover. It is recommended to add an SSH key which
    /// will be deployed to all nodes for a read-only access. This access will be needed later to
    /// download the subnet state from the most up to date node.
    Halt,
    /// In order to determine whether we had a possible state divergence during the subnet failure,
    /// we need to pull all certification pools from all nodes.
    DownloadCertifications,
    /// In this step we will merge all found certifications and determine whether it is safe to
    /// continue without a manual intervention. In most cases, when a subnet happened due to a
    /// replica bug and not due to malicious actors, this step should not reveal any problems.
    MergeCertificationPools,
    /// In this step we will download the latest persisted subnet state and all finalized consensus
    /// artifacts. For that we should use a node, that is up to date with the highest certification
    /// and finalization height because this node should contain all we need for the recovery.
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

#[derive(Debug, Clone, PartialEq, Parser, Serialize, Deserialize)]
#[clap(version = "1.0")]
pub struct AppSubnetRecoveryArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to upgrade the broken subnet to
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_version: Option<ReplicaVersion>,

    /// URL of the upgrade image
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_image_url: Option<Url>,

    /// SHA256 hash of the upgrade image
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_image_hash: Option<String>,

    #[clap(long, multiple_values(true), parse(try_from_str=crate::util::node_id_from_str))]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<NodeId>>,

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    /// Public ssh key to be deployed to the subnet for read only access
    #[clap(long)]
    pub pub_key: Option<String>,

    /// IP address of the node to download the subnet state from
    #[clap(long)]
    pub download_node: Option<IpAddr>,

    /// If the downloaded state should be backed up locally
    #[clap(long)]
    pub keep_downloaded_state: Option<bool>,

    /// IP address of the node to upload the new subnet state to
    #[clap(long)]
    pub upload_node: Option<IpAddr>,

    /// Id of the chain key subnet used for resharing chain keys to the subnet to be recovered
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub chain_key_subnet_id: Option<SubnetId>,

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,
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
        .expect("Failed to init recovery");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            neuron_args,
            recovery,
            logger,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
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

    fn read_step_params(&mut self, step_type: StepType) {
        // Depending on the next step we might require some user interaction before we can execute
        // it.
        match step_type {
            StepType::Halt => {
                if self.params.pub_key.is_none() {
                    self.params.pub_key = read_optional(
                        &self.logger,
                        "Enter public key to add readonly SSH access to subnet: ",
                    );
                }
            }

            StepType::DownloadCertifications => {
                info!(&self.logger, "Ensure subnet is halted.");
                // This can hardly be automated as currently the notion of "subnet is halted" is
                // unclear, especially in the presence of failures.
                wait_for_confirmation(&self.logger);
            }

            StepType::DownloadState => {
                // We could pick a node with highest finalization height automatically,
                // but we might have a preference between nodes of the same finalization height.
                print_height_info(
                    &self.logger,
                    &self.recovery.registry_helper,
                    self.params.subnet_id,
                );

                if self.params.download_node.is_none() {
                    self.params.download_node = read_optional(&self.logger, "Enter download IP:");
                }

                self.params.keep_downloaded_state = Some(consent_given(
                    &self.logger,
                    "Preserve original downloaded state locally?",
                ));
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
                if self.params.upload_node.is_none() {
                    self.params.upload_node =
                        read_optional(&self.logger, "Enter IP of node with admin access: ");
                }
            }

            _ => {}
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        match step_type {
            StepType::Halt => {
                let keys = if let Some(pub_key) = &self.params.pub_key {
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
                if self.params.pub_key.is_some() {
                    Ok(Box::new(
                        self.recovery
                            .get_download_certs_step(self.params.subnet_id, false),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::MergeCertificationPools => {
                if self.params.pub_key.is_some() {
                    Ok(Box::new(self.recovery.get_merge_certification_pools_step()))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadState => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        self.params.pub_key.is_some(),
                        self.params.keep_downloaded_state == Some(true),
                        /*additional_excludes=*/ vec![CUPS_DIR],
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ICReplay => Ok(Box::new(self.recovery.get_replay_step(
                self.params.subnet_id,
                None,
                None,
                self.params.replay_until_height,
            ))),

            StepType::ValidateReplayOutput => Ok(Box::new(
                self.recovery
                    .get_validate_replay_step(self.params.subnet_id, 0),
            )),

            StepType::UploadState => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_upload_and_restart_step(node_ip)))
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
                if let Some(node_ip) = self.params.upload_node {
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
