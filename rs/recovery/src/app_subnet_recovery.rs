use crate::cli::{
    consent_given, print_height_info, read_optional, read_optional_ip, read_optional_node_ids,
    read_optional_subnet_id, read_optional_version, wait_for_confirmation,
};
use crate::recovery_iterator::RecoveryIterator;
use crate::RecoveryResult;
use crate::{error::RecoveryError, RecoveryArgs};
use clap::Parser;
use ic_base_types::{NodeId, SubnetId};
use ic_types::ReplicaVersion;
use slog::{info, Logger};
use std::net::IpAddr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{NeuronArgs, Recovery, Step};

#[derive(Debug, Copy, Clone, EnumIter)]
pub enum StepType {
    Halt,
    DownloadCertifications,
    MergeCertificationPools,
    DownloadState,
    ICReplay,
    ValidateReplayOutput,
    BlessVersion,
    UpgradeVersion,
    ProposeCup,
    UploadState,
    WaitForCUP,
    Unhalt,
    Cleanup,
}

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct AppSubnetRecoveryArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to upgrade the broken subnet to
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_version: Option<ReplicaVersion>,

    #[clap(long, multiple_values(true), parse(try_from_str=crate::util::node_id_from_str))]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<NodeId>>,

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

    /// Id of the ecdsa subnet used for resharing ecdsa key of subnet to be recovered
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub ecdsa_subnet_id: Option<SubnetId>,
}

pub struct AppSubnetRecovery {
    step_iterator: Box<dyn Iterator<Item = StepType>>,
    pub params: AppSubnetRecoveryArgs,
    recovery: Recovery,
    interactive: bool,
    logger: Logger,
}

impl AppSubnetRecovery {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_args: AppSubnetRecoveryArgs,
        interactive: bool,
    ) -> Self {
        let ssh_confirmation = neuron_args.is_some();
        let recovery = Recovery::new(logger.clone(), recovery_args, neuron_args, ssh_confirmation)
            .expect("Failed to init recovery");
        recovery.init_registry_local_store();
        Self {
            step_iterator: Box::new(StepType::iter()),
            params: subnet_args,
            recovery,
            logger,
            interactive,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
    }
}

impl RecoveryIterator<StepType> for AppSubnetRecovery {
    fn get_step_iterator(&mut self) -> &mut Box<dyn Iterator<Item = StepType>> {
        &mut self.step_iterator
    }

    fn get_logger(&self) -> &Logger {
        &self.logger
    }

    fn interactive(&self) -> bool {
        self.interactive
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
                // This can hardly be automated as currently the notion of "subnet is halted" is unclear,
                // especially in the presence of failures.
                wait_for_confirmation(&self.logger);
            }

            StepType::DownloadState => {
                // We could pick a node with highest finalization height automatically,
                // but we might have a preference between nodes of the same finalization height.
                print_height_info(
                    &self.logger,
                    self.recovery.registry_client.clone(),
                    self.params.subnet_id,
                );

                if self.params.download_node.is_none() {
                    self.params.download_node =
                        read_optional_ip(&self.logger, "Enter download IP:");
                }

                self.params.keep_downloaded_state = Some(consent_given(
                    &self.logger,
                    "Preserve original downloaded state locally?",
                ));
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
                if self.params.ecdsa_subnet_id.is_none() {
                    self.params.ecdsa_subnet_id = read_optional_subnet_id(
                        &self.logger,
                        "Enter ID of subnet to reshare ECDSA key from: ",
                    );
                }
            }

            StepType::UploadState => {
                if self.params.upload_node.is_none() {
                    self.params.upload_node =
                        read_optional_ip(&self.logger, "Enter IP of node with admin access: ");
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
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ICReplay => Ok(Box::new(self.recovery.get_replay_step(
                self.params.subnet_id,
                None,
                None,
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
                    let step = self.recovery.bless_replica_version(upgrade_version)?;
                    Ok(Box::new(step))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UpgradeVersion => {
                if let Some(upgrade_version) = &self.params.upgrade_version {
                    Ok(Box::new(self.recovery.update_subnet_replica_version(
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
                    self.params.ecdsa_subnet_id,
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
