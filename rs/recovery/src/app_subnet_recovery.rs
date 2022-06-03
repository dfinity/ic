use crate::recovery_iterator::RecoveryIterator;
use crate::RecoveryResult;
use crate::{error::RecoveryError, RecoveryArgs};
use clap::Parser;
use ic_base_types::{NodeId, SubnetId};
use ic_types::ReplicaVersion;
use slog::Logger;
use std::net::IpAddr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{NeuronArgs, Recovery, Step};

#[derive(Debug, Copy, Clone, EnumIter)]
pub enum StepType {
    Halt,
    DownloadState,
    UpdateConfig,
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

    /// IP address of the node to upload the new subnet state to
    #[clap(long)]
    pub upload_node: Option<IpAddr>,
}

pub struct AppSubnetRecovery {
    step_iterator: Box<dyn Iterator<Item = StepType>>,
    pub params: AppSubnetRecoveryArgs,
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
        let ssh_confirmation = neuron_args.is_some();
        Self {
            step_iterator: Box::new(StepType::iter()),
            params: subnet_args,
            recovery: Recovery::new(logger.clone(), recovery_args, neuron_args, ssh_confirmation)
                .expect("Failed to init recovery"),
            logger,
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

            StepType::DownloadState => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        self.params.pub_key.is_some(),
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UpdateConfig => Ok(Box::new(self.recovery.get_update_config_step())),

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
                )))
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
