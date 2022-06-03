use crate::recovery_iterator::RecoveryIterator;
use crate::RecoveryResult;
use crate::{error::RecoveryError, RecoveryArgs};
use clap::Parser;
use ic_base_types::SubnetId;
use ic_types::ReplicaVersion;
use slog::Logger;
use std::net::IpAddr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{Recovery, Step};

#[derive(Debug, Copy, Clone, EnumIter)]
pub enum StepType {
    StopReplica,
    DownloadState,
    UpdateConfig,
    ICReplay,
    ValidateReplayOutput,
    UpdateRegistryLocalStore,
    CreateTars,
    SetRecoveryCUP,
    UpdateLocalStoreWithCUP,
    ExtractCUPFile,
    UploadCUPandRegistry,
    WaitForCUP,
    UploadState,
    Cleanup,
}

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct NNSRecoverySameNodesArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to upgrade the broken subnet to
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub upgrade_version: Option<ReplicaVersion>,

    /// Public ssh key to be deployed to the subnet for read only access
    #[clap(long)]
    pub pub_key: Option<String>,

    /// IP address of the node to download the subnet state from. Should be different to node used in nns-url.
    #[clap(long)]
    pub download_node: Option<IpAddr>,

    /// IP address of the node to upload the new subnet state to
    #[clap(long)]
    pub upload_node: Option<IpAddr>,
}

pub struct NNSRecoverySameNodes {
    step_iterator: Box<dyn Iterator<Item = StepType>>,
    pub params: NNSRecoverySameNodesArgs,
    recovery: Recovery,
    test: bool,
    logger: Logger,
}

impl NNSRecoverySameNodes {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        subnet_args: NNSRecoverySameNodesArgs,
        test: bool,
    ) -> Self {
        Self {
            step_iterator: Box::new(StepType::iter()),
            params: subnet_args,
            recovery: Recovery::new(logger.clone(), recovery_args, None, !test)
                .expect("Failed to init recovery"),
            test,
            logger,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
    }
}

impl RecoveryIterator<StepType> for NNSRecoverySameNodes {
    fn get_step_iterator(&mut self) -> &mut Box<dyn Iterator<Item = StepType>> {
        &mut self.step_iterator
    }

    fn get_logger(&self) -> &Logger {
        &self.logger
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        match step_type {
            StepType::StopReplica => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_stop_replica_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadState => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(
                        self.recovery.get_download_state_step(node_ip, false),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UpdateConfig => Ok(Box::new(self.recovery.get_update_config_step())),

            StepType::ICReplay => {
                if let Some(upgrade_version) = self.params.upgrade_version.clone() {
                    Ok(Box::new(self.recovery.get_replay_with_upgrade_step(
                        self.params.subnet_id,
                        upgrade_version,
                    )?))
                } else {
                    Ok(Box::new(self.recovery.get_replay_step(
                        self.params.subnet_id,
                        None,
                        None,
                    )))
                }
            }
            StepType::ValidateReplayOutput => Ok(Box::new(self.recovery.get_validate_replay_step(
                self.params.subnet_id,
                if self.params.upgrade_version.is_some() {
                    1
                } else {
                    0
                },
            ))),

            StepType::UpdateRegistryLocalStore => Ok(Box::new(
                self.recovery
                    .get_update_local_store_step(self.params.subnet_id),
            )),

            StepType::CreateTars => Ok(Box::new(self.recovery.get_create_tars_step(true))),
            StepType::SetRecoveryCUP => Ok(Box::new(
                self.recovery
                    .get_set_recovery_cup_step(self.params.subnet_id)?,
            )),

            StepType::UpdateLocalStoreWithCUP => Ok(Box::new(
                self.recovery
                    .get_update_local_store_step(self.params.subnet_id),
            )),

            StepType::ExtractCUPFile => Ok(Box::new(
                self.recovery
                    .get_extract_cup_file_step(self.params.subnet_id),
            )),

            StepType::UploadCUPandRegistry => Ok(Box::new(
                self.recovery
                    .get_upload_cup_and_tar_step(self.params.subnet_id, None),
            )),

            StepType::WaitForCUP => {
                if !self.test {
                    return Err(RecoveryError::StepSkipped);
                }
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UploadState => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_upload_cup_and_tar_step(
                        self.params.subnet_id,
                        Some(node_ip),
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
