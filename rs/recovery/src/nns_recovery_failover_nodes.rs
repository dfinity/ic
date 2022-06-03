use crate::admin_helper::RegistryParams;
use crate::command_helper::pipe_all;
use crate::recovery_iterator::RecoveryIterator;
use crate::{error::RecoveryError, RecoveryArgs};
use crate::{NeuronArgs, RecoveryResult, IC_REGISTRY_LOCAL_STORE};
use clap::Parser;
use ic_base_types::SubnetId;
use ic_types::{NodeId, ReplicaVersion};
use slog::Logger;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use url::Url;

use crate::{Recovery, Step};

/// Caller id that will be used to mutate the registry canister.
pub const CANISTER_CALLER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";

#[derive(Debug, Copy, Clone, EnumIter)]
pub enum StepType {
    StopReplica,
    DownloadState,
    UpdateConfig,
    ProposeToCreateSubnet,
    DownloadParentNNSStore,
    ICReplayWithRegistryContent,
    ValidateReplayOutput,
    UpdateRegistryLocalStore,
    CreateRegistryTar,
    UploadAndHostTar,
    ProposeCUP,
    WaitForCUP,
    UploadStateToChildNNSHost,
    Cleanup,
}

#[derive(Parser)]
#[clap(version = "1.0")]
pub struct NNSRecoveryFailoverNodesArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to start the new NNS with (has to be blessed by parent NNS)
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub replica_version: Option<ReplicaVersion>,

    /// Public ssh key to be deployed to the subnet for read only access
    #[clap(long)]
    pub pub_key: Option<String>,

    /// IP address of the auxiliary host the registry is uploaded to
    #[clap(long)]
    pub aux_ip: Option<IpAddr>,

    /// User of the auxiliary host the registry is uploaded to
    #[clap(long)]
    pub aux_user: Option<String>,

    /// IP address of the node to download the subnet state from
    #[clap(long)]
    pub download_node: Option<IpAddr>,

    /// IP address of the node to upload the new subnet state to
    #[clap(long)]
    pub upload_node: Option<IpAddr>,

    /// IP address of the parent nns host to download the registry store from
    #[clap(long)]
    pub parent_nns_host_ip: Option<IpAddr>,

    #[clap(long, multiple_values(true), parse(try_from_str=crate::util::node_id_from_str))]
    /// Replace the members of the given subnet with these nodes
    pub replacement_nodes: Option<Vec<NodeId>>,
}

pub struct NNSRecoveryFailoverNodes {
    step_iterator: Box<dyn Iterator<Item = StepType>>,
    pub params: NNSRecoveryFailoverNodesArgs,
    recovery: Recovery,
    logger: Logger,
    new_registry_local_store: PathBuf,
}

impl NNSRecoveryFailoverNodes {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_args: NNSRecoveryFailoverNodesArgs,
    ) -> Self {
        let ssh_confirmation = neuron_args.is_some();
        let recovery = Recovery::new(logger.clone(), recovery_args, neuron_args, ssh_confirmation)
            .expect("Failed to init recovery");
        let new_registry_local_store = recovery.work_dir.join(IC_REGISTRY_LOCAL_STORE);
        Self {
            step_iterator: Box::new(StepType::iter()),
            params: subnet_args,
            recovery,
            logger,
            new_registry_local_store,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
    }
}

impl RecoveryIterator<StepType> for NNSRecoveryFailoverNodes {
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

            StepType::ProposeToCreateSubnet => {
                if let (Some(version), Some(nodes)) = (
                    self.params.replica_version.clone(),
                    self.params.replacement_nodes.as_ref(),
                ) {
                    Ok(Box::new(
                        self.recovery.get_propose_to_create_test_system_subnet_step(
                            self.params.subnet_id,
                            version,
                            nodes,
                        ),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadParentNNSStore => {
                if let Some(ip) = self.params.parent_nns_host_ip {
                    Ok(Box::new(self.recovery.get_download_regsitry_store_step(
                        ip,
                        self.params.subnet_id,
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ICReplayWithRegistryContent => Ok(Box::new(
                self.recovery.get_replay_with_registry_content_step(
                    self.params.subnet_id,
                    self.new_registry_local_store.clone(),
                    CANISTER_CALLER_ID,
                )?,
            )),

            StepType::ValidateReplayOutput => Ok(Box::new(
                self.recovery
                    .get_validate_replay_step(self.params.subnet_id, 0),
            )),

            StepType::UpdateRegistryLocalStore => Ok(Box::new(
                self.recovery
                    .get_update_local_store_step(self.params.subnet_id),
            )),

            StepType::CreateRegistryTar => Ok(Box::new(self.recovery.get_create_tars_step(false))),

            StepType::UploadAndHostTar => {
                if let (Some(aux_user), Some(aux_ip)) =
                    (self.params.aux_user.clone(), self.params.aux_ip)
                {
                    Ok(Box::new(
                        self.recovery.get_upload_and_host_tar(
                            aux_user,
                            aux_ip,
                            self.recovery
                                .work_dir
                                .join(format!("{}.tar.gz", IC_REGISTRY_LOCAL_STORE)),
                        ),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ProposeCUP => {
                if let Some(aux_ip) = self.params.aux_ip {
                    let state_params = self.recovery.get_replay_output()?;
                    let recovery_height = Recovery::get_recovery_height(state_params.height);

                    let store_tar = self
                        .recovery
                        .work_dir
                        .join(format!("{}.tar.gz", IC_REGISTRY_LOCAL_STORE));
                    let mut sha256sum = Command::new("sha256sum");
                    sha256sum.arg(store_tar);

                    let mut cut = Command::new("cut");
                    cut.arg("-d").arg(" ").arg("-f").arg("1");

                    let sha = pipe_all(&mut [sha256sum, cut])?.ok_or_else(|| {
                        RecoveryError::invalid_output_error("Empty sha output".to_string())
                    })?;

                    let url_string = format!(
                        "http://[{}]:8081/tmp/recovery_registry/{}.tar.gz",
                        aux_ip, IC_REGISTRY_LOCAL_STORE
                    );
                    let url = Url::parse(&url_string).map_err(|e| {
                        RecoveryError::invalid_output_error(format!("Failed to parse Url: {}", e))
                    })?;

                    let registry_params = RegistryParams {
                        registry_store_uri: url,
                        registry_store_hash: sha.trim().to_string(),
                        registry_version: state_params.registry_version,
                    };

                    Ok(Box::new(self.recovery.update_recovery_cup(
                        self.params.subnet_id,
                        recovery_height,
                        state_params.hash,
                        &[],
                        Some(registry_params),
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::WaitForCUP => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UploadStateToChildNNSHost => {
                if let Some(node_ip) = self.params.upload_node {
                    Ok(Box::new(self.recovery.get_upload_and_restart_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
