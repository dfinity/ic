use crate::{
    admin_helper::RegistryParams,
    cli::{print_height_info, read_optional, read_optional_node_ids, read_optional_version},
    command_helper::pipe_all,
    error::RecoveryError,
    recovery_iterator::RecoveryIterator,
    registry_helper::RegistryPollingStrategy,
    NeuronArgs, Recovery, RecoveryArgs, RecoveryResult, Step, CUPS_DIR, IC_REGISTRY_LOCAL_STORE,
};
use clap::Parser;
use ic_base_types::SubnetId;
use ic_types::{NodeId, ReplicaVersion};
use serde::{Deserialize, Serialize};
use slog::Logger;
use std::{iter::Peekable, net::IpAddr, path::PathBuf, process::Command};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumMessage, EnumString};
use url::Url;

/// Caller id that will be used to mutate the registry canister.
pub const CANISTER_CALLER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";

#[derive(
    Debug, Copy, Clone, EnumIter, EnumString, PartialEq, Deserialize, Serialize, EnumMessage,
)]
pub enum StepType {
    StopReplica,
    DownloadCertifications,
    MergeCertificationPools,
    DownloadState,
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Parser)]
#[clap(version = "1.0")]
pub struct NNSRecoveryFailoverNodesArgs {
    /// Id of the broken subnet
    #[clap(long, parse(try_from_str=crate::util::subnet_id_from_str))]
    pub subnet_id: SubnetId,

    /// Replica version to start the new NNS with (has to be blessed by parent NNS)
    #[clap(long, parse(try_from_str=::std::convert::TryFrom::try_from))]
    pub replica_version: Option<ReplicaVersion>,

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    /// IP address of the auxiliary host the registry is uploaded to
    #[clap(long)]
    pub aux_ip: Option<IpAddr>,

    /// User of the auxiliary host the registry is uploaded to
    #[clap(long)]
    pub aux_user: Option<String>,

    /// Url from where the registry can be downloaded
    #[clap(long)]
    pub registry_url: Option<Url>,

    /// Url of one of the nodes from the original NNS
    #[clap(long)]
    pub validate_nns_url: Url,

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

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,

    /// Which steps to skip
    #[clap(long)]
    pub skip: Option<Vec<StepType>>,
}

pub struct NNSRecoveryFailoverNodes {
    step_iterator: Peekable<StepTypeIter>,
    pub recovery_args: RecoveryArgs,
    pub params: NNSRecoveryFailoverNodesArgs,
    pub neuron_args: Option<NeuronArgs>,
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
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            neuron_args.clone(),
            subnet_args.validate_nns_url.clone(),
            RegistryPollingStrategy::OnlyOnInit,
        )
        .expect("Failed to init recovery");

        let new_registry_local_store = recovery.work_dir.join(IC_REGISTRY_LOCAL_STORE);
        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            neuron_args,
            recovery,
            logger,
            new_registry_local_store,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
    }

    pub fn get_local_store_tar(&self) -> PathBuf {
        self.recovery
            .work_dir
            .join(format!("{}.tar.zst", IC_REGISTRY_LOCAL_STORE))
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for NNSRecoveryFailoverNodes {
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
        match step_type {
            StepType::StopReplica => {
                print_height_info(
                    &self.logger,
                    &self.recovery.registry_helper,
                    self.params.subnet_id,
                );

                if self.params.download_node.is_none() {
                    self.params.download_node = read_optional(&self.logger, "Enter download IP:");
                }
            }

            StepType::ProposeToCreateSubnet => {
                if self.params.replica_version.is_none() {
                    self.params.replica_version = read_optional_version(
                        &self.logger,
                        "New NNS version (current unassigned version or other version blessed by parent NNS): ",
                    );
                }
                if self.params.replacement_nodes.is_none() {
                    self.params.replacement_nodes = read_optional_node_ids(
                        &self.logger,
                        "Enter space separated list of replacement nodes: ",
                    );
                }
            }

            StepType::DownloadParentNNSStore => {
                if self.params.parent_nns_host_ip.is_none() {
                    self.params.parent_nns_host_ip = read_optional(
                        &self.logger,
                        "Enter parent NNS IP to download the registry store from:",
                    );
                }
            }

            StepType::ICReplayWithRegistryContent => {
                if self.params.replay_until_height.is_none() {
                    self.params.replay_until_height =
                        read_optional(&self.logger, "Replay until height: ");
                }
            }

            StepType::UploadAndHostTar => {
                if self.params.aux_user.is_none() {
                    self.params.aux_user = read_optional(&self.logger, "Enter aux user:");
                }
                if self.params.aux_ip.is_none() {
                    self.params.aux_ip = read_optional(&self.logger, "Enter aux IP:");
                }
                if (self.params.aux_user.is_none() || self.params.aux_ip.is_none())
                    && self.params.registry_url.is_none()
                {
                    self.params.registry_url = read_optional(
                        &self.logger,
                        "Enter URL of the hosted registry store tar file:",
                    );
                }
            }

            StepType::WaitForCUP => {
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
            StepType::StopReplica => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_stop_replica_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::DownloadCertifications => Ok(Box::new(
                self.recovery
                    .get_download_certs_step(self.params.subnet_id, true),
            )),

            StepType::MergeCertificationPools => {
                Ok(Box::new(self.recovery.get_merge_certification_pools_step()))
            }

            StepType::DownloadState => {
                if let Some(node_ip) = self.params.download_node {
                    Ok(Box::new(self.recovery.get_download_state_step(
                        node_ip,
                        /*try_readonly=*/ false,
                        /*keep_downloaded_state=*/ false,
                        /*additional_excludes=*/ vec![CUPS_DIR],
                    )))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

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
                    Ok(Box::new(self.recovery.get_download_registry_store_step(
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
                    self.params.replay_until_height,
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

            StepType::CreateRegistryTar => Ok(Box::new(self.recovery.get_create_tars_step())),

            StepType::UploadAndHostTar => {
                let tar = self.get_local_store_tar();
                if let (Some(aux_user), Some(aux_ip)) =
                    (self.params.aux_user.clone(), self.params.aux_ip)
                {
                    Ok(Box::new(
                        self.recovery.get_upload_and_host_tar(aux_user, aux_ip, tar),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::ProposeCUP => {
                let url = if let Some(aux_ip) = self.params.aux_ip {
                    let url_str = format!(
                        "http://[{}]:8081/tmp/recovery_registry/{}.tar.zst",
                        aux_ip, IC_REGISTRY_LOCAL_STORE
                    );
                    Some(Url::parse(&url_str).map_err(|e| {
                        RecoveryError::invalid_output_error(format!("Failed to parse Url: {}", e))
                    })?)
                } else {
                    self.params.registry_url.clone()
                };
                if let Some(url) = url {
                    let state_params = self.recovery.get_replay_output()?;
                    let recovery_height = Recovery::get_recovery_height(state_params.height);

                    let store_tar = self.get_local_store_tar();
                    let mut sha256sum = Command::new("sha256sum");
                    sha256sum.arg(store_tar);

                    let mut cut = Command::new("cut");
                    cut.arg("-d").arg(" ").arg("-f").arg("1");

                    let sha = pipe_all(&mut [sha256sum, cut])?.ok_or_else(|| {
                        RecoveryError::invalid_output_error("Empty sha output".to_string())
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
                        None,
                    )?))
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
