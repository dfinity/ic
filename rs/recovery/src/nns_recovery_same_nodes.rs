use crate::{
    cli::{print_height_info, read_optional, read_optional_data_location, read_optional_version},
    error::{GracefulExpect, RecoveryError},
    file_sync_helper::create_dir,
    recovery_iterator::RecoveryIterator,
    registry_helper::RegistryPollingStrategy,
    util::{DataLocation, SshUser},
    RecoveryArgs, RecoveryResult, CUPS_DIR,
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
    Copy, Clone, PartialEq, Debug, Deserialize, EnumIter, EnumMessage, EnumString, Serialize,
)]
pub enum StepType {
    StopReplica,
    DownloadCertifications,
    MergeCertificationPools,
    DownloadState,
    ICReplay,
    ValidateReplayOutput,
    UpdateRegistryLocalStore,
    CreateRegistryTar,
    CopyIcState,
    GetRecoveryCUP,
    UploadCUPAndRegistry,
    WaitForCUP,
    UploadState,
    CreateArtifacts,
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

    #[clap(long)]
    /// The replay will stop at this height and make a checkpoint.
    pub replay_until_height: Option<u64>,

    /// URL of the upgrade image
    #[clap(long)]
    pub upgrade_image_url: Option<Url>,

    /// SHA256 hash of the upgrade image
    #[clap(long)]
    pub upgrade_image_hash: Option<String>,

    /// IP address of the node to download the subnet state from. Should be different to node used in nns-url.
    #[clap(long)]
    pub download_node: Option<IpAddr>,

    /// The method of uploading state. Possible values are either `local` (for a
    /// local recovery on the admin node) or the ipv6 address of the target node.
    /// Local recoveries allow us to skip a potentially expensive data transfer.
    #[clap(long, value_parser=crate::util::data_location_from_str)]
    pub upload_method: Option<DataLocation>,

    /// The path to a file containing the private key that has backup access to all nodes in the subnet.
    #[clap(long)]
    pub backup_key_file: Option<PathBuf>,

    /// The output directory where the recovery artifacts (and its hash) will be stored.
    #[clap(long)]
    pub output_dir: Option<PathBuf>,

    /// If present the tool will start execution for the provided step, skipping the initial ones
    #[clap(long = "resume")]
    pub next_step: Option<StepType>,
}

pub struct NNSRecoverySameNodes {
    step_iterator: Peekable<StepTypeIter>,
    pub params: NNSRecoverySameNodesArgs,
    pub recovery_args: RecoveryArgs,
    pub recovery: Recovery,
    logger: Logger,
    new_state_dir: PathBuf,
}

impl NNSRecoverySameNodes {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        subnet_args: NNSRecoverySameNodesArgs,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            /*neuron_args=*/ None,
            recovery_args.nns_url.clone(),
            RegistryPollingStrategy::OnlyOnInit,
        )
        .expect_graceful("Failed to init recovery");

        let new_state_dir = recovery.work_dir.join("new_ic_state");
        create_dir(&new_state_dir).expect_graceful("Failed to create state directory for upload.");
        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            recovery,
            logger,
            new_state_dir,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
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

            StepType::ICReplay => {
                if self.params.upgrade_version.is_none() {
                    self.params.upgrade_version =
                        read_optional_version(&self.logger, "Upgrade version: ");
                };
                if self.params.replay_until_height.is_none() {
                    self.params.replay_until_height =
                        read_optional(&self.logger, "Replay until height: ");
                }
            }

            StepType::UploadCUPAndRegistry => {
                if self.params.upload_method.is_none() {
                    self.params.upload_method = read_optional_data_location(
                        &self.logger,
                        "Are you performing a local recovery directly on the node, or a remote recovery? [local/<ipv6>]",
                    );
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

            StepType::CopyIcState => Ok(Box::new(
                self.recovery.get_copy_ic_state(self.new_state_dir.clone()),
            )),

            StepType::GetRecoveryCUP => Ok(Box::new(
                self.recovery
                    .get_recovery_cup_step(self.params.subnet_id, !self.interactive())?,
            )),

            StepType::UploadCUPAndRegistry => {
                if let Some(method) = self.params.upload_method {
                    let node_ip = match method {
                        DataLocation::Remote(ip) => ip,
                        DataLocation::Local => IpAddr::V6(Ipv6Addr::LOCALHOST),
                    };
                    Ok(Box::new(self.recovery.get_upload_cup_and_tar_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::WaitForCUP => {
                if let Some(method) = self.params.upload_method {
                    let node_ip = match method {
                        DataLocation::Remote(ip) => ip,
                        DataLocation::Local => IpAddr::V6(Ipv6Addr::LOCALHOST),
                    };
                    Ok(Box::new(self.recovery.get_wait_for_cup_step(node_ip)))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::UploadState => {
                if let Some(method) = self.params.upload_method {
                    Ok(Box::new(
                        self.recovery.get_upload_and_restart_step_with_data_src(
                            method,
                            self.new_state_dir.clone(),
                        ),
                    ))
                } else {
                    Err(RecoveryError::StepSkipped)
                }
            }

            StepType::CreateArtifacts => Ok(Box::new(
                self.recovery
                    .get_create_nns_recovery_tar_step(self.params.output_dir.clone()),
            )),

            StepType::Cleanup => Ok(Box::new(self.recovery.get_cleanup_step())),
        }
    }
}
