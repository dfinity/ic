use crate::{
    admin_helper::{
        get_propose_to_cool_down_subnet_command, get_propose_to_delete_subnet_command,
        get_propose_to_merge_subnets_command,
    },
    layout::Layout,
    steps::{
        CheckCoolingDownStep, CheckMergeReadinessStep, CheckRegistryVersionOnAllSubnetsStep,
        CheckRoutingTableStep, MergeStatesStep, ValidateCupStep, WaitForHaltingCupStep,
        WaitForRecoveryCupStep,
    },
    target_subnet::TargetSubnet,
    utils::MergedStateParams,
};

use clap::Parser;
use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    CUPS_DIR, NeuronArgs, Recovery, RecoveryArgs,
    cli::{consent_given, read_optional},
    error::{RecoveryError, RecoveryResult},
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::RegistryPollingStrategy,
    ssh_helper::SshHelper,
    steps::{AdminStep, DownloadIcDataStep, Step, UploadStateAndRestartStep},
    util::{CheckpointHeight, DataLocation, ExecutionMode, SshUser},
};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_tools::{
    admin_helper::get_halt_subnet_at_cup_height_command, cli::print_url_and_ask_for_confirmation,
};
use ic_types::Height;
use serde::{Deserialize, Serialize};
use slog::{Logger, info, warn};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};

use std::{
    iter::Peekable,
    net::IpAddr,
    path::PathBuf,
    time::{Duration, UNIX_EPOCH},
};

const SUBNET_TYPE_ALLOW_LIST: [SubnetType; 2] =
    [SubnetType::Application, SubnetType::VerifiedApplication];

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
    clap::ValueEnum,
)]
pub enum StepType {
    CoolDownSourceSubnet,
    CheckRegistryForCoolingDownFlag,
    CheckMergeReadiness,
    HaltSourceSubnetAtCupHeight,
    HaltDestinationSubnetAtCupHeight,
    WaitForHaltingCupOnSourceSubnet,
    WaitForHaltingCupOnDestinationSubnet,
    StopSourceReplica,
    StopDestinationReplica,
    DownloadStateFromSourceSubnet,
    DownloadStateFromDestinationSubnet,
    ValidateSourceSubnetCup,
    ValidateDestinationSubnetCup,
    MergeStates,
    MergeSubnets,
    CheckRegistryForRoutingTableEntry,
    ProposeCupForDestinationSubnet,
    UploadStateToDestinationSubnet,
    WaitForCUPOnDestinationSubnet,
    UnhaltDestinationSubnet,
    CheckRegistryVersionOnAllSubnets,
    DeleteSourceSubnet,
    Cleanup,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct SubnetMergingArgs {
    /// Id of the subnet that is cooling down, whose canisters are merged into
    /// the destination subnet and which is deleted afterwards.
    #[clap(long, value_parser=ic_recovery::util::subnet_id_from_str)]
    pub source_subnet_id: SubnetId,

    /// Id of the subnet that hosts the canisters of the source subnet after the
    /// merge, and that is recovered at the merged state.
    #[clap(long, value_parser=ic_recovery::util::subnet_id_from_str)]
    pub destination_subnet_id: SubnetId,

    /// Public ssh key to be deployed to both subnets for read only access.
    #[clap(long)]
    pub readonly_pub_key: Option<String>,

    /// The path to a file containing the private key associated with `readonly_pub_key`.
    #[clap(long)]
    pub readonly_key_file: Option<PathBuf>,

    /// If the downloaded states should be backed up locally.
    #[clap(long)]
    pub keep_downloaded_state: Option<bool>,

    /// IP address of the node of the source subnet to download the state from.
    #[clap(long)]
    pub download_node_source: Option<IpAddr>,

    /// IP address of the node of the destination subnet to download the state from.
    #[clap(long)]
    pub download_node_destination: Option<IpAddr>,

    /// IP address of the node of the destination subnet to upload the merged state to.
    #[clap(long)]
    pub upload_node_destination: Option<IpAddr>,

    /// How much later than the checkpoints it is assembled from the merged
    /// state starts, in seconds.
    #[clap(long, default_value = "60")]
    pub time_margin_secs: u64,

    /// How long to wait for the subnet that is cooling down to become ready to
    /// be merged, in seconds.
    #[clap(long, default_value = "2400")]
    pub merge_ready_timeout_secs: u64,

    /// How long to wait for a subnet to reach the CUP it halts at, in seconds.
    #[clap(long, default_value = "900")]
    pub halt_timeout_secs: u64,

    /// How long to wait for the registry to reflect a proposal that `ic-admin`
    /// reported as executed, in seconds.
    #[clap(long, default_value = "300")]
    pub registry_timeout_secs: u64,

    /// How long to wait between two evaluations of a condition this tool waits
    /// for, in seconds.
    #[clap(long, default_value = "10")]
    pub poll_interval_secs: u64,

    /// If present the tool will start execution for the provided step, skipping the initial ones.
    #[clap(long = "resume")]
    #[clap(value_enum)]
    pub next_step: Option<StepType>,
}

pub struct SubnetMerging {
    step_iterator: Peekable<StepTypeIter>,
    params: SubnetMergingArgs,
    recovery_args: RecoveryArgs,
    neuron_args: Option<NeuronArgs>,
    recovery: Recovery,
    layout: Layout,
    logger: Logger,
}

impl SubnetMerging {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_merging_args: SubnetMergingArgs,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            neuron_args.clone(),
            recovery_args.nns_url.clone(),
            RegistryPollingStrategy::WithEveryRead,
        )
        .expect("Failed to initialize recovery");

        Self::check_subnets_preconditions(
            &recovery,
            subnet_merging_args.source_subnet_id,
            subnet_merging_args.destination_subnet_id,
        )
        .expect("Subnets should satisfy all the preconditions");

        let layout = Layout::new(&recovery);
        layout
            .create_dirs()
            .expect("Failed to create the working directories");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_merging_args,
            recovery_args,
            neuron_args,
            layout,
            recovery,
            logger,
        }
    }

    /// Checks whether the subnets satisfy the following preconditions:
    ///
    /// Both subnets:
    /// 1) Are `Application` (or `VerifiedApplication`) subnets;
    /// 2) Are not Chain key subnets;
    /// 3) Are not halted: this tool halts them itself, at their next CUP;
    /// 4) Have the same subnet type, as the merged state inherits the
    ///    destination subnet's.
    ///
    /// And they are two different subnets. Unlike subnet splitting, the
    /// destination subnet is a subnet in operation: it keeps serving its own
    /// canisters across the merge, and it may or may not be empty.
    fn check_subnets_preconditions(
        recovery: &Recovery,
        source_subnet_id: SubnetId,
        destination_subnet_id: SubnetId,
    ) -> RecoveryResult<()> {
        if source_subnet_id == destination_subnet_id {
            return Err(RecoveryError::ValidationFailed(format!(
                "A subnet cannot be merged into itself ({source_subnet_id})"
            )));
        }

        let source_subnet_record =
            Self::get_and_pre_validate_subnet_record(recovery, source_subnet_id, None)?;

        let _ = Self::get_and_pre_validate_subnet_record(
            recovery,
            destination_subnet_id,
            Some(source_subnet_record),
        )?;

        Ok(())
    }

    fn get_and_pre_validate_subnet_record(
        recovery: &Recovery,
        subnet_id: SubnetId,
        other_subnet_record: Option<SubnetRecord>,
    ) -> RecoveryResult<SubnetRecord> {
        let validation_error = |error_message| {
            Err(RecoveryError::ValidationFailed(format!(
                "Subnet {subnet_id}: {error_message}"
            )))
        };

        let (_, Some(subnet_record)) = recovery.registry_helper.get_subnet_record(subnet_id)?
        else {
            return validation_error("Subnet Record should not be empty".to_string());
        };

        if subnet_record
            .chain_key_config
            .as_ref()
            .is_some_and(|chain_key_config| !chain_key_config.key_configs.is_empty())
        {
            return validation_error("Subnet should not be a Chain key subnet".to_string());
        }

        let subnet_type = subnet_record
            .subnet_type()
            .try_into()
            .expect("Unexpected subnet type");

        if !SUBNET_TYPE_ALLOW_LIST.contains(&subnet_type) {
            return validation_error(format!(
                "Subnet's type ({subnet_type:?}) is not allowed for subnet merging. Allowlist: {SUBNET_TYPE_ALLOW_LIST:?}",
            ));
        }

        if subnet_record.is_halted {
            return validation_error(String::from(
                "Subnet should not be halted: subnet merging halts both subnets itself, at the \
                 CUP whose state it merges",
            ));
        }

        if let Some(other_subnet_record) = other_subnet_record
            && subnet_record.subnet_type() != other_subnet_record.subnet_type()
        {
            return validation_error(format!(
                "Both subnets should have the same subnet type. \
                 Expected subnet type = {:?}, actual subnet type = {:?}",
                other_subnet_record.subnet_type(),
                subnet_record.subnet_type(),
            ));
        }

        Ok(subnet_record)
    }

    fn wait_for_halting_cup_step(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<impl Step + use<>> {
        let Some(node_ip) = self.download_node(target_subnet) else {
            return Err(RecoveryError::StepSkipped);
        };

        Ok(WaitForHaltingCupStep {
            subnet_id: self.subnet_id(target_subnet),
            node_ip,
            registry_helper: self.recovery.registry_helper.clone(),
            layout: self.layout.clone(),
            ssh_helper: self.ssh_helper(node_ip),
            timeout: Duration::from_secs(self.params.halt_timeout_secs),
            poll_interval: Duration::from_secs(self.params.poll_interval_secs),
            logger: self.recovery.logger.clone(),
        })
    }

    fn stop_replica_step(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step + use<>> {
        // The state manager of a running replica owns its state directory, even
        // while consensus is halted, so the replica has to be stopped before the
        // state is downloaded. The destination subnet's replica stays stopped
        // until the merged state is uploaded to it; the source subnet's stays
        // stopped for good, as that subnet is deleted at the end of the merge.
        match self.download_node(target_subnet) {
            Some(node_ip) => Ok(self.recovery.get_stop_replica_step(node_ip)),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    /// Downloads the state a subnet halted at into that subnet's working
    /// directory.
    ///
    /// `DownloadIcDataStep` rather than `Recovery::get_download_data_step`: a
    /// merge downloads two states, and the latter always downloads into the
    /// single working directory a `Recovery` has.
    fn download_state_step(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<impl Step + use<>> {
        let Some(node_ip) = self.download_node(target_subnet) else {
            return Err(RecoveryError::StepSkipped);
        };

        let mut ssh_helper = self.ssh_helper(node_ip);
        if ssh_helper.wait_for_access().is_err() {
            ssh_helper.ssh_user = SshUser::Admin;
            ssh_helper.key_file = self.recovery.admin_key_file.clone();
            if !ssh_helper.can_connect() {
                return Err(RecoveryError::UnexpectedError(format!(
                    "SSH access to node {node_ip} denied"
                )));
            }
        }
        info!(
            self.recovery.logger,
            "Continuing with account: {}", ssh_helper.ssh_user
        );

        let mut includes = Recovery::get_ic_state_includes(
            &self.recovery.logger,
            ExecutionMode::Remote(&ssh_helper),
            CheckpointHeight::Latest,
        )?;
        // The CUP the subnet halted at, which the validation step checks the
        // downloaded state against.
        includes.push(PathBuf::from(CUPS_DIR));

        Ok(DownloadIcDataStep {
            logger: self.recovery.logger.clone(),
            ssh_helper,
            backup_dir: self.layout.original_data_dir(target_subnet),
            working_dir: self.layout.work_dir(target_subnet),
            keep_downloaded_data: self.params.keep_downloaded_state == Some(true),
            data_includes: includes,
            include_config: true,
        })
    }

    fn validate_cup_step(&self, target_subnet: TargetSubnet) -> impl Step + use<> {
        ValidateCupStep {
            subnet_id: self.subnet_id(target_subnet),
            target_subnet,
            nns_url: self.recovery_args.nns_url.clone(),
            layout: self.layout.clone(),
            logger: self.recovery.logger.clone(),
        }
    }

    /// The recovery CUP of the destination subnet, at the merged state.
    fn propose_cup(&self) -> RecoveryResult<impl Step + use<>> {
        let params = MergedStateParams::read(self.layout.merged_state_params_file())?;

        self.recovery.update_recovery_cup(
            self.params.destination_subnet_id,
            Height::from(params.height),
            params.state_hash,
            /*replacement_nodes=*/ &[],
            /*registry_params=*/ None,
            // The merged subnets are both unavailable while the recovery CUP is
            // created, so its DKG is handled by whichever subnet the NNS picks
            // by default, which is neither of them.
            /*initial_dkg_subnet_id=*/
            None,
            /*chain_key_subnet_id=*/ None,
            Some(UNIX_EPOCH + Duration::from_nanos(params.time_nanos)),
        )
    }

    fn upload_state_and_restart_step(&self) -> RecoveryResult<impl Step + use<>> {
        match self.params.upload_node_destination {
            // The replica of the destination subnet has been stopped before its
            // state was downloaded, so this step replaces its state directory
            // and starts it back up on the merged state.
            Some(node_ip) => Ok(UploadStateAndRestartStep {
                logger: self.recovery.logger.clone(),
                ssh_user: SshUser::Admin,
                upload_method: DataLocation::Remote(node_ip),
                work_dir: self.layout.work_dir(TargetSubnet::Merged),
                data_src: self.layout.ic_state_dir(TargetSubnet::Merged),
                require_confirmation: !self.recovery_args.skip_prompts,
                key_file: self.recovery.admin_key_file.clone(),
                check_ic_replay_height: false,
            }),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    fn wait_for_recovery_cup_step(&self) -> RecoveryResult<impl Step + use<>> {
        match self.params.upload_node_destination {
            Some(node_ip) => Ok(WaitForRecoveryCupStep {
                node_ip,
                layout: self.layout.clone(),
                logger: self.recovery.logger.clone(),
            }),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    fn ssh_helper(&self, node_ip: IpAddr) -> SshHelper {
        let (ssh_user, key_file) = if self.params.readonly_pub_key.is_some() {
            (SshUser::Readonly, self.params.readonly_key_file.clone())
        } else {
            (SshUser::Admin, self.recovery.admin_key_file.clone())
        };

        SshHelper::new(
            self.recovery.logger.clone(),
            ssh_user,
            node_ip,
            self.recovery.ssh_confirmation,
            key_file,
        )
    }

    fn download_node(&self, target_subnet: TargetSubnet) -> Option<IpAddr> {
        match target_subnet {
            TargetSubnet::Source => self.params.download_node_source,
            TargetSubnet::Destination => self.params.download_node_destination,
            TargetSubnet::Merged => None,
        }
    }

    fn subnet_id(&self, target_subnet: TargetSubnet) -> SubnetId {
        match target_subnet {
            TargetSubnet::Source => self.params.source_subnet_id,
            TargetSubnet::Destination | TargetSubnet::Merged => self.params.destination_subnet_id,
        }
    }

    fn dashboard_url(&self, dashboard: &str) -> String {
        match self.recovery.registry_helper.latest_registry_version() {
            Ok(registry_version) => format!(
                "https://grafana.mainnet.dfinity.network/d/{dashboard}?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}&var-registry_version={}",
                self.params.source_subnet_id, registry_version,
            ),
            Err(err) => {
                warn!(
                    self.logger,
                    "Failed to get the latest registry version: {}", err
                );
                format!(
                    "https://grafana.mainnet.dfinity.network/d/{dashboard}?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}",
                    self.params.source_subnet_id,
                )
            }
        }
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for SubnetMerging {
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
            StepType::CoolDownSourceSubnet => {
                if self.params.readonly_pub_key.is_none() {
                    self.params.readonly_pub_key = read_optional(
                        &self.logger,
                        "Enter public key to add readonly SSH access to both subnets. Ensure the right format.\n\
                        Format:   ssh-ed25519 <pubkey> <identity>\n\
                        Example:  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwS/0S6xH0g/xLDV0Tz7VeMZE9AKPeSbLmCsq9bY3F1 foo@dfinity.org\n\
                        Enter your key: ",
                    )
                }
            }

            StepType::CheckMergeReadiness => {
                print_url_and_ask_for_confirmation(
                    &self.logger,
                    self.dashboard_url("subnet-merging"),
                    "The tool evaluates the merge readiness condition itself, and waits until it \
                     holds. Please check the dashboard as well, to see whether it is safe to \
                     merge the subnet",
                );
            }

            StepType::DownloadStateFromSourceSubnet => {
                if self.params.download_node_source.is_none() {
                    self.params.download_node_source = read_optional(
                        &self.logger,
                        "Enter the IP of the node of the Source Subnet to download the state from:",
                    );
                }

                self.params.keep_downloaded_state = Some(consent_given(
                    &self.logger,
                    "Preserve original downloaded state locally?",
                ));
            }

            StepType::DownloadStateFromDestinationSubnet => {
                if self.params.download_node_destination.is_none() {
                    self.params.download_node_destination = read_optional(
                        &self.logger,
                        "Enter the IP of the node of the Destination Subnet to download the state from:",
                    );
                }
            }

            #[allow(clippy::collapsible_match)]
            StepType::UploadStateToDestinationSubnet => {
                if self.params.upload_node_destination.is_none() {
                    self.params.upload_node_destination = read_optional(
                        &self.logger,
                        "Enter IP of node in the Destination Subnet with admin access: ",
                    );
                }
            }

            StepType::DeleteSourceSubnet => {
                print_url_and_ask_for_confirmation(
                    &self.logger,
                    self.dashboard_url("subnet-merging"),
                    "Please check the dashboard to see if it is safe to delete the subnet that \
                     was merged away",
                );
            }

            _ => (),
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        let step: Box<dyn Step> = match step_type {
            StepType::CoolDownSourceSubnet => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_cool_down_subnet_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                    &self.params.readonly_pub_key,
                ),
            }
            .into(),

            StepType::CheckRegistryForCoolingDownFlag => CheckCoolingDownStep {
                source_subnet_id: self.params.source_subnet_id,
                registry_helper: self.recovery.registry_helper.clone(),
                layout: self.layout.clone(),
                timeout: Duration::from_secs(self.params.registry_timeout_secs),
                poll_interval: Duration::from_secs(self.params.poll_interval_secs),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::CheckMergeReadiness => CheckMergeReadinessStep {
                source_subnet_id: self.params.source_subnet_id,
                registry_helper: self.recovery.registry_helper.clone(),
                layout: self.layout.clone(),
                timeout: Duration::from_secs(self.params.merge_ready_timeout_secs),
                poll_interval: Duration::from_secs(self.params.poll_interval_secs),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::HaltSourceSubnetAtCupHeight => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_halt_subnet_at_cup_height_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                    &self.params.readonly_pub_key,
                ),
            }
            .into(),

            StepType::HaltDestinationSubnetAtCupHeight => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_halt_subnet_at_cup_height_command(
                    &self.recovery.admin_helper,
                    self.params.destination_subnet_id,
                    &self.params.readonly_pub_key,
                ),
            }
            .into(),

            StepType::WaitForHaltingCupOnSourceSubnet => {
                self.wait_for_halting_cup_step(TargetSubnet::Source)?.into()
            }
            StepType::WaitForHaltingCupOnDestinationSubnet => self
                .wait_for_halting_cup_step(TargetSubnet::Destination)?
                .into(),

            StepType::StopSourceReplica => self.stop_replica_step(TargetSubnet::Source)?.into(),
            StepType::StopDestinationReplica => {
                self.stop_replica_step(TargetSubnet::Destination)?.into()
            }

            StepType::DownloadStateFromSourceSubnet => {
                self.download_state_step(TargetSubnet::Source)?.into()
            }
            StepType::DownloadStateFromDestinationSubnet => {
                self.download_state_step(TargetSubnet::Destination)?.into()
            }

            StepType::ValidateSourceSubnetCup => {
                self.validate_cup_step(TargetSubnet::Source).into()
            }
            StepType::ValidateDestinationSubnetCup => {
                self.validate_cup_step(TargetSubnet::Destination).into()
            }

            StepType::MergeStates => MergeStatesStep {
                layout: self.layout.clone(),
                time_margin: Duration::from_secs(self.params.time_margin_secs),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::MergeSubnets => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_merge_subnets_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                    self.params.destination_subnet_id,
                ),
            }
            .into(),

            StepType::CheckRegistryForRoutingTableEntry => CheckRoutingTableStep {
                source_subnet_id: self.params.source_subnet_id,
                destination_subnet_id: self.params.destination_subnet_id,
                registry_helper: self.recovery.registry_helper.clone(),
                layout: self.layout.clone(),
                timeout: Duration::from_secs(self.params.registry_timeout_secs),
                poll_interval: Duration::from_secs(self.params.poll_interval_secs),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::ProposeCupForDestinationSubnet => self.propose_cup()?.into(),
            StepType::UploadStateToDestinationSubnet => {
                self.upload_state_and_restart_step()?.into()
            }
            StepType::WaitForCUPOnDestinationSubnet => self.wait_for_recovery_cup_step()?.into(),

            StepType::UnhaltDestinationSubnet => self
                .recovery
                .bring_subnet_back_online_after_repairs(self.params.destination_subnet_id)
                .into(),

            StepType::CheckRegistryVersionOnAllSubnets => CheckRegistryVersionOnAllSubnetsStep {
                source_subnet_id: self.params.source_subnet_id,
                registry_helper: self.recovery.registry_helper.clone(),
                layout: self.layout.clone(),
                timeout: Duration::from_secs(self.params.merge_ready_timeout_secs),
                poll_interval: Duration::from_secs(self.params.poll_interval_secs),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::DeleteSourceSubnet => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_delete_subnet_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                ),
            }
            .into(),

            StepType::Cleanup => self.recovery.get_cleanup_step().into(),
        };

        Ok(step)
    }
}

impl Iterator for SubnetMerging {
    type Item = (StepType, Box<dyn Step>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_step()
    }
}

impl HasRecoveryState for SubnetMerging {
    type StepType = StepType;
    type SubcommandArgsType = SubnetMergingArgs;

    fn get_next_step(&self) -> Option<Self::StepType> {
        self.params.next_step
    }

    fn get_state(&self) -> RecoveryResult<RecoveryState<Self::SubcommandArgsType>> {
        Ok(RecoveryState {
            recovery_args: self.recovery_args.clone(),
            neuron_args: self.neuron_args.clone(),
            subcommand_args: self.params.clone(),
        })
    }
}
