use crate::{
    admin_helper::{
        get_halt_subnet_at_cup_height_command, get_propose_to_complete_canister_migration_command,
        get_propose_to_prepare_canister_migration_command,
        get_propose_to_reroute_canister_ranges_command,
    },
    layout::Layout,
    state_tool_helper::StateToolHelper,
    steps::{
        ComputeExpectedManifestsStep, CopyWorkDirStep, ReadRegistryStep, SplitStateStep,
        StateSplitStrategy, ValidateCUPStep, WaitForCUPStep,
    },
    target_subnet::TargetSubnet,
    utils::get_state_hash,
};

use clap::Parser;
use ic_base_types::SubnetId;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    IC_CONSENSUS_POOL_PATH, IC_REGISTRY_LOCAL_STORE, NeuronArgs, Recovery, RecoveryArgs,
    cli::{consent_given, read_optional, wait_for_confirmation},
    error::{RecoveryError, RecoveryResult},
    get_node_heights_from_metrics,
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::RegistryPollingStrategy,
    steps::{AdminStep, Step, UploadAndRestartStep},
    util::{DataLocation, SshUser},
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use serde::{Deserialize, Serialize};
use slog::{Logger, error, warn};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};
use url::Url;

use std::{collections::HashMap, iter::Peekable, net::IpAddr, path::PathBuf};

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
    PrepareCanisterMigration,
    CheckRegistryForCanisterMigrationsEntry,
    HaltSourceSubnetAtCupHeight,
    RerouteCanisterRanges,
    CheckRegistryForRoutingTableEntry,
    DownloadStateFromSourceSubnet,
    ValidateSourceSubnetCup,
    ComputeExpectedManifestsStep,
    CopyDir,
    SplitOutSourceState,
    SplitOutDestinationState,
    ProposeCupForSourceSubnet,
    UploadStateToSourceSubnet,
    ProposeCupForDestinationSubnet,
    UploadStateToDestinationSubnet,
    WaitForCUPOnSourceSubnet,
    WaitForCUPOnDestinationSubnet,
    UnhaltSourceSubnet,
    UnhaltDestinationSubnet,
    CompleteCanisterMigration,
    CheckRegistryForCanisterMigrationsEntryAgain,
    Cleanup,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Parser, Serialize)]
#[clap(version = "1.0")]
pub struct SubnetSplittingArgs {
    /// Id of the subnet whose state will be split.
    #[clap(long, value_parser=ic_recovery::util::subnet_id_from_str)]
    pub source_subnet_id: SubnetId,

    /// Id of the destination subnet.
    #[clap(long, value_parser=ic_recovery::util::subnet_id_from_str)]
    pub destination_subnet_id: SubnetId,

    /// Public ssh key to be deployed to the subnet for read only access.
    #[clap(long)]
    pub readonly_pub_key: Option<String>,

    /// The path to a file containing the private key associated with `readonly_pub_key`.
    #[clap(long)]
    pub readonly_key_file: Option<PathBuf>,

    /// If the downloaded state should be backed up locally.
    #[clap(long)]
    pub keep_downloaded_state: Option<bool>,

    /// IP address of the node from the source subnet to download the state from.
    #[clap(long)]
    pub download_node_source: Option<IpAddr>,

    /// IP address of the node to upload the new subnet state to.
    #[clap(long)]
    pub upload_node_source: Option<IpAddr>,

    /// IP address of the node to upload the new subnet state to.
    #[clap(long)]
    pub upload_node_destination: Option<IpAddr>,

    /// If present the tool will start execution for the provided step, skipping the initial ones.
    #[clap(long = "resume")]
    #[clap(value_enum)]
    pub next_step: Option<StepType>,

    /// The canister ID ranges to be moved to the destination subnet.
    #[clap(long, num_args(1..), required = true)]
    pub canister_id_ranges_to_move: Vec<CanisterIdRange>,
}

pub struct SubnetSplitting {
    step_iterator: Peekable<StepTypeIter>,
    params: SubnetSplittingArgs,
    recovery_args: RecoveryArgs,
    neuron_args: Option<NeuronArgs>,
    recovery: Recovery,
    state_tool_helper: StateToolHelper,
    layout: Layout,
    logger: Logger,
    subnet_type: SubnetType,
}

impl SubnetSplitting {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_splitting_args: SubnetSplittingArgs,
    ) -> Self {
        let recovery = Recovery::new(
            logger.clone(),
            recovery_args.clone(),
            neuron_args.clone(),
            recovery_args.nns_url.clone(),
            RegistryPollingStrategy::WithEveryRead,
        )
        .expect("Failed to initialize recovery");

        let state_tool_helper = StateToolHelper::new(
            recovery.binary_dir.clone(),
            recovery_args.replica_version.clone(),
            logger.clone(),
        )
        .expect("Failed to initialize state tool helper");

        let subnet_type = Self::check_subnets_preconditions(
            &recovery,
            subnet_splitting_args.source_subnet_id,
            subnet_splitting_args.destination_subnet_id,
        )
        .expect("Subnets should satisfy all the preconditions");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_splitting_args,
            recovery_args,
            neuron_args,
            layout: Layout::new(&recovery),
            recovery,
            state_tool_helper,
            logger,
            subnet_type,
        }
    }

    /// Checks whether the subnets satisfy the following preconditions:
    ///
    /// Source Subnet:
    /// 1) Is an `Application` subnet
    /// 2) Is not a Chain key subnet
    ///
    /// Destination Subnet:
    /// 1) Is an `Application` subnet
    /// 2) Is not a Chain key subnet
    /// 3) Is halted
    /// 4) Hasn't produced any block yet
    /// 5) Has the same size as the Source Subnet
    fn check_subnets_preconditions(
        recovery: &Recovery,
        source_subnet_id: SubnetId,
        destination_subnet_id: SubnetId,
    ) -> RecoveryResult<SubnetType> {
        let source_subnet_record = Self::get_and_pre_validate_subnet_record(
            recovery,
            source_subnet_id,
            /*other_subnet_record=*/ None,
            /*check_whether_halted=*/ false,
            /*check_height=*/ false,
        )?;

        let subnet_type = source_subnet_record
            .subnet_type()
            .try_into()
            .expect("Unexpected subnet type");

        let _ = Self::get_and_pre_validate_subnet_record(
            recovery,
            destination_subnet_id,
            Some(source_subnet_record),
            /*check_whether_halted=*/ true,
            /*check_height=*/ true,
        )?;

        Ok(subnet_type)
    }

    fn get_and_pre_validate_subnet_record(
        recovery: &Recovery,
        subnet_id: SubnetId,
        other_subnet_record: Option<SubnetRecord>,
        check_whether_halted: bool,
        check_height: bool,
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
                "Subnet's type ({subnet_type:?}) is not allowed for subnet splitting. Allowlist: {SUBNET_TYPE_ALLOW_LIST:?}",
            ));
        }

        if let Some(other_subnet_record) = other_subnet_record {
            if subnet_record.subnet_type() != other_subnet_record.subnet_type() {
                return validation_error(format!(
                    "Both subnets should have the same subnet type. \
                     Expected subnet type = {:?}, actual subnet type = {:?}",
                    other_subnet_record.subnet_type(),
                    subnet_record.subnet_type(),
                ));
            }

            if subnet_record.membership.len() != other_subnet_record.membership.len() {
                return validation_error(format!(
                    "Both subnets should have the same size. \
                    Expected subnet size = {}, actual subnet size = {}",
                    other_subnet_record.membership.len(),
                    subnet_record.membership.len()
                ));
            }
        }

        if check_whether_halted && !subnet_record.is_halted {
            return validation_error(String::from("Subnet should be halted"));
        }

        if check_height
            && get_node_heights_from_metrics(
                &recovery.logger,
                &recovery.registry_helper,
                subnet_id,
            )?
            .iter()
            .any(|metrics| metrics.finalization_height > Height::new(0))
        {
            return validation_error(String::from("Subnet has a non-zero height"));
        }

        Ok(subnet_record)
    }

    fn split_state_step(&self, target_subnet: TargetSubnet) -> SplitStateStep {
        let state_split_strategy = match target_subnet {
            TargetSubnet::Source => {
                StateSplitStrategy::Drop(self.params.canister_id_ranges_to_move.clone())
            }
            TargetSubnet::Destination => {
                StateSplitStrategy::Retain(self.params.canister_id_ranges_to_move.clone())
            }
        };

        SplitStateStep {
            subnet_id: self.subnet_id(target_subnet),
            state_split_strategy,
            layout: self.layout.clone(),
            target_subnet,
            logger: self.recovery.logger.clone(),
        }
    }

    fn unhalt(&self, target_subnet: TargetSubnet) -> impl Step + use<> {
        self.recovery.halt_subnet(
            self.subnet_id(target_subnet),
            /*is_halted=*/ false,
            /*keys=*/ &[],
        )
    }

    fn propose_cup(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step + use<>> {
        let checkpoints_dir = self.layout.checkpoints_dir(target_subnet);

        let (max_name, max_height) =
            Recovery::get_latest_checkpoint_name_and_height(&checkpoints_dir)?;

        let max_checkpoint_dir = checkpoints_dir.join(max_name);
        let state_hash = get_state_hash(max_checkpoint_dir)?;

        self.recovery.update_recovery_cup(
            self.subnet_id(target_subnet),
            Recovery::get_recovery_height(max_height),
            state_hash,
            /*replacement_nodes=*/ &[],
            /*registry_params=*/ None,
            /*chain_key_subnet_id=*/ None,
        )
    }

    fn upload_and_restart_step(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<impl Step + use<>> {
        match self.upload_node(target_subnet) {
            Some(node_ip) => Ok(UploadAndRestartStep {
                logger: self.recovery.logger.clone(),
                upload_method: DataLocation::Remote(node_ip),
                work_dir: self.layout.work_dir(target_subnet),
                data_src: self.layout.ic_state_dir(target_subnet),
                require_confirmation: !self.recovery_args.skip_prompts,
                key_file: self.recovery.admin_key_file.clone(),
                check_ic_replay_height: false,
            }),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    fn wait_for_cup_step(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step + use<>> {
        match self.upload_node(target_subnet) {
            Some(node_ip) => Ok(WaitForCUPStep {
                logger: self.recovery.logger.clone(),
                layout: self.layout.clone(),
                node_ip,
                target_subnet,
            }),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    fn upload_node(&self, target_subnet: TargetSubnet) -> Option<IpAddr> {
        match target_subnet {
            TargetSubnet::Source => self.params.upload_node_source,
            TargetSubnet::Destination => self.params.upload_node_destination,
        }
    }

    fn subnet_id(&self, target_subnet: TargetSubnet) -> SubnetId {
        match target_subnet {
            TargetSubnet::Source => self.params.source_subnet_id,
            TargetSubnet::Destination => self.params.destination_subnet_id,
        }
    }
}

impl RecoveryIterator<StepType, StepTypeIter> for SubnetSplitting {
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
            StepType::HaltSourceSubnetAtCupHeight => {
                let url = match self.recovery.registry_helper.latest_registry_version() {
                    Ok(registry_version) => {
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/subnet-splitting-preflight?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}&var-registry_version={}",
                            self.params.destination_subnet_id, registry_version
                        )
                    }
                    Err(err) => {
                        warn!(
                            self.logger,
                            "Failed to get the latest registry version: {}", err
                        );
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/subnet-splitting-preflight?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}",
                            self.params.destination_subnet_id
                        )
                    }
                };

                print_url_and_ask_for_confirmation(
                    &self.logger,
                    url,
                    "Please check the dashboard to see if it is safe to begin subnet splitting",
                );

                if self.params.readonly_pub_key.is_none() {
                    self.params.readonly_pub_key = read_optional(
                        &self.logger,
                        "Enter public key to add readonly SSH access to subnet. Ensure the right format.\n\
                        Format:   ssh-ed25519 <pubkey> <identity>\n\
                        Example:  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwS/0S6xH0g/xLDV0Tz7VeMZE9AKPeSbLmCsq9bY3F1 foo@dfinity.org\n\
                        Enter your key: ",
                    )
                }
            }

            StepType::DownloadStateFromSourceSubnet => {
                if self.params.download_node_source.is_none() {
                    self.params.download_node_source =
                        read_optional(&self.logger, "Enter download IP on the Source Subnet:");
                }

                self.params.keep_downloaded_state = Some(consent_given(
                    &self.logger,
                    "Preserve original downloaded state locally?",
                ));
            }

            StepType::UploadStateToSourceSubnet => {
                if self.params.upload_node_source.is_none() {
                    self.params.upload_node_source = read_optional(
                        &self.logger,
                        "Enter IP of node in the Source Subnet with admin access: ",
                    );
                }
            }

            StepType::UploadStateToDestinationSubnet => {
                if self.params.upload_node_destination.is_none() {
                    self.params.upload_node_destination = read_optional(
                        &self.logger,
                        "Enter IP of node in the Destination Subnet with admin access: ",
                    );
                }
            }

            StepType::UnhaltDestinationSubnet | StepType::CompleteCanisterMigration => {
                let url = match self.recovery.registry_helper.latest_registry_version() {
                    Ok(registry_version) => {
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/subnet-splitting?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}&var-registry_version={}",
                            self.params.source_subnet_id, registry_version
                        )
                    }
                    Err(err) => {
                        warn!(
                            self.logger,
                            "Failed to get the latest registry version: {}", err
                        );
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/subnet-splitting?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}",
                            self.params.source_subnet_id,
                        )
                    }
                };

                print_url_and_ask_for_confirmation(
                    &self.logger,
                    url,
                    "Please check the dashboard to see if it is safe to unhalt the \
                    destination subnet and/or remove the canister migrations entry",
                );
            }

            _ => (),
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        let step: Box<dyn Step> = match step_type {
            StepType::PrepareCanisterMigration => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_prepare_canister_migration_command(
                    &self.recovery.admin_helper,
                    &self.params.canister_id_ranges_to_move,
                    self.params.source_subnet_id,
                    self.params.destination_subnet_id,
                ),
            }
            .into(),

            StepType::CheckRegistryForCanisterMigrationsEntry
            | StepType::CheckRegistryForCanisterMigrationsEntryAgain => {
                let registry_helper = self.recovery.registry_helper.clone();

                ReadRegistryStep {
                    logger: self.recovery.logger.clone(),
                    label: "Canister Migrations".to_string(),
                    querier: move || registry_helper.get_canister_migrations(),
                    interactive: !self.recovery_args.skip_prompts,
                }
                .into()
            }

            StepType::HaltSourceSubnetAtCupHeight => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_halt_subnet_at_cup_height_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                    &self.params.readonly_pub_key,
                ),
            }
            .into(),

            StepType::RerouteCanisterRanges => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_reroute_canister_ranges_command(
                    &self.recovery.admin_helper,
                    &self.params.canister_id_ranges_to_move,
                    self.params.source_subnet_id,
                    self.params.destination_subnet_id,
                ),
            }
            .into(),

            StepType::CheckRegistryForRoutingTableEntry => {
                let registry_helper = self.recovery.registry_helper.clone();
                let source_subnet = self.params.source_subnet_id;
                let destination_subnet = self.params.destination_subnet_id;

                let get_ranges = move |routing_table: RoutingTable| {
                    HashMap::from([
                        (source_subnet, routing_table.ranges(source_subnet)),
                        (destination_subnet, routing_table.ranges(destination_subnet)),
                    ])
                };

                ReadRegistryStep {
                    logger: self.recovery.logger.clone(),
                    label: "Routing Table".to_string(),
                    querier: move || {
                        registry_helper.get_routing_table().map(
                            |(registry_version, routing_table)| {
                                (registry_version, routing_table.map(get_ranges))
                            },
                        )
                    },
                    interactive: !self.recovery_args.skip_prompts,
                }
                .into()
            }

            StepType::DownloadStateFromSourceSubnet => {
                let Some(node_ip) = self.params.download_node_source else {
                    return Err(RecoveryError::StepSkipped);
                };

                let (ssh_user, key_file) = if self.params.readonly_pub_key.is_some() {
                    (SshUser::Readonly, self.params.readonly_key_file.clone())
                } else {
                    (SshUser::Admin, self.recovery.admin_key_file.clone())
                };

                self.recovery
                    .get_download_state_step(
                        node_ip,
                        ssh_user,
                        key_file,
                        self.params.keep_downloaded_state == Some(true),
                        /*additional_excludes=*/
                        vec![
                            "orchestrator",
                            IC_CONSENSUS_POOL_PATH,
                            IC_REGISTRY_LOCAL_STORE,
                        ],
                    )
                    .into()
            }
            StepType::CopyDir => CopyWorkDirStep {
                layout: self.layout.clone(),
                logger: self.recovery.logger.clone(),
            }
            .into(),

            StepType::SplitOutSourceState => self.split_state_step(TargetSubnet::Source).into(),
            StepType::SplitOutDestinationState => {
                self.split_state_step(TargetSubnet::Destination).into()
            }

            StepType::ProposeCupForSourceSubnet => self.propose_cup(TargetSubnet::Source)?.into(),
            StepType::UploadStateToSourceSubnet => {
                self.upload_and_restart_step(TargetSubnet::Source)?.into()
            }
            StepType::ProposeCupForDestinationSubnet => {
                self.propose_cup(TargetSubnet::Destination)?.into()
            }
            StepType::UploadStateToDestinationSubnet => self
                .upload_and_restart_step(TargetSubnet::Destination)?
                .into(),
            StepType::WaitForCUPOnSourceSubnet => {
                self.wait_for_cup_step(TargetSubnet::Source)?.into()
            }
            StepType::WaitForCUPOnDestinationSubnet => {
                self.wait_for_cup_step(TargetSubnet::Destination)?.into()
            }
            StepType::UnhaltSourceSubnet => self.unhalt(TargetSubnet::Source).into(),
            StepType::UnhaltDestinationSubnet => self.unhalt(TargetSubnet::Destination).into(),

            StepType::CompleteCanisterMigration => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_complete_canister_migration_command(
                    &self.recovery.admin_helper,
                    &self.params.canister_id_ranges_to_move,
                    self.params.source_subnet_id,
                    self.params.destination_subnet_id,
                ),
            }
            .into(),

            StepType::Cleanup => self.recovery.get_cleanup_step().into(),
            StepType::ComputeExpectedManifestsStep => ComputeExpectedManifestsStep {
                layout: self.layout.clone(),
                state_tool_helper: self.state_tool_helper.clone(),
                source_subnet_id: self.params.source_subnet_id,
                destination_subnet_id: self.params.destination_subnet_id,
                canister_id_ranges_to_move: self.params.canister_id_ranges_to_move.clone(),
                subnet_type: self.subnet_type,
            }
            .into(),
            StepType::ValidateSourceSubnetCup => ValidateCUPStep {
                subnet_id: self.params.source_subnet_id,
                nns_url: self.recovery_args.nns_url.clone(),
                layout: self.layout.clone(),
                logger: self.logger.clone(),
            }
            .into(),
        };

        Ok(step)
    }
}

impl Iterator for SubnetSplitting {
    type Item = (StepType, Box<dyn Step>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_step()
    }
}

impl HasRecoveryState for SubnetSplitting {
    type StepType = StepType;
    type SubcommandArgsType = SubnetSplittingArgs;

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

fn print_url_and_ask_for_confirmation(
    logger: &Logger,
    url: String,
    text_to_display: impl std::fmt::Display,
) {
    match Url::parse(&url) {
        Ok(url) => {
            warn!(logger, "{}", text_to_display);
            warn!(logger, "{}", url);
            wait_for_confirmation(logger);
        }
        Err(err) => {
            error!(logger, "Failed to parse url {}: {}", url, err);
        }
    }
}
