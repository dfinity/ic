use crate::{
    admin_helper::{
        get_halt_subnet_at_cup_height_command, get_propose_to_complete_canister_migration_command,
        get_propose_to_prepare_canister_migration_command,
        get_propose_to_reroute_canister_ranges_command,
    },
    layout::Layout,
    state_tool_helper::StateToolHelper,
    steps::{
        ComputeExpectedManifestsStep, CopyWorkDirStep, SplitStateStep, StateSplitStrategy,
        ValidateCUPStep, WaitForCUPStep,
    },
    target_subnet::TargetSubnet,
    utils::get_state_hash,
};

use clap::Parser;
use ic_base_types::SubnetId;
use ic_recovery::{
    cli::{consent_given, read_optional, wait_for_confirmation},
    error::{RecoveryError, RecoveryResult},
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::{RegistryPollingStrategy, VersionedRecoveryResult},
    steps::{AdminStep, Step, UploadAndRestartStep},
    NeuronArgs, Recovery, RecoveryArgs, IC_REGISTRY_LOCAL_STORE,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};
use url::Url;

use std::{collections::HashMap, iter::Peekable, net::IpAddr};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    EnumIter,
    EnumString,
    Serialize,
    Deserialize,
    EnumMessage,
    clap::ValueEnum,
)]
pub enum StepType {
    PrepareCanisterMigration,
    HaltSourceSubnetAtCupHeight,
    RerouteCanisterRanges,
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
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Parser, Serialize, Deserialize)]
#[clap(version = "1.0")]
pub struct SubnetSplittingArgs {
    /// Id of the subnet whose state will be split.
    #[clap(long, parse(try_from_str=ic_recovery::util::subnet_id_from_str))]
    pub source_subnet_id: SubnetId,

    /// Id of the destination subnet.
    #[clap(long, parse(try_from_str=ic_recovery::util::subnet_id_from_str))]
    pub destination_subnet_id: SubnetId,

    /// Public ssh key to be deployed to the subnet for read only access.
    #[clap(long)]
    pub pub_key: Option<String>,

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
    #[clap(long, multiple_values(true), required = true)]
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
    interactive: bool,
}

impl SubnetSplitting {
    pub fn new(
        logger: Logger,
        recovery_args: RecoveryArgs,
        neuron_args: Option<NeuronArgs>,
        subnet_args: SubnetSplittingArgs,
        interactive: bool,
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

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_args,
            recovery_args,
            neuron_args,
            layout: Layout::new(&recovery),
            recovery,
            state_tool_helper,
            logger,
            interactive,
        }
    }

    pub fn get_recovery_api(&self) -> &Recovery {
        &self.recovery
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
            state_tool_helper: self.state_tool_helper.clone(),
            layout: self.layout.clone(),
            target_subnet,
            logger: self.recovery.logger.clone(),
        }
    }

    fn unhalt(&self, target_subnet: TargetSubnet) -> impl Step {
        self.recovery.halt_subnet(
            self.subnet_id(target_subnet),
            /*is_halted=*/ false,
            /*keys=*/ &[],
        )
    }

    fn propose_cup(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step> {
        let checkpoints_dir = self.layout.checkpoints_dir(target_subnet);

        let (max_name, max_height) =
            Recovery::get_latest_checkpoint_name_and_height(&checkpoints_dir)?;

        let max_checkpoint_dir = checkpoints_dir.join(max_name);
        let state_hash = get_state_hash(&max_checkpoint_dir)?;

        self.recovery.update_recovery_cup(
            self.subnet_id(target_subnet),
            Recovery::get_recovery_height(max_height),
            state_hash,
            /*replacement_nodes=*/ &[],
            /*registry_params=*/ None,
            /*ecdsa_subnet_id=*/ None,
        )
    }

    fn upload_and_restart_step(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step> {
        match self.upload_node(target_subnet) {
            Some(node_ip) => Ok(UploadAndRestartStep {
                logger: self.recovery.logger.clone(),
                node_ip,
                work_dir: self.layout.work_dir(target_subnet),
                data_src: self.layout.ic_state_dir(target_subnet),
                require_confirmation: self.interactive,
                key_file: self.recovery.key_file.clone(),
                check_ic_replay_height: false,
            }),
            None => Err(RecoveryError::StepSkipped),
        }
    }

    fn wait_for_cup_step(&self, target_subnet: TargetSubnet) -> RecoveryResult<impl Step> {
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
        self.interactive
    }

    fn read_step_params(&mut self, step_type: StepType) {
        match step_type {
            StepType::HaltSourceSubnetAtCupHeight => {
                read_registry(&self.logger, "Canister Migrations", || {
                    self.recovery.registry_helper.get_canister_migrations()
                });

                let url = match self.recovery.registry_helper.latest_registry_version() {
                    Ok(registry_version) => {
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/cB-qtJX4k/subnet-splitting-pre-flight?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}&var-registry_version={}",
                            self.params.destination_subnet_id, registry_version
                        )
                    }
                    Err(err) => {
                        warn!(
                            self.logger,
                            "Failed to get the latest registry version: {}", err
                        );
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/cB-qtJX4k/subnet-splitting-pre-flight?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}",
                            self.params.destination_subnet_id
                        )
                    }
                };

                print_url_and_ask_for_confirmation(
                    &self.logger,
                    url,
                    "Please check the dashboard to see if it is safe to begin subnet splitting",
                );

                if self.params.pub_key.is_none() {
                    self.params.pub_key = read_optional(
                        &self.logger,
                        "Enter public key to add readonly SSH access to subnet: ",
                    )
                }
            }

            StepType::RerouteCanisterRanges => {
                read_registry(&self.logger, "Source Subnet Record", || {
                    self.recovery
                        .registry_helper
                        .get_subnet_record(self.params.source_subnet_id)
                })
            }

            StepType::DownloadStateFromSourceSubnet => {
                let get_ranges = |routing_table: RoutingTable| {
                    HashMap::from([
                        (
                            "source subnet canister ranges",
                            routing_table.ranges(self.params.source_subnet_id),
                        ),
                        (
                            "destination subnet canister ranges",
                            routing_table.ranges(self.params.destination_subnet_id),
                        ),
                    ])
                };

                read_registry(&self.logger, "Routing Table", || {
                    self.recovery.registry_helper.get_routing_table().map(
                        |(registry_version, routing_table)| {
                            (registry_version, routing_table.map(get_ranges))
                        },
                    )
                });

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

            StepType::Cleanup => read_registry(&self.logger, "Canister Migrations", || {
                self.recovery.registry_helper.get_canister_migrations()
            }),

            StepType::UnhaltDestinationSubnet | StepType::CompleteCanisterMigration => {
                let url = match self.recovery.registry_helper.latest_registry_version() {
                    Ok(registry_version) => {
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/K08U69_4k/subnet-splitting?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}&var-registry_version={}",
                            self.params.source_subnet_id, registry_version
                        )
                    }
                    Err(err) => {
                        warn!(
                            self.logger,
                            "Failed to get the latest registry version: {}", err
                        );
                        format!(
                            "https://grafana.mainnet.dfinity.network/d/K08U69_4k/subnet-splitting?var-datasource=IC+Metrics&var-ic=mercury&var-ic_subnet={}",
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

            StepType::HaltSourceSubnetAtCupHeight => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_halt_subnet_at_cup_height_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
                    &self.params.pub_key,
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

            StepType::DownloadStateFromSourceSubnet => {
                let Some(node_ip) = self.params.download_node_source else {
                    return Err(RecoveryError::StepSkipped);
                };

                self.recovery
                    .get_download_state_step(
                        node_ip,
                        self.params.pub_key.is_some(),
                        self.params.keep_downloaded_state == Some(true),
                        /*additional_excludes=*/
                        vec!["orchestrator", "ic_consensus_pool", IC_REGISTRY_LOCAL_STORE],
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

fn read_registry<T: std::fmt::Debug>(
    logger: &Logger,
    label: &str,
    querier: impl Fn() -> VersionedRecoveryResult<T>,
) {
    loop {
        match querier() {
            Ok((registry_version, value)) => info!(
                logger,
                "{} at registry version {}: {:?}", label, registry_version, value,
            ),
            Err(err) => error!(logger, "Failed getting {}, error: {}", label, err),
        }

        if !consent_given(logger, "Read registry again?") {
            break;
        }
    }
}

fn print_url_and_ask_for_confirmation(
    logger: &Logger,
    url: String,
    text_to_display: impl std::fmt::Display,
) {
    match Url::parse(&url) {
        Ok(url) => {
            info!(logger, "{}", text_to_display);
            info!(logger, "{}", url);
            wait_for_confirmation(logger);
        }
        Err(err) => {
            warn!(logger, "Failed to parse url {}: {}", url, err);
        }
    }
}
