use crate::{
    admin_helper::get_propose_to_cool_down_subnet_command,
    download_node::DownloadNode,
    layout::Layout,
    steps::{
        CheckCoolingDownStep, CheckMergeReadinessStep, DownloadStateStep,
        StopReplicaAtHaltingCheckpointStep, ValidateCupStep, WaitForHaltingCupStep,
    },
};

use clap::Parser;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    NeuronArgs, Recovery, RecoveryArgs,
    cli::read_data_location,
    error::{RecoveryError, RecoveryResult},
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::RegistryPollingStrategy,
    steps::{AdminStep, Step},
    util::DataLocation,
};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_tools::{
    admin_helper::get_halt_subnet_at_cup_height_command, utils::print_url_and_ask_for_confirmation,
};
use serde::{Deserialize, Serialize};
use slog::{Logger, warn};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};

use std::{collections::BTreeSet, fmt::Debug, iter::Peekable, time::Duration};

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
    /// Submit a proposal to label the source subnet as "cooling down".
    CoolDownSourceSubnet,
    /// Wait until the registry labels the source subnet as "cooling down", and
    /// record the registry version at which the label was read.
    CheckRegistryForCoolingDownFlag,
    /// Wait until the source subnet is ready to be merged.
    CheckMergeReadiness,
    /// Submit a proposal to halt the source subnet at its next CUP.
    HaltSourceSubnetAtCupHeight,
    /// Submit a proposal to halt the destination subnet at its next CUP.
    HaltDestinationSubnetAtCupHeight,
    /// Wait until the node of the source subnet the state is downloaded from
    /// serves the CUP the subnet halts at.
    WaitForHaltingCupOnSourceSubnet,
    /// Wait until the node of the destination subnet the state is downloaded
    /// from serves the CUP the subnet halts at.
    WaitForHaltingCupOnDestinationSubnet,
    /// Wait until the node of the source subnet the state is downloaded from
    /// holds a finished checkpoint at the height of the CUP the subnet halts
    /// at, then stop its replica.
    StopSourceReplica,
    /// Wait until the node of the destination subnet the state is downloaded
    /// from holds a finished checkpoint at the height of the CUP the subnet
    /// halts at, then stop its replica.
    StopDestinationReplica,
    /// Download the checkpoint at the height of the CUP the source subnet
    /// halted at.
    DownloadStateFromSourceSubnet,
    /// Download the checkpoint at the height of the CUP the destination subnet
    /// halted at.
    DownloadStateFromDestinationSubnet,
    /// Validate the state downloaded from the source subnet against the CUP it
    /// halted at.
    ValidateSourceSubnetCup,
    /// Validate the state downloaded from the destination subnet against the
    /// CUP it halted at.
    ValidateDestinationSubnetCup,
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

    /// The node of the source subnet to download the state from: its IP
    /// address, or "local" if the tool runs on that node. Required by
    /// `WaitForHaltingCupOnSourceSubnet`; asked for if missing, unless prompts
    /// are skipped. Unless the tool runs on that node, the steps that stop its
    /// replica and download its state access it over SSH with the admin key.
    #[clap(long, value_parser=ic_recovery::util::data_location_from_str)]
    pub download_node_source: Option<DataLocation>,

    /// The node of the destination subnet to download the state from: its IP
    /// address, or "local" if the tool runs on that node. Required by
    /// `WaitForHaltingCupOnDestinationSubnet`; asked for if missing, unless
    /// prompts are skipped. Unless the tool runs on that node, the steps that
    /// stop its replica and download its state access it over SSH with the
    /// admin key.
    #[clap(long, value_parser=ic_recovery::util::data_location_from_str)]
    pub download_node_destination: Option<DataLocation>,

    /// How long to wait for the subnet that is cooling down to become ready to
    /// be merged, in seconds.
    #[clap(long, default_value = "2400")]
    pub merge_ready_timeout_secs: u64,

    /// How long to wait, in seconds, for a subnet to reach the CUP it halts at.
    /// The step waiting for it is meant to be run once the proposal halting the
    /// subnet has been executed. The subnet halts at the first CUP whose
    /// registry version has the subnet scheduled to halt. As a DKG summary
    /// takes its registry version from the previous summary, that CUP can be up
    /// to two DKG intervals away. Also how long to wait for the node a state is
    /// downloaded from to finish the checkpoint at the height of that CUP.
    #[clap(long, default_value = "1800")]
    pub halt_timeout_secs: u64,

    /// How long to wait, in seconds, for the proposal labeling the source
    /// subnet as "cooling down" to be adopted, executed and visible in the
    /// registry.
    #[clap(long, default_value = "3600")]
    pub registry_timeout_secs: u64,

    /// How long to wait, in seconds, between two attempts of a step that waits.
    /// Must be positive.
    #[clap(long, default_value = "10", value_parser = clap::value_parser!(u64).range(1..))]
    pub poll_interval_secs: u64,

    /// If present the tool will start execution for the provided step, skipping the initial ones.
    #[clap(long = "resume")]
    #[clap(value_enum)]
    pub next_step: Option<StepType>,

    /// Which steps to skip
    #[clap(long)]
    pub skip: Option<Vec<StepType>>,
}

/// The two subnets a subnet merge works with.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum TargetSubnet {
    /// The subnet that is cooling down, whose canisters are merged away and
    /// which is deleted afterwards.
    Source,
    /// The subnet that hosts the canisters of the source subnet after the merge
    /// and that is recovered at the merged state.
    Destination,
}

impl std::fmt::Display for TargetSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TargetSubnet::Source => "source",
            TargetSubnet::Destination => "destination",
        };
        write!(f, "{name}")
    }
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

        if recovery_args.skip_prompts {
            Self::check_download_nodes(&subnet_merging_args)
                .expect("The download nodes should be given when prompts are skipped");
        }

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

    /// Checks that the download node of each subnet is given, unless the step
    /// waiting for the halting CUP on it is skipped explicitly.
    ///
    /// Only needed when prompts are skipped: otherwise the step asks for the
    /// node. Without the node the step cannot be created, and the tool would
    /// carry on without confirming that the subnet has halted.
    fn check_download_nodes(args: &SubnetMergingArgs) -> RecoveryResult<()> {
        let skipped_steps = args.skip.clone().unwrap_or_default();
        for (step_type, node, option) in [
            (
                StepType::WaitForHaltingCupOnSourceSubnet,
                args.download_node_source,
                "--download-node-source",
            ),
            (
                StepType::WaitForHaltingCupOnDestinationSubnet,
                args.download_node_destination,
                "--download-node-destination",
            ),
        ] {
            if node.is_none() && !skipped_steps.contains(&step_type) {
                return Err(RecoveryError::UnexpectedError(format!(
                    "{option} is required by step {step_type:?}"
                )));
            }
        }
        Ok(())
    }

    /// Checks whether the subnets satisfy the following preconditions:
    /// 1) They are two different subnets;
    /// 2) Both are `Application` (or `VerifiedApplication`) subnets;
    /// 3) Neither holds any chain keys;
    /// 4) Neither is halted (`is_halted`), as a halted subnet never reaches the
    ///    CUP it is halted at by the tool (which sets `halt_at_cup_height`, but
    ///    never `is_halted`);
    /// 5) The destination subnet is not cooling down;
    /// 6) Both have the same subnet type, cycles cost schedule, subnet admins
    ///    and SEV setting.
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

        let source = Self::get_and_pre_validate_subnet_record(recovery, source_subnet_id)?;
        let destination =
            Self::get_and_pre_validate_subnet_record(recovery, destination_subnet_id)?;

        Self::ensure_compatible_subnet_records(
            source_subnet_id,
            &source,
            destination_subnet_id,
            &destination,
        )
    }

    /// Checks whether the records of the two (individually valid) subnets are
    /// compatible, i.e. the preconditions 5) and 6) above.
    fn ensure_compatible_subnet_records(
        source_subnet_id: SubnetId,
        source: &SubnetRecord,
        destination_subnet_id: SubnetId,
        destination: &SubnetRecord,
    ) -> RecoveryResult<()> {
        // Destructured exhaustively, so that a field added to `SubnetRecord`
        // fails to compile until it is decided whether it needs a check here.
        let SubnetRecord {
            // Checked below.
            subnet_type: _,
            canister_cycles_cost_schedule: _,
            subnet_admins: _,
            features: _, // Only `sev_enabled`.
            cooling_down: _,
            // Checked for each subnet on its own, by
            // `get_and_pre_validate_subnet_record`.
            is_halted: _,
            chain_key_config: _,
            // Set by the tool itself to halt both subnets.
            halt_at_cup_height: _,
            // Capacity, left to the merge step.
            max_number_of_canisters: _,
            resource_limits: _,
            // Settings of each subnet on its own: the merged subnet keeps those
            // of the destination subnet.
            membership: _,
            max_ingress_bytes_per_message: _,
            unit_delay_millis: _,
            initial_notary_delay_millis: _,
            replica_version_id: _,
            recalled_replica_version_ids: _,
            dkg_interval_length: _,
            dkg_dealings_per_block: _,
            start_as_nns: _,
            max_ingress_messages_per_block: _,
            max_ingress_bytes_per_block: _,
            max_block_payload_size: _,
            ssh_readonly_access: _,
            ssh_backup_access: _,
        } = source;

        if destination.cooling_down {
            return Err(RecoveryError::ValidationFailed(format!(
                "Subnet {destination_subnet_id}: the destination subnet should not be cooling down"
            )));
        }

        let mismatch = |what: &str, source_value: &dyn Debug, destination_value: &dyn Debug| {
            Err(RecoveryError::ValidationFailed(format!(
                "Both subnets should have the same {what}, but subnet {source_subnet_id} has \
                 {source_value:?} and subnet {destination_subnet_id} has {destination_value:?}"
            )))
        };
        let subnet_admins = |subnet_id: SubnetId, record: &SubnetRecord| {
            record
                .subnet_admins
                .iter()
                .map(|admin| {
                    PrincipalId::try_from(admin.raw.as_slice()).map_err(|err| {
                        RecoveryError::ValidationFailed(format!(
                            "Subnet {subnet_id}: invalid subnet admin {:?}: {err}",
                            admin.raw
                        ))
                    })
                })
                .collect::<RecoveryResult<BTreeSet<_>>>()
        };
        let sev_enabled = |record: &SubnetRecord| {
            record
                .features
                .and_then(|features| features.sev_enabled)
                .unwrap_or(false)
        };

        let (source_type, destination_type) = (source.subnet_type(), destination.subnet_type());
        if source_type != destination_type {
            return mismatch("subnet type", &source_type, &destination_type);
        }
        let (source_schedule, destination_schedule) = (
            source.canister_cycles_cost_schedule(),
            destination.canister_cycles_cost_schedule(),
        );
        if source_schedule != destination_schedule {
            return mismatch(
                "cycles cost schedule",
                &source_schedule,
                &destination_schedule,
            );
        }
        let (source_admins, destination_admins) = (
            subnet_admins(source_subnet_id, source)?,
            subnet_admins(destination_subnet_id, destination)?,
        );
        if source_admins != destination_admins {
            return mismatch("subnet admins", &source_admins, &destination_admins);
        }
        let (source_sev, destination_sev) = (sev_enabled(source), sev_enabled(destination));
        if source_sev != destination_sev {
            return mismatch("SEV setting (sev_enabled)", &source_sev, &destination_sev);
        }

        Ok(())
    }

    fn get_and_pre_validate_subnet_record(
        recovery: &Recovery,
        subnet_id: SubnetId,
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
            return validation_error("Subnet should not hold any chain keys".to_string());
        }

        if subnet_record.is_halted {
            return validation_error("Subnet should not be halted".to_string());
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

        Ok(subnet_record)
    }

    fn halt_subnet_at_cup_height_step(&self, target_subnet: TargetSubnet) -> AdminStep {
        AdminStep {
            logger: self.recovery.logger.clone(),
            ic_admin_cmd: get_halt_subnet_at_cup_height_command(
                &self.recovery.admin_helper,
                self.subnet_id(target_subnet),
                // No readonly SSH key (`key`) is needed: the halting CUP is
                // read from the replica's public endpoint rather than over SSH.
                &None,
            ),
        }
    }

    fn wait_for_halting_cup_step(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<impl Step + use<>> {
        // Not `StepSkipped`: the node is asked for or checked upfront, and
        // skipping the step would leave the halt unconfirmed.
        let Some(node) = self.download_node(target_subnet) else {
            return Err(RecoveryError::UnexpectedError(format!(
                "The node of subnet {} to download the state from is missing",
                self.subnet_id(target_subnet),
            )));
        };

        Ok(WaitForHaltingCupStep {
            subnet_id: self.subnet_id(target_subnet),
            node,
            registry_helper: self.recovery.registry_helper.clone(),
            layout: self.layout.clone(),
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
        Ok(StopReplicaAtHaltingCheckpointStep {
            subnet_id: self.subnet_id(target_subnet),
            node: self.download_node_access(target_subnet)?,
            layout: self.layout.clone(),
            timeout: Duration::from_secs(self.params.halt_timeout_secs),
            poll_interval: Duration::from_secs(self.params.poll_interval_secs),
            logger: self.recovery.logger.clone(),
        })
    }

    fn download_state_step(
        &self,
        target_subnet: TargetSubnet,
    ) -> RecoveryResult<impl Step + use<>> {
        Ok(DownloadStateStep {
            subnet_id: self.subnet_id(target_subnet),
            target_subnet,
            node: self.download_node_access(target_subnet)?,
            layout: self.layout.clone(),
            logger: self.recovery.logger.clone(),
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

    /// How the steps run commands on the node of a subnet whose state is
    /// merged: locally if the tool runs on that node, and over SSH with the
    /// admin key otherwise. Skips the step if the node is not given.
    fn download_node_access(&self, target_subnet: TargetSubnet) -> RecoveryResult<DownloadNode> {
        let location = self
            .download_node(target_subnet)
            .ok_or(RecoveryError::StepSkipped)?;
        Ok(DownloadNode {
            location,
            admin_key_file: self.recovery.admin_key_file.clone(),
            require_confirmation: self.recovery.ssh_confirmation,
            logger: self.recovery.logger.clone(),
        })
    }

    /// The node of a subnet whose state is merged, i.e. the one the halting CUP
    /// is waited for on.
    fn download_node(&self, target_subnet: TargetSubnet) -> Option<DataLocation> {
        match target_subnet {
            TargetSubnet::Source => self.params.download_node_source,
            TargetSubnet::Destination => self.params.download_node_destination,
        }
    }

    fn subnet_id(&self, target_subnet: TargetSubnet) -> SubnetId {
        match target_subnet {
            TargetSubnet::Source => self.params.source_subnet_id,
            TargetSubnet::Destination => self.params.destination_subnet_id,
        }
    }

    /// The URL of the dashboard evaluating the merge readiness condition, for
    /// the registry version `V` recorded by `CheckRegistryForCoolingDownFlag`.
    fn dashboard_url(&self) -> String {
        let source_subnet_id = self.params.source_subnet_id;
        match self
            .layout
            .read_cooling_down_registry_version(source_subnet_id)
        {
            Ok(registry_version) => format!(
                "https://grafana.mainnet.dfinity.network/d/subnet-merging?var-ic=mercury&var-ic_subnet={source_subnet_id}&var-registry_version={registry_version}",
            ),
            Err(err) => {
                warn!(
                    self.logger,
                    "Failed to read the registry version the subnet is labeled \"cooling down\" \
                     at: {}",
                    err
                );
                format!(
                    "https://grafana.mainnet.dfinity.network/d/subnet-merging?var-ic=mercury&var-ic_subnet={source_subnet_id}",
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

    fn get_skipped_steps(&self) -> Vec<StepType> {
        self.params.skip.clone().unwrap_or_default()
    }

    fn interactive(&self) -> bool {
        !self.recovery_args.skip_prompts
    }

    fn read_step_params(&mut self, step_type: StepType) {
        match step_type {
            StepType::CoolDownSourceSubnet | StepType::CheckRegistryForCoolingDownFlag => {}
            StepType::CheckMergeReadiness => print_url_and_ask_for_confirmation(
                &self.logger,
                self.dashboard_url(),
                "The tool evaluates the merge readiness condition itself, and waits until it \
                 holds. Please check the dashboard as well, to see whether it is safe to merge \
                 the subnet",
            ),
            StepType::HaltSourceSubnetAtCupHeight | StepType::HaltDestinationSubnetAtCupHeight => {}
            StepType::WaitForHaltingCupOnSourceSubnet => {
                if self.params.download_node_source.is_none() {
                    self.params.download_node_source = Some(read_data_location(
                        &self.logger,
                        "Enter the IP of the node of the Source Subnet to download the state from \
                         (or \"local\" if the tool runs on that node):",
                    ));
                }
            }
            StepType::WaitForHaltingCupOnDestinationSubnet => {
                if self.params.download_node_destination.is_none() {
                    self.params.download_node_destination = Some(read_data_location(
                        &self.logger,
                        "Enter the IP of the node of the Destination Subnet to download the state \
                         from (or \"local\" if the tool runs on that node):",
                    ));
                }
            }
            StepType::StopSourceReplica
            | StepType::StopDestinationReplica
            | StepType::DownloadStateFromSourceSubnet
            | StepType::DownloadStateFromDestinationSubnet
            | StepType::ValidateSourceSubnetCup
            | StepType::ValidateDestinationSubnetCup => {}
        }
    }

    fn get_step_impl(&self, step_type: StepType) -> RecoveryResult<Box<dyn Step>> {
        let step: Box<dyn Step> = match step_type {
            StepType::CoolDownSourceSubnet => AdminStep {
                logger: self.recovery.logger.clone(),
                ic_admin_cmd: get_propose_to_cool_down_subnet_command(
                    &self.recovery.admin_helper,
                    self.params.source_subnet_id,
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

            StepType::HaltSourceSubnetAtCupHeight => self
                .halt_subnet_at_cup_height_step(TargetSubnet::Source)
                .into(),

            StepType::HaltDestinationSubnetAtCupHeight => self
                .halt_subnet_at_cup_height_step(TargetSubnet::Destination)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> SubnetMergingArgs {
        SubnetMergingArgs {
            source_subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(1)),
            destination_subnet_id: SubnetId::from(PrincipalId::new_subnet_test_id(2)),
            download_node_source: Some(DataLocation::Remote("::1".parse().unwrap())),
            download_node_destination: Some(DataLocation::Local),
            merge_ready_timeout_secs: 2400,
            halt_timeout_secs: 123,
            registry_timeout_secs: 3600,
            poll_interval_secs: 10,
            next_step: Some(StepType::CheckMergeReadiness),
            skip: None,
        }
    }

    #[test]
    fn download_nodes_are_required_unless_their_step_is_skipped() {
        assert!(SubnetMerging::check_download_nodes(&args()).is_ok());

        let mut args = args();
        args.download_node_destination = None;
        let err = SubnetMerging::check_download_nodes(&args)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--download-node-destination"), "{err}");

        args.skip = Some(vec![StepType::WaitForHaltingCupOnDestinationSubnet]);
        assert!(SubnetMerging::check_download_nodes(&args).is_ok());

        args.download_node_source = None;
        let err = SubnetMerging::check_download_nodes(&args)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--download-node-source"), "{err}");
    }

    #[test]
    fn args_round_trip() {
        let args = args();
        let json = serde_json::to_string(&args).unwrap();
        assert_eq!(
            serde_json::from_str::<SubnetMergingArgs>(&json).unwrap(),
            args
        );
    }
}
