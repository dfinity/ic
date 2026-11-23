use crate::{
    admin_helper::{get_propose_to_cool_down_subnet_command, get_propose_to_merge_subnets_command},
    layout::Layout,
    steps::{
        CheckCoolingDownStep, CheckMergeReadinessStep, CheckRoutingTableStep,
        ComputeExpectedMergedManifestStep, DownloadStateStep, MergeStatesStep,
        ProposeRecoveryCupStep, RestartDestinationReplicaStep, StopReplicaAtHaltingCheckpointStep,
        UploadMergedStateStep, ValidateCupStep, WaitForHaltingCupStep, WaitForRecoveryCupStep,
    },
    utils::ensure_default_initial_dkg_subnet_is_not_merged,
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
    ssh_helper::SshHelper,
    steps::{AdminStep, Step},
    util::{DataLocation, ExecutionMode, SshUser},
};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_tools::{
    admin_helper::{get_halt_subnet_at_cup_height_command, get_unhalt_subnet_command},
    utils::print_url_and_ask_for_confirmation,
};
use serde::{Deserialize, Serialize};
use slog::{Logger, warn};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};

use std::{
    collections::BTreeSet,
    fmt::Debug,
    iter::Peekable,
    net::{IpAddr, Ipv6Addr},
    time::Duration,
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
    /// at, then stop its replica and crypto vault.
    StopSourceReplica,
    /// Wait until the node of the destination subnet the state is downloaded
    /// from holds a finished checkpoint at the height of the CUP the subnet
    /// halts at, then stop its replica and crypto vault.
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
    /// Compute the manifest the merged state is expected to have from the
    /// manifests of the two downloaded states.
    ComputeExpectedMergedManifest,
    /// Assemble the merged state from the two downloaded states, and check its
    /// manifest against the expected one.
    MergeStates,
    /// Submit a proposal to route the canister ID ranges of the source subnet
    /// to the destination subnet.
    MergeSubnets,
    /// Wait until the registry routes no canister ID range to the source subnet
    /// anymore, and record the registry version at which this was read.
    CheckRegistryForRoutingTableEntry,
    /// Submit a proposal for a recovery CUP of the destination subnet at the
    /// merged state.
    ProposeCupForDestinationSubnet,
    /// Upload the merged state to a node of the destination subnet.
    UploadStateToDestinationSubnet,
    /// Set permissions on the installed state and restart the destination node's replica.
    RestartDestinationReplica,
    /// Wait until that node reports the recovery CUP.
    WaitForCupOnDestinationSubnet,
    /// Submit a proposal to unhalt the destination subnet.
    UnhaltDestinationSubnet,
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

    /// The node of the source subnet to download the state from: its IPv6
    /// address, or "local" if the tool runs on that node. The halting CUP is
    /// waited for on that node, and its replica is stopped before the download.
    /// Asked for if missing, unless prompts are skipped. Remote access uses SSH
    /// with the admin key.
    #[clap(long, value_parser=ic_recovery::util::data_location_from_str)]
    pub source_node: Option<DataLocation>,

    /// The node of the destination subnet to download the state from and upload
    /// the merged state to: its IPv6 address, or "local" if the tool runs on
    /// that node. The halting CUP is waited for on that node, its replica is
    /// stopped before the download and restarted on the merged state, and the
    /// recovery CUP is waited for on that node. Asked for if missing, unless prompts are skipped. Remote access uses SSH with the
    /// admin key.
    #[clap(long, value_parser=ic_recovery::util::data_location_from_str)]
    pub destination_node: Option<DataLocation>,

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

    /// How long to wait, in seconds, for the proposals labeling the source
    /// subnet as "cooling down" and merging it into the destination subnet to
    /// be adopted, executed and visible in the registry.
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

        let layout =
            Layout::new(&recovery, &logger).expect("Failed to create the working directories");

        if recovery_args.skip_prompts {
            Self::check_nodes(&subnet_merging_args)
                .expect("The nodes should be given when prompts are skipped");
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

    /// Checks that the node of each subnet is given, unless none of the steps
    /// that need it runs, i.e. each is skipped explicitly or comes before the
    /// step the tool resumes at.
    ///
    /// Only needed when prompts are skipped: otherwise each of these steps asks
    /// for the node. Without the node the steps cannot be created, and the tool
    /// would carry on without confirming that the subnet has halted or
    /// uploading the merged state and waiting for its recovery CUP.
    fn check_nodes(args: &SubnetMergingArgs) -> RecoveryResult<()> {
        let skipped_steps = args.skip.clone().unwrap_or_default();
        let runs = |step_type: &StepType| {
            !skipped_steps.contains(step_type)
                && args
                    .next_step
                    .is_none_or(|next_step| *step_type as usize >= next_step as usize)
        };
        for (step_types, node, option) in [
            (
                &[
                    StepType::WaitForHaltingCupOnSourceSubnet,
                    StepType::StopSourceReplica,
                    StepType::DownloadStateFromSourceSubnet,
                ][..],
                args.source_node,
                "--source-node",
            ),
            (
                &[
                    StepType::WaitForHaltingCupOnDestinationSubnet,
                    StepType::StopDestinationReplica,
                    StepType::DownloadStateFromDestinationSubnet,
                    StepType::UploadStateToDestinationSubnet,
                    StepType::RestartDestinationReplica,
                    StepType::WaitForCupOnDestinationSubnet,
                ][..],
                args.destination_node,
                "--destination-node",
            ),
        ] {
            if node.is_some() {
                continue;
            }
            if let Some(step_type) = step_types.iter().find(|step_type| runs(step_type)) {
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
    /// 4) The destination subnet is not cooling down;
    /// 5) Both have the same subnet type, cycles cost schedule, subnet admins,
    ///    SEV setting and replica version;
    /// 6) Neither is the default initial DKG subnet, which runs the DKG for the
    ///    recovery of the destination subnet.
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
        )?;

        ensure_default_initial_dkg_subnet_is_not_merged(
            &recovery.registry_helper,
            source_subnet_id,
            destination_subnet_id,
        )
    }

    /// Checks whether the records of the two (individually valid) subnets are
    /// compatible, i.e. the preconditions 4) and 5) above.
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
            replica_version_id: _,
            cooling_down: _,
            // Checked for each subnet on its own, by
            // `get_and_pre_validate_subnet_record`.
            chain_key_config: _,
            // Changed by the merge itself: the tool sets `halt_at_cup_height` on both
            // subnets, and the recovery CUP proposal turns it into `is_halted` on the
            // destination subnet.
            is_halted: _,
            halt_at_cup_height: _,
            // Capacity, not checked yet: a follow-up is to load the merged
            // state into a `StateMachine` with the destination subnet's
            // settings and check that the merged state is fine there.
            max_number_of_canisters: _,
            resource_limits: _,
            // Settings of each subnet on its own: the merged subnet keeps those
            // of the destination subnet.
            membership: _,
            max_ingress_bytes_per_message: _,
            unit_delay_millis: _,
            initial_notary_delay_millis: _,
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
        // The merged state combines checkpoints written by the replicas of both
        // subnets and is loaded by the replica of the destination subnet, so
        // both subnets must run the same replica version (which, in
        // particular, writes the same state sync version).
        if source.replica_version_id != destination.replica_version_id {
            return mismatch(
                "replica version",
                &source.replica_version_id,
                &destination.replica_version_id,
            );
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

    /// Unhalting the destination subnet only clears its `is_halted` flag. The
    /// merge installs no SSH keys, so there are none to clear, and any SSH keys
    /// or recalled replica versions the destination subnet had before the merge
    /// are kept.
    fn unhalt_destination_subnet_step(&self) -> AdminStep {
        AdminStep {
            logger: self.recovery.logger.clone(),
            ic_admin_cmd: get_unhalt_subnet_command(
                &self.recovery.admin_helper,
                self.params.destination_subnet_id,
            ),
        }
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
        Ok(WaitForHaltingCupStep {
            subnet_id: self.subnet_id(target_subnet),
            node: self.node_location(target_subnet)?,
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
            node: self.node_access(target_subnet)?,
            require_confirmation: self.recovery.ssh_confirmation,
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
            node: self.node_access(target_subnet)?,
            require_confirmation: self.recovery.ssh_confirmation,
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

    fn upload_merged_state_step(&self) -> RecoveryResult<impl Step + use<>> {
        Ok(UploadMergedStateStep {
            node: self.node_location(TargetSubnet::Destination)?,
            layout: self.layout.clone(),
            require_confirmation: self.recovery.ssh_confirmation,
            key_file: self.recovery.admin_key_file.clone(),
            logger: self.recovery.logger.clone(),
        })
    }

    fn wait_for_recovery_cup_step(&self) -> RecoveryResult<impl Step + use<>> {
        Ok(WaitForRecoveryCupStep {
            source_subnet_id: self.params.source_subnet_id,
            destination_subnet_id: self.params.destination_subnet_id,
            node_ip: match self.node_location(TargetSubnet::Destination)? {
                DataLocation::Remote(ip) => ip,
                DataLocation::Local => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            layout: self.layout.clone(),
            logger: self.recovery.logger.clone(),
        })
    }

    /// How the steps run commands on the node of a subnet whose state is
    /// merged: locally if the tool runs on that node, and over SSH with the
    /// admin key otherwise.
    fn node_access(&self, target_subnet: TargetSubnet) -> RecoveryResult<ExecutionMode> {
        Ok(match self.node_location(target_subnet)? {
            DataLocation::Local => ExecutionMode::Local,
            // The upload of the merged state to the destination subnet needs
            // the admin key anyway.
            DataLocation::Remote(node_ip) => ExecutionMode::Remote(SshHelper::new(
                self.recovery.logger.clone(),
                SshUser::Admin,
                node_ip,
                self.recovery.ssh_confirmation,
                self.recovery.admin_key_file.clone(),
            )),
        })
    }

    /// The node used for every step that accesses a subnet: waiting for CUPs,
    /// stopping its replica, downloading its state and, for the destination
    /// subnet, uploading the merged state, restarting its replica and waiting
    /// for the recovery CUP.
    ///
    /// Every step that needs the node prompts for it, and it is checked upfront
    /// when prompts are skipped, so it is only missing if something went wrong.
    fn node_location(&self, target_subnet: TargetSubnet) -> RecoveryResult<DataLocation> {
        let node = match target_subnet {
            TargetSubnet::Source => self.params.source_node,
            TargetSubnet::Destination => self.params.destination_node,
        };
        node.ok_or_else(|| {
            RecoveryError::UnexpectedError(format!(
                "The node of subnet {} is missing",
                self.subnet_id(target_subnet),
            ))
        })
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
            StepType::WaitForHaltingCupOnSourceSubnet
            | StepType::StopSourceReplica
            | StepType::DownloadStateFromSourceSubnet => {
                if self.params.source_node.is_none() {
                    self.params.source_node = Some(read_data_location(
                        &self.logger,
                        "Enter the IP of the node of the Source Subnet to download the state from \
                         (or \"local\" if the tool runs on that node):",
                    ));
                }
            }
            StepType::WaitForHaltingCupOnDestinationSubnet
            | StepType::StopDestinationReplica
            | StepType::DownloadStateFromDestinationSubnet
            | StepType::UploadStateToDestinationSubnet
            | StepType::RestartDestinationReplica
            | StepType::WaitForCupOnDestinationSubnet => {
                if self.params.destination_node.is_none() {
                    self.params.destination_node = Some(read_data_location(
                        &self.logger,
                        "Enter the IP of the node of the Destination Subnet to download the state \
                         from and upload the merged state to (or \"local\" if the tool runs on \
                         that node):",
                    ));
                }
            }
            StepType::ValidateSourceSubnetCup
            | StepType::ValidateDestinationSubnetCup
            | StepType::ComputeExpectedMergedManifest
            | StepType::MergeStates
            | StepType::MergeSubnets
            | StepType::CheckRegistryForRoutingTableEntry
            | StepType::ProposeCupForDestinationSubnet
            | StepType::UnhaltDestinationSubnet => {}
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

            StepType::ComputeExpectedMergedManifest => ComputeExpectedMergedManifestStep {
                source_subnet_id: self.params.source_subnet_id,
                destination_subnet_id: self.params.destination_subnet_id,
                layout: self.layout.clone(),
            }
            .into(),

            StepType::MergeStates => MergeStatesStep {
                source_subnet_id: self.params.source_subnet_id,
                destination_subnet_id: self.params.destination_subnet_id,
                layout: self.layout.clone(),
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

            StepType::ProposeCupForDestinationSubnet => ProposeRecoveryCupStep {
                source_subnet_id: self.params.source_subnet_id,
                destination_subnet_id: self.params.destination_subnet_id,
                admin_helper: self.recovery.admin_helper.clone(),
                registry_helper: self.recovery.registry_helper.clone(),
                layout: self.layout.clone(),
                logger: self.recovery.logger.clone(),
            }
            .into(),
            StepType::UploadStateToDestinationSubnet => self.upload_merged_state_step()?.into(),
            StepType::RestartDestinationReplica => RestartDestinationReplicaStep {
                node: self.node_access(TargetSubnet::Destination)?,
                require_confirmation: self.recovery.ssh_confirmation,
                logger: self.recovery.logger.clone(),
            }
            .into(),
            StepType::WaitForCupOnDestinationSubnet => self.wait_for_recovery_cup_step()?.into(),
            StepType::UnhaltDestinationSubnet => self.unhalt_destination_subnet_step().into(),
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
            source_node: Some(DataLocation::Remote("::1".parse().unwrap())),
            destination_node: Some(DataLocation::Local),
            merge_ready_timeout_secs: 2400,
            halt_timeout_secs: 123,
            registry_timeout_secs: 3600,
            poll_interval_secs: 10,
            next_step: Some(StepType::CheckMergeReadiness),
            skip: None,
        }
    }

    #[test]
    fn source_node_is_required_unless_all_its_steps_are_skipped() {
        let mut args = args();
        assert!(SubnetMerging::check_nodes(&args).is_ok());
        args.source_node = None;
        for step in [
            StepType::WaitForHaltingCupOnSourceSubnet,
            StepType::StopSourceReplica,
            StepType::DownloadStateFromSourceSubnet,
        ] {
            let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
            assert!(err.contains("--source-node"), "{err}");
            assert!(err.contains(&format!("{step:?}")), "{err}");
            args.skip.get_or_insert_default().push(step);
        }
        assert!(SubnetMerging::check_nodes(&args).is_ok());
    }

    #[test]
    fn destination_node_is_required_unless_all_its_steps_are_skipped() {
        let mut args = args();
        assert!(SubnetMerging::check_nodes(&args).is_ok());
        args.destination_node = None;
        for step in [
            StepType::WaitForHaltingCupOnDestinationSubnet,
            StepType::StopDestinationReplica,
            StepType::DownloadStateFromDestinationSubnet,
            StepType::UploadStateToDestinationSubnet,
            StepType::RestartDestinationReplica,
            StepType::WaitForCupOnDestinationSubnet,
        ] {
            let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
            assert!(err.contains("--destination-node"), "{err}");
            assert!(err.contains(&format!("{step:?}")), "{err}");
            args.skip.get_or_insert_default().push(step);
        }
        assert!(SubnetMerging::check_nodes(&args).is_ok());
    }

    #[test]
    fn nodes_are_required_unless_resumed_past_their_steps() {
        let mut args = args();
        args.source_node = None;
        args.destination_node = None;

        // Both nodes are needed by the steps from the one resumed at.
        args.next_step = Some(StepType::StopSourceReplica);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("StopSourceReplica"), "{err}");

        args.source_node = Some(DataLocation::Local);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("StopDestinationReplica"), "{err}");
        args.source_node = None;

        // The last step needing the node of the source subnet still runs.
        args.next_step = Some(StepType::DownloadStateFromSourceSubnet);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("--source-node"), "{err}");
        assert!(err.contains("DownloadStateFromSourceSubnet"), "{err}");

        // Past it, only the node of the destination subnet is needed.
        args.next_step = Some(StepType::DownloadStateFromDestinationSubnet);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("--destination-node"), "{err}");
        assert!(err.contains("DownloadStateFromDestinationSubnet"), "{err}");

        args.destination_node = Some(DataLocation::Local);
        assert!(SubnetMerging::check_nodes(&args).is_ok());
        args.destination_node = None;

        // The validation steps need neither node, but the steps recovering the
        // destination subnet after them need its node.
        args.next_step = Some(StepType::ValidateSourceSubnetCup);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("--destination-node"), "{err}");
        assert!(err.contains("UploadStateToDestinationSubnet"), "{err}");

        args.destination_node = Some(DataLocation::Local);
        assert!(SubnetMerging::check_nodes(&args).is_ok());
        args.destination_node = None;

        // Resuming after upload still needs the destination node for the restart
        // and for waiting for the recovery CUP.
        args.next_step = Some(StepType::RestartDestinationReplica);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("--destination-node"), "{err}");
        assert!(err.contains("RestartDestinationReplica"), "{err}");

        args.next_step = Some(StepType::WaitForCupOnDestinationSubnet);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(err.contains("--destination-node"), "{err}");
        assert!(err.contains("WaitForCupOnDestinationSubnet"), "{err}");

        // Past the last step needing the destination node, no node is needed.
        args.next_step = Some(StepType::UnhaltDestinationSubnet);
        assert!(SubnetMerging::check_nodes(&args).is_ok());

        // Without resuming, every step runs.
        args.next_step = None;
        args.source_node = Some(DataLocation::Local);
        let err = SubnetMerging::check_nodes(&args).unwrap_err().to_string();
        assert!(
            err.contains("WaitForHaltingCupOnDestinationSubnet"),
            "{err}"
        );
    }

    #[test]
    fn subnets_must_run_the_same_replica_version() {
        let source_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
        let destination_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(2));
        let record = |replica_version_id: &str| SubnetRecord {
            replica_version_id: replica_version_id.to_string(),
            ..Default::default()
        };

        assert!(
            SubnetMerging::ensure_compatible_subnet_records(
                source_subnet_id,
                &record("version_a"),
                destination_subnet_id,
                &record("version_a"),
            )
            .is_ok()
        );

        let err = SubnetMerging::ensure_compatible_subnet_records(
            source_subnet_id,
            &record("version_a"),
            destination_subnet_id,
            &record("version_b"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("replica version"), "{err}");
        assert!(err.contains("version_a"), "{err}");
        assert!(err.contains("version_b"), "{err}");
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
