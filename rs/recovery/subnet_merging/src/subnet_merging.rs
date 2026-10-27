use crate::{
    admin_helper::get_propose_to_cool_down_subnet_command,
    layout::Layout,
    steps::{CheckCoolingDownStep, CheckMergeReadinessStep, WaitForHaltingCupStep},
    target_subnet::TargetSubnet,
};

use clap::Parser;
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_recovery::{
    NeuronArgs, Recovery, RecoveryArgs,
    cli::read_optional,
    error::{RecoveryError, RecoveryResult},
    recovery_iterator::RecoveryIterator,
    recovery_state::{HasRecoveryState, RecoveryState},
    registry_helper::RegistryPollingStrategy,
    ssh_helper::SshHelper,
    steps::{AdminStep, Step},
    util::SshUser,
};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_tools::{
    admin_helper::get_halt_subnet_at_cup_height_command, utils::print_url_and_ask_for_confirmation,
};
use serde::{Deserialize, Serialize};
use slog::{Logger, warn};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{EnumIter, EnumString};

use std::{
    collections::BTreeSet, fmt::Debug, iter::Peekable, net::IpAddr, path::PathBuf, time::Duration,
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
    /// holds the CUP the subnet halts at.
    WaitForHaltingCupOnSourceSubnet,
    /// Wait until the node of the destination subnet the state is downloaded
    /// from holds the CUP the subnet halts at.
    WaitForHaltingCupOnDestinationSubnet,
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

    /// IP address of the node of the source subnet to download the state from.
    #[clap(long)]
    pub download_node_source: Option<IpAddr>,

    /// IP address of the node of the destination subnet to download the state from.
    #[clap(long)]
    pub download_node_destination: Option<IpAddr>,

    /// How long to wait for the subnet that is cooling down to become ready to
    /// be merged, in seconds.
    #[clap(long, default_value = "2400")]
    pub merge_ready_timeout_secs: u64,

    /// How long to wait for a subnet to reach the CUP it halts at, in seconds.
    #[clap(long, default_value = "900")]
    pub halt_timeout_secs: u64,

    /// How long to wait, in seconds, for the proposal labeling the source
    /// subnet as "cooling down" to be adopted, executed and visible in the
    /// registry.
    #[clap(long, default_value = "3600")]
    pub registry_timeout_secs: u64,

    /// How long to wait, in seconds, between two attempts of a step that waits:
    /// between two registry reads while waiting for the "cooling down" label,
    /// and between two readiness rounds (each reading the registry and scraping
    /// every replica). Must be positive.
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
            subnet_merging_args.next_step,
        )
        .expect("Subnets should satisfy all the preconditions");

        Self {
            step_iterator: StepType::iter().peekable(),
            params: subnet_merging_args,
            recovery_args,
            neuron_args,
            layout: Layout::new(&recovery),
            recovery,
            logger,
        }
    }

    /// Checks whether the subnets satisfy the following preconditions:
    /// 1) They are two different subnets;
    /// 2) Both are `Application` (or `VerifiedApplication`) subnets;
    /// 3) Neither holds any chain keys;
    /// 4) Neither is halted nor scheduled to halt at its next CUP, unless the
    ///    tool is resumed past `HaltSourceSubnetAtCupHeight`, i.e. after it
    ///    started halting them itself;
    /// 5) The destination subnet is not cooling down;
    /// 6) Both have the same subnet type, cycles cost schedule, subnet admins
    ///    and SEV setting.
    fn check_subnets_preconditions(
        recovery: &Recovery,
        source_subnet_id: SubnetId,
        destination_subnet_id: SubnetId,
        next_step: Option<StepType>,
    ) -> RecoveryResult<()> {
        if source_subnet_id == destination_subnet_id {
            return Err(RecoveryError::ValidationFailed(format!(
                "A subnet cannot be merged into itself ({source_subnet_id})"
            )));
        }

        let check_not_halted = next_step.is_none_or(|next_step| {
            next_step as usize <= StepType::HaltSourceSubnetAtCupHeight as usize
        });
        let source =
            Self::get_and_pre_validate_subnet_record(recovery, source_subnet_id, check_not_halted)?;
        let destination = Self::get_and_pre_validate_subnet_record(
            recovery,
            destination_subnet_id,
            check_not_halted,
        )?;

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
            halt_at_cup_height: _,
            chain_key_config: _,
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
        check_not_halted: bool,
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

        if check_not_halted && (subnet_record.is_halted || subnet_record.halt_at_cup_height) {
            return validation_error(String::from(
                "Subnet should neither be halted nor scheduled to halt at its next CUP",
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

    /// The node of a subnet whose state is merged, i.e. the one the halting CUP
    /// is waited for on.
    fn download_node(&self, target_subnet: TargetSubnet) -> Option<IpAddr> {
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
            StepType::HaltSourceSubnetAtCupHeight => {
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
            StepType::HaltDestinationSubnetAtCupHeight => {}
            StepType::WaitForHaltingCupOnSourceSubnet => {
                if self.params.download_node_source.is_none() {
                    self.params.download_node_source = read_optional(
                        &self.logger,
                        "Enter the IP of the node of the Source Subnet to download the state from:",
                    );
                }
            }
            StepType::WaitForHaltingCupOnDestinationSubnet => {
                if self.params.download_node_destination.is_none() {
                    self.params.download_node_destination = read_optional(
                        &self.logger,
                        "Enter the IP of the node of the Destination Subnet to download the state from:",
                    );
                }
            }
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
