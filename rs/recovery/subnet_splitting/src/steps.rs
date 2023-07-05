use crate::{
    agent_helper::AgentHelper,
    layout::Layout,
    state_tool_helper::StateToolHelper,
    target_subnet::TargetSubnet,
    utils::{find_expected_state_hash_for_subnet_id, get_state_hash},
};

use ic_base_types::SubnetId;
use ic_metrics::MetricsRegistry;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::rsync,
    replay_helper,
    steps::Step,
    util::{block_on, parse_hex_str},
    Recovery, CUPS_DIR, IC_REGISTRY_LOCAL_STORE,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_manager::split::resolve_ranges_and_split;
use ic_types::Height;
use slog::{info, Logger};
use url::Url;

use std::net::IpAddr;

pub(crate) struct CopyWorkDirStep {
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for CopyWorkDirStep {
    fn descr(&self) -> String {
        format!(
            "Copying {} to {}. Excluding cups and registry local store",
            self.layout.work_dir(TargetSubnet::Source).display(),
            self.layout.work_dir(TargetSubnet::Destination).display(),
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        rsync(
            &self.logger,
            vec![CUPS_DIR, IC_REGISTRY_LOCAL_STORE],
            &format!("{}/", self.layout.work_dir(TargetSubnet::Source).display()),
            &self
                .layout
                .work_dir(TargetSubnet::Destination)
                .display()
                .to_string(),
            /*require_confirmation=*/ false,
            /*key_file=*/ None,
        )
        .map(|_| ())
    }
}

pub(crate) enum StateSplitStrategy {
    Retain(Vec<CanisterIdRange>),
    Drop(Vec<CanisterIdRange>),
}

impl StateSplitStrategy {
    fn dropped_canister_id_ranges(&self) -> Vec<CanisterIdRange> {
        match self {
            StateSplitStrategy::Retain(_) => vec![],
            StateSplitStrategy::Drop(dropped_canister_id_ranges) => {
                dropped_canister_id_ranges.clone()
            }
        }
    }

    fn retained_canister_id_ranges(&self) -> Vec<CanisterIdRange> {
        match self {
            StateSplitStrategy::Retain(retained_canister_id_ranges) => {
                retained_canister_id_ranges.clone()
            }
            StateSplitStrategy::Drop(_) => vec![],
        }
    }
}

pub(crate) struct SplitStateStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) state_split_strategy: StateSplitStrategy,
    pub(crate) state_tool_helper: StateToolHelper,
    pub(crate) layout: Layout,
    pub(crate) target_subnet: TargetSubnet,
    pub(crate) logger: Logger,
}

impl Step for SplitStateStep {
    fn descr(&self) -> String {
        match &self.state_split_strategy {
            StateSplitStrategy::Retain(retained_canister_id_ranges) => format!(
                "Retaining the canister id ranges {:#?} from state for the subnet {} \
                 and removing all but the highest checkpoints. Work dir: {}",
                retained_canister_id_ranges,
                self.subnet_id,
                self.layout.work_dir(self.target_subnet).display(),
            ),
            StateSplitStrategy::Drop(dropped_canister_id_ranges) => format!(
                "Dropping the canister id ranges {:#?} from state for the subnet {}. \
                 and removing all but the highest checkpoints. Work dir: {}",
                dropped_canister_id_ranges,
                self.subnet_id,
                self.layout.work_dir(self.target_subnet).display(),
            ),
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        // 1. Split the state.
        info!(self.logger, "Splitting the state");
        resolve_ranges_and_split(
            self.layout.ic_state_dir(self.target_subnet),
            self.subnet_id.get(),
            self.state_split_strategy.retained_canister_id_ranges(),
            self.state_split_strategy.dropped_canister_id_ranges(),
            &MetricsRegistry::new(),
            self.logger.clone().into(),
        )
        .map_err(RecoveryError::OutputError)?;

        // 2. Compute the manifest
        info!(self.logger, "Computing the state manifest");
        let latest_checkpoint_dir = self.layout.latest_checkpoint_dir(self.target_subnet)?;
        let manifest_path = self.layout.actual_manifest_file(self.subnet_id);

        self.state_tool_helper
            .compute_manifest(&latest_checkpoint_dir, &manifest_path)?;

        // 3. Validate the manifest
        info!(self.logger, "Validating the manifest");
        self.state_tool_helper
            .verify_manifest(&manifest_path)
            .map_err(|err| RecoveryError::validation_failed("Manifest verification failed", err))?;

        let expected_state_hash = find_expected_state_hash_for_subnet_id(
            self.layout.expected_manifests_file(),
            self.subnet_id,
        )?;
        let actual_state_hash = get_state_hash(&latest_checkpoint_dir)?;

        if actual_state_hash != expected_state_hash {
            return Err(RecoveryError::ValidationFailed(format!(
                "State hash after split {} doesn't match the expected state hash {}",
                actual_state_hash, expected_state_hash,
            )));
        }

        info!(self.logger, "Validation passed!");
        // 4. Remove all the other checkpoints
        info!(self.logger, "Removing past checkpoints");

        Recovery::remove_all_but_highest_checkpoints(
            &self.layout.checkpoints_dir(self.target_subnet),
            &self.logger,
        )
        .map(|_| ())
    }
}

pub(crate) struct ComputeExpectedManifestsStep {
    pub(crate) state_tool_helper: StateToolHelper,
    pub(crate) source_subnet_id: SubnetId,
    pub(crate) destination_subnet_id: SubnetId,
    pub(crate) canister_id_ranges_to_move: Vec<CanisterIdRange>,
    pub(crate) layout: Layout,
}

impl Step for ComputeExpectedManifestsStep {
    fn descr(&self) -> String {
        format!(
            "Compute the expected manifests of the states resulting from splitting the manifest \
            at {} between {} (hosting all canisters in {:?}) and {} (all remaining canisters)",
            self.layout.checkpoints_dir(TargetSubnet::Source).display(),
            self.destination_subnet_id,
            self.canister_id_ranges_to_move,
            self.source_subnet_id,
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        self.state_tool_helper.compute_manifest(
            &self.layout.latest_checkpoint_dir(TargetSubnet::Source)?,
            self.layout.original_state_manifest_file(),
        )?;

        self.state_tool_helper.split_manifest(
            self.layout.original_state_manifest_file(),
            self.source_subnet_id,
            self.destination_subnet_id,
            &self.canister_id_ranges_to_move,
            self.layout.expected_manifests_file(),
        )
    }
}

pub(crate) struct ValidateCUPStep {
    pub(crate) subnet_id: SubnetId,
    pub(crate) nns_url: Url,
    pub(crate) layout: Layout,
    pub(crate) logger: Logger,
}

impl Step for ValidateCUPStep {
    fn descr(&self) -> String {
        format!(
            "Validate the CUP downloaded from the source subnet {} and preserve the subnet's \
            public key and the state tree (with only relevant paths) so it can be verified \
            independently.",
            self.subnet_id
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let work_dir = self.layout.work_dir(TargetSubnet::Source);

        // 1. Get the subnet's public key using `ic-agent` and persist it at the disk
        let agent_helper = AgentHelper::new(
            &self.nns_url,
            self.layout.nns_public_key_file(),
            self.logger.clone(),
        )?;

        let pruned_state_tree = agent_helper.read_subnet_data(self.subnet_id)?;
        agent_helper
            .validate_state_tree(&pruned_state_tree)
            .map_err(|err| {
                RecoveryError::validation_failed("Failed to validate the state tree", err)
            })?;

        pruned_state_tree.save_to_file(self.layout.pruned_state_tree_file())?;
        pruned_state_tree
            .save_public_key_to_file(&self.layout.subnet_public_key_file(self.subnet_id))?;

        // 2. Run ic-replay to verify the CUP
        block_on(replay_helper::replay(
            self.subnet_id,
            work_dir.join("ic.json5"),
            /*canister_caller_id=*/ None,
            self.layout.data_dir(TargetSubnet::Source),
            Some(ic_replay::cmd::SubCommand::VerifySubnetCUP(
                ic_replay::cmd::VerifySubnetCUPCmd {
                    cup_file: self.layout.cup_file(TargetSubnet::Source),
                    public_key_file: self.layout.subnet_public_key_file(self.subnet_id),
                },
            )),
            work_dir.join("cup_validation_result.txt"),
        ))
        .map(|_| ())
        .map_err(|err| RecoveryError::validation_failed("Failed to validate CUP", err))
    }
}

pub(crate) struct WaitForCUPStep {
    pub(crate) logger: Logger,
    pub(crate) node_ip: IpAddr,
    pub(crate) layout: Layout,
    pub(crate) target_subnet: TargetSubnet,
}

impl Step for WaitForCUPStep {
    fn descr(&self) -> String {
        format!(
            "Waiting until recovery CUP is found on node {}.",
            self.node_ip
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        let latest_checkpoint = self.layout.latest_checkpoint_dir(self.target_subnet)?;
        let state_hash = get_state_hash(&latest_checkpoint)?;
        let state_height = parse_hex_str(latest_checkpoint.file_name().unwrap().to_str().unwrap())?;
        let new_cup_height = Recovery::get_recovery_height(Height::from(state_height));

        Recovery::wait_for_recovery_cup(&self.logger, self.node_ip, new_cup_height, state_hash)
    }
}
