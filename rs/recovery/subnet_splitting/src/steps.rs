use crate::{
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
    steps::Step,
    Recovery, CUPS_DIR, IC_REGISTRY_LOCAL_STORE,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_manager::split::resolve_ranges_and_split;
use slog::{info, Logger};

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
            .map_err(|err| {
                RecoveryError::ValidationFailed(format!("Manifest verification failed: {}", err))
            })?;

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
