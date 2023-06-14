use ic_base_types::SubnetId;
use ic_metrics::MetricsRegistry;
use ic_recovery::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::rsync,
    steps::Step,
    Recovery, CHECKPOINTS, CUPS_DIR, IC_REGISTRY_LOCAL_STORE, IC_STATE_DIR,
};
use ic_registry_routing_table::CanisterIdRange;
use ic_state_manager::split::resolve_ranges_and_split;
use slog::Logger;

use std::path::PathBuf;

pub(crate) struct CopyWorkDirStep {
    pub(crate) from: PathBuf,
    pub(crate) to: PathBuf,
    pub(crate) logger: Logger,
}

impl Step for CopyWorkDirStep {
    fn descr(&self) -> String {
        format!(
            "Copying {} to {}. Excluding cups and registry local store",
            self.from.display(),
            self.to.display()
        )
    }

    fn exec(&self) -> RecoveryResult<()> {
        rsync(
            &self.logger,
            vec![CUPS_DIR, IC_REGISTRY_LOCAL_STORE],
            &format!("{}/", self.from.display()),
            &self.to.display().to_string(),
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
    pub(crate) work_dir: PathBuf,
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
                self.work_dir.display(),
            ),
            StateSplitStrategy::Drop(dropped_canister_id_ranges) => format!(
                "Dropping the canister id ranges {:#?} from state for the subnet {}. \
                 and removing all but the highest checkpoints. Work dir: {}",
                dropped_canister_id_ranges,
                self.subnet_id,
                self.work_dir.display(),
            ),
        }
    }

    fn exec(&self) -> RecoveryResult<()> {
        let state_dir = self.work_dir.join(IC_STATE_DIR);
        let checkpoints_dir = state_dir.join(CHECKPOINTS);

        resolve_ranges_and_split(
            state_dir,
            self.subnet_id.get(),
            self.state_split_strategy.retained_canister_id_ranges(),
            self.state_split_strategy.dropped_canister_id_ranges(),
            &MetricsRegistry::new(),
            self.logger.clone().into(),
        )
        .map_err(RecoveryError::OutputError)?;

        Recovery::remove_all_but_highest_checkpoints(&checkpoints_dir, &self.logger).map(|_| ())
    }
}
