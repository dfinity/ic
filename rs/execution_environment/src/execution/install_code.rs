// This module defines types and functions common between canister installation
// and upgrades.

use ic_base_types::NumBytes;
use ic_replicated_state::CanisterState;
use ic_types::NumInstructions;

use crate::{
    canister_manager::CanisterManagerError, execution_environment::RoundContext, RoundLimits,
};

/// The result of canister installation or upgrade routines.
/// If the routine has finished successfuly, then the canister state is the new
/// canister state with all changes. If the routine has failed, then there is no
/// new canister state and the caller should use the old state after refunding
/// the remaining instructions.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum InstallCodeRoutineResult {
    Finished {
        instructions_left: NumInstructions,
        result: Result<(CanisterState, NumBytes), CanisterManagerError>,
    },
    Paused {
        paused_execution: Box<dyn PausedInstallCodeRoutine>,
    },
}

/// Represents a paused execution of install code routine,
/// that can be resumed or aborted.
pub(crate) trait PausedInstallCodeRoutine: std::fmt::Debug {
    /// Resumes a paused install code execution.
    fn resume(
        self: Box<Self>,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> InstallCodeRoutineResult;

    // Aborts the paused execution.
    fn abort(self: Box<Self>);
}
