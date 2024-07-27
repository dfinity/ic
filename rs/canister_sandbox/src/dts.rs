use ic_embedders::wasm_executor::SliceExecutionOutput;
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, OutOfInstructionsHandler,
};
use ic_types::NumInstructions;
use std::sync::{Arc, Condvar, Mutex};

// The upper bound on the number of supported execution slices.
//
// It is set to 400 because 500 the number of rounds in an epoch,
// which the interval between two checkpoints.
//
// Note that currently the maximum number of slices:
// - for update messages is 10.
// - for upgrade messages is 100.
// See constants in `rs/config/src/subnet_config.rs`
const MAX_NUM_SLICES: i64 = 400;

// Indicates the current state of execution.
// It start with `Running` and may transition to `Paused`.
// From `Paused` it transitions either to `Running` or `Aborted`.
#[derive(Debug, Eq, PartialEq)]
enum ExecutionStatus {
    Running,
    Aborted,
    Paused,
}

// All the state necessary to implement deterministic time slicing.
struct State {
    execution_status: ExecutionStatus,

    /// The instruction limit to report in case of an error.
    instruction_limit_to_report: i64,

    // The instruction limit for all slices combined.
    total_instruction_limit: i64,

    // The maximum value of the slice instruction limit.
    max_slice_instruction_limit: i64,

    // The instruction limit for the next slice. Typically it is the same as
    // `max_slice_instruction_limit`, but may be lower for the last slice
    // and if the previous slice went over its limit.
    slice_instruction_limit: i64,

    // The number of instructions that have been executed so far.
    // Invariant: it does not exceed `total_instruction_limit`.
    instructions_executed: i64,

    // The number of remaining execution slices.
    //
    // Note that normally execution finishes when `instructions_executed`
    // exceeds `total_instruction_limit`. This counter is used as an additional
    // safeguard to guarantee fast progress for the case when each slice does
    // not use all its available instructions.
    slices_left: i64,
}

impl State {
    fn new(
        instruction_limit_to_report: i64,
        total_instruction_limit: i64,
        max_slice_instruction_limit: i64,
    ) -> Self {
        let max_slice_instruction_limit = max_slice_instruction_limit.min(total_instruction_limit);

        let max_num_slices =
            (total_instruction_limit / max_slice_instruction_limit.max(1)).min(MAX_NUM_SLICES);

        // Since the number of slices is a secondary limit and just a safeguard
        // in addition to the primary limit of instructions, we can give it some
        // slack to ensure that it doesn't interfere in regular cases.
        let max_num_slices_with_slack = (2 * max_num_slices).clamp(4, MAX_NUM_SLICES);

        let result = Self {
            execution_status: ExecutionStatus::Running,
            instruction_limit_to_report,
            total_instruction_limit,
            max_slice_instruction_limit,
            slice_instruction_limit: max_slice_instruction_limit,
            instructions_executed: 0,
            slices_left: max_num_slices_with_slack,
        };
        result.check_invariants();
        result
    }

    fn check_invariants(&self) {
        if self.total_instructions_left() < 0 {
            assert_eq!(self.slice_instruction_limit, 0);
        } else {
            assert!(
                self.slice_instruction_limit <= self.total_instructions_left(),
                "slice instructions limit {} exceeds instructions left {} ",
                self.slice_instruction_limit,
                self.total_instructions_left()
            );
        }
        // Note that `self.instructions_executed` may exceed either of the
        // limits because Wasm execution does a best-effort detection of
        // out-of-instruction condition.
        assert!(self.instructions_executed >= 0);
    }

    /// Returns true if the current slice is sufficient to reach the total
    /// instruction limit.
    fn is_last_slice(&self) -> bool {
        self.slice_instruction_limit >= self.total_instructions_left() || self.slices_left <= 1
    }

    /// Computes the limit for the next slice taking into account
    /// the instructions remaining in the total limit and
    /// the instructions carried over from the current slice.
    fn next_slice_instruction_limit(&mut self, instruction_counter: i64) -> i64 {
        let newly_executed = self.newly_executed(instruction_counter);
        let carry_over = (newly_executed - self.slice_instruction_limit).max(0);
        (self.max_slice_instruction_limit - carry_over)
            .clamp(0, self.total_instructions_left().max(0))
    }

    /// Returns the number of instructions executed in the current slice.
    fn newly_executed(&self, instruction_counter: i64) -> i64 {
        // Normally the instruction counter does not exceed the instruction
        // limit. However, we cannot trust the instruction counter because it is
        // coming from Wasm execution, so we use saturating operations here to avoid
        // over-/underflows and invalid state.
        self.slice_instruction_limit
            .saturating_sub(instruction_counter)
            .max(0)
    }

    /// Updates the state to prepare for the next slice.
    fn update(&mut self, instruction_counter: i64) {
        self.instructions_executed = self
            .instructions_executed
            .saturating_add(self.newly_executed(instruction_counter));
        self.slice_instruction_limit = self.next_slice_instruction_limit(instruction_counter);
        self.slices_left -= 1;
        self.check_invariants();
    }

    /// The number of instructions remaining from the total limit.
    fn total_instructions_left(&self) -> i64 {
        // Both numbers are non-negative, so this cannot underflow.
        self.total_instruction_limit - self.instructions_executed
    }
}

// Provides support for pausing, resuming, and aborting execution.
// As input it gets the total and per-slice instruction limits.
// It assumes that there are two threads:
// - the execution thread (the sandbox execution thread),
// - the control thread (the sandbox IPC thread).
// The execution thread executes instructions and calls `try_pause()` and
// `wait_for_resume_or_abort()`.
// The control thread calls `resume()` or `abort()`.
#[derive(Clone)]
struct DeterministicTimeSlicing {
    state: Arc<Mutex<State>>,
    resumed_or_aborted: Arc<Condvar>,
}

impl DeterministicTimeSlicing {
    fn new(
        instruction_limit_to_report: i64,
        total_instruction_limit: i64,
        slice_instruction_limit: i64,
    ) -> Self {
        let state = State::new(
            instruction_limit_to_report,
            total_instruction_limit,
            slice_instruction_limit,
        );
        Self {
            state: Arc::new(Mutex::new(state)),
            resumed_or_aborted: Arc::new(Condvar::new()),
        }
    }

    // Transitions to state `Running` and wakes up the execution thread.
    // Precondition: execution is paused.
    fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.execution_status, ExecutionStatus::Paused);
        state.execution_status = ExecutionStatus::Running;
        self.resumed_or_aborted.notify_one();
    }

    // Transitions to state `Aborted` and wakes up the execution thread.
    // Precondition: execution is paused.
    fn abort(&self) {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.execution_status, ExecutionStatus::Paused);
        state.execution_status = ExecutionStatus::Aborted;
        self.resumed_or_aborted.notify_one();
    }

    // Given the current Wasm instruction counter the function either:
    // - transitions to `Paused` if it is possible to continue the execution in
    //   the next slice.
    // - or returns the `InstructionLimitExceeded` error.
    fn try_pause(&self, instruction_counter: i64) -> Result<SliceExecutionOutput, HypervisorError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.execution_status, ExecutionStatus::Running);
        if state.is_last_slice() {
            return Err(HypervisorError::InstructionLimitExceeded(
                NumInstructions::from(state.instruction_limit_to_report as u64),
            ));
        }

        let newly_executed = state.newly_executed(instruction_counter);
        if state.next_slice_instruction_limit(instruction_counter) == 0 {
            // If the next slice doesn't have any instructions left, then
            // execution will fail anyway, so we can return the error now.
            return Err(HypervisorError::SliceOverrun {
                instructions: NumInstructions::from(newly_executed as u64),
                limit: NumInstructions::from(state.max_slice_instruction_limit as u64),
            });
        }

        // At this point we know that the next slice will be able to run, so we
        // can commit the state changes and pause now.
        state.update(instruction_counter);
        state.execution_status = ExecutionStatus::Paused;
        Ok(SliceExecutionOutput {
            executed_instructions: NumInstructions::from(newly_executed as u64),
        })
    }

    // Performance improvement:
    // - The function is called from the execution thread when too many dirty
    //  pages are created during message execution.
    // - The function transitions to `Paused` if it is possible to continue the
    //   dirty page copying in the next slice.
    fn try_yield_for_dirty_memory_copy(
        &self,
        instruction_counter: i64,
    ) -> Result<SliceExecutionOutput, HypervisorError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.execution_status, ExecutionStatus::Running);
        // Get newly executed instructions.
        let executed_instructions =
            NumInstructions::from(state.newly_executed(instruction_counter) as u64);
        // Update the instruction counter such that the canister is charged the for executed instructions.
        state.update(instruction_counter);
        state.execution_status = ExecutionStatus::Paused;

        // This code path happens only during a longer execution which has triggered many dirty
        // pages. After the execution happened, we slice, ending the round so that the copying
        // of dirty pages can happen in a new round.
        // In the future we might consider adding an overhead for dirty pages copying also here.
        Ok(SliceExecutionOutput {
            executed_instructions,
        })
    }

    // Sleeps while the current execution state is `Paused`.
    // Returns the instruction limit for the next slice if execution was resumed.
    // Otherwise, returns an error that indicates that execution was aborted.
    fn wait_for_resume_or_abort(&self) -> Result<i64, HypervisorError> {
        let state = self.state.lock().unwrap();
        let state = self
            .resumed_or_aborted
            .wait_while(state, |state| {
                state.execution_status == ExecutionStatus::Paused
            })
            .unwrap();
        match state.execution_status {
            ExecutionStatus::Paused => {
                // This is really unreachable.
                unreachable!("Unexpected paused status after waiting for a condition variable")
            }
            ExecutionStatus::Running => Ok(state.slice_instruction_limit),
            ExecutionStatus::Aborted => Err(HypervisorError::Aborted),
        }
    }
}

// Represents a paused execution and allows the owner to resume or abort
// the execution.
pub struct PausedExecution {
    dts: DeterministicTimeSlicing,
}

impl PausedExecution {
    pub fn resume(self) {
        self.dts.resume();
    }

    pub fn abort(self) {
        self.dts.abort();
    }
}

// This callback is provided by the user of `DeterministicTimeSlicingHandler` to
// send `PausedExecution` to the thread that controls pausing and aborting.
pub type PauseCallback = dyn Fn(SliceExecutionOutput, PausedExecution) + 'static;

/// An implementation of `OutOfInstructionsHandler` that support
/// deterministic time slicing. As input it expects:
/// - the total instruction limit for all execution slices combined.
/// - the instruction limit per execution slice.
/// - a callback that takes `PausedExecution` and passes it on to another
///   thread that controls pausing and aborting of execution.
pub struct DeterministicTimeSlicingHandler {
    dts: DeterministicTimeSlicing,
    pause_callback: Box<PauseCallback>,
}

impl DeterministicTimeSlicingHandler {
    pub fn new<F>(
        total_instruction_limit_to_report: i64,
        total_instruction_limit: i64,
        slice_instruction_limit: i64,
        pause_callback: F,
    ) -> Self
    where
        F: Fn(SliceExecutionOutput, PausedExecution) + 'static,
    {
        Self {
            dts: DeterministicTimeSlicing::new(
                total_instruction_limit_to_report,
                total_instruction_limit,
                slice_instruction_limit,
            ),
            pause_callback: Box::new(pause_callback),
        }
    }
}

impl OutOfInstructionsHandler for DeterministicTimeSlicingHandler {
    fn out_of_instructions(&self, instruction_counter: i64) -> HypervisorResult<i64> {
        let slice = self.dts.try_pause(instruction_counter)?;
        let paused = PausedExecution {
            dts: self.dts.clone(),
        };
        (self.pause_callback)(slice, paused);
        self.dts.wait_for_resume_or_abort()
    }

    fn yield_for_dirty_memory_copy(&self, instruction_counter: i64) -> HypervisorResult<i64> {
        let slice = self
            .dts
            .try_yield_for_dirty_memory_copy(instruction_counter)?;
        let paused = PausedExecution {
            dts: self.dts.clone(),
        };
        (self.pause_callback)(slice, paused);
        self.dts.wait_for_resume_or_abort()
    }
}

#[cfg(test)]
mod tests;
