use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, OutOfInstructionsHandler,
};
use ic_types::NumInstructions;
use std::sync::{Arc, Condvar, Mutex};

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
    // The instruction limit for all slices combined.
    total_instruction_limit: NumInstructions,
    // The instruction limit for the next execution slice.
    // Initially it is given as input and stays constant for
    // all slices except maybe the last one, which may have
    // a smaller limit to ensure that the total limit is not
    // exceeded.
    slice_instruction_limit: NumInstructions,
    // The number of instructions that have been executed so far.
    // Invariant: it does not exceed `total_instruction_limit`.
    instructions_executed: NumInstructions,
}

impl State {
    fn new(
        total_instruction_limit: NumInstructions,
        slice_instruction_limit: NumInstructions,
    ) -> Self {
        assert!(slice_instruction_limit <= total_instruction_limit);
        Self {
            execution_status: ExecutionStatus::Running,
            total_instruction_limit,
            slice_instruction_limit,
            instructions_executed: NumInstructions::from(0),
        }
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
        total_instruction_limit: NumInstructions,
        slice_instruction_limit: NumInstructions,
    ) -> Self {
        let state = State::new(total_instruction_limit, slice_instruction_limit);
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

    // Given the number of instructions left in the current slice, the function:
    // - either transitions to `Paused` after increasing `instructions_executed`
    //   and setting the limit for the next slice.
    // - or returns the `InstructionLimitExceeded` error.
    fn try_pause(&self, instructions_left: NumInstructions) -> Result<(), HypervisorError> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.execution_status, ExecutionStatus::Running);
        assert!(
            instructions_left <= state.slice_instruction_limit,
            "The precondition of the DTS handler is broken: {} <= {}",
            instructions_left,
            state.slice_instruction_limit,
        );
        // The main invariant of the DTS handler.
        assert!(
            state.instructions_executed + state.slice_instruction_limit
                <= state.total_instruction_limit,
            "The main invariant of the DTS handler is broken: {} + {} <= {}",
            state.instructions_executed,
            state.slice_instruction_limit,
            state.total_instruction_limit
        );
        let newly_executed_instructions = state.slice_instruction_limit - instructions_left;
        if newly_executed_instructions.get() == 0 {
            // No progress in executing instructions. Return an early error.
            return Err(HypervisorError::InstructionLimitExceeded);
        }
        if state.instructions_executed + state.slice_instruction_limit
            == state.total_instruction_limit
        {
            // This was the last slice.
            return Err(HypervisorError::InstructionLimitExceeded);
        }
        state.instructions_executed += newly_executed_instructions;
        // Maintain the main invariant.
        state.slice_instruction_limit = state
            .slice_instruction_limit
            .min(state.total_instruction_limit - state.instructions_executed);
        state.execution_status = ExecutionStatus::Paused;
        Ok(())
    }

    // Sleeps while the current execution state is `Paused`.
    // Returns the instruction limit for the next slice if execution was resumed.
    // Otherwise, returns an error that indicates that execution was aborted.
    fn wait_for_resume_or_abort(&self) -> Result<NumInstructions, HypervisorError> {
        let state = self.state.lock().unwrap();
        let state = self
            .resumed_or_aborted
            .wait_while(state, |state| {
                state.execution_status == ExecutionStatus::Paused
            })
            .unwrap();
        assert!(
            state.instructions_executed + state.slice_instruction_limit
                <= state.total_instruction_limit
        );
        match state.execution_status {
            ExecutionStatus::Paused => {
                // This is really unreachable.
                unreachable!("Unexpected paused status after waiting for a condition variable")
            }
            ExecutionStatus::Running => Ok(state.slice_instruction_limit),
            ExecutionStatus::Aborted => {
                // TODO(EXC-864): Implement aborting of execution by return a new "abort" error here.
                unimplemented!()
            }
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

    // TODO(EXC-864): Implement aborting of execution.
    #[allow(dead_code)]
    pub fn abort(self) {
        self.dts.abort();
    }
}

// This callback is provided by the user of `DeterministicTimeSlicingHandler` to
// send `PausedExecution` to the thread that controls pausing and aborting.
pub type PauseCallback = dyn Fn(PausedExecution) + 'static;

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
        total_instruction_limit: NumInstructions,
        slice_instruction_limit: NumInstructions,
        pause_callback: F,
    ) -> Self
    where
        F: Fn(PausedExecution) + 'static,
    {
        Self {
            dts: DeterministicTimeSlicing::new(total_instruction_limit, slice_instruction_limit),
            pause_callback: Box::new(pause_callback),
        }
    }
}

impl OutOfInstructionsHandler for DeterministicTimeSlicingHandler {
    fn out_of_instructions(
        &self,
        instructions_left: NumInstructions,
    ) -> HypervisorResult<NumInstructions> {
        self.dts.try_pause(instructions_left)?;
        (self.pause_callback)(PausedExecution {
            dts: self.dts.clone(),
        });
        self.dts.wait_for_resume_or_abort()
    }
}

#[cfg(test)]
mod tests;
