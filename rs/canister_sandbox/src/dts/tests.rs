use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use ic_interfaces::execution_environment::{HypervisorError, OutOfInstructionsHandler};
use ic_types::NumInstructions;

use crate::dts::MAX_NUM_SLICES;

use super::{DeterministicTimeSlicingHandler, PausedExecution};

#[test]
fn dts_state_updates() {
    let mut state = super::State::new(2500, 2500, 1000);
    assert_eq!(state.slice_instruction_limit, 1000);
    assert_eq!(state.instructions_executed, 0);
    assert_eq!(state.total_instructions_left(), 2500);
    assert!(!state.is_last_slice());
    state.update(0);
    assert_eq!(state.slice_instruction_limit, 1000);
    assert_eq!(state.instructions_executed, 1000);
    assert_eq!(state.total_instructions_left(), 1500);
    assert!(!state.is_last_slice());
    state.update(0);
    assert_eq!(state.slice_instruction_limit, 500);
    assert_eq!(state.instructions_executed, 2000);
    assert_eq!(state.total_instructions_left(), 500);
    assert!(state.is_last_slice());
    // This slice reports `-500` for its instruction counter, as if a system
    // API call had charged more than the 500 instructions left in the total
    // budget. `instructions_executed` is capped at `total_instruction_limit`
    // (2500) instead of overshooting to 3000, so `total_instructions_left()`
    // bottoms out at 0 instead of going negative.
    state.update(-500);
    assert_eq!(state.slice_instruction_limit, 0);
    assert_eq!(state.instructions_executed, 2500);
    assert_eq!(state.total_instructions_left(), 0);
    assert!(state.is_last_slice());
}

#[test]
fn dts_state_updates_invalid_instructions() {
    let mut state = super::State::new(2500, 2500, 2000);
    assert_eq!(state.slice_instruction_limit, 2000);
    assert_eq!(state.instructions_executed, 0);
    assert_eq!(state.total_instructions_left(), 2500);
    assert!(!state.is_last_slice());
    state.update(4000);
    assert_eq!(state.slice_instruction_limit, 2000);
    assert_eq!(state.instructions_executed, 0);
    assert_eq!(state.total_instructions_left(), 2500);
    assert!(!state.is_last_slice());
}

#[test]
fn dts_state_updates_saturating() {
    let mut state = super::State::new(2500, 2500, 2000);
    assert_eq!(state.slice_instruction_limit, 2000);
    assert_eq!(state.instructions_executed, 0);
    assert_eq!(state.total_instructions_left(), 2500);
    assert!(!state.is_last_slice());
    // `instruction_counter` being `i64::MIN` models a system API call that
    // charged a huge fee before failing with an out-of-instructions error.
    // `newly_executed` saturates during the subtraction, but is then capped
    // at the 2500 instructions left in the total budget instead of leaking
    // out as `i64::MAX`, so `instructions_executed` / `total_instructions_left`
    // stay consistent with the total instruction budget.
    state.update(i64::MIN);
    assert_eq!(state.slice_instruction_limit, 0);
    assert_eq!(state.instructions_executed, 2500);
    assert_eq!(state.total_instructions_left(), 0);
    assert!(state.is_last_slice());
}

#[test]
fn dts_max_num_slices() {
    let mut state = super::State::new(1_000_000, 1_000_000, 100);
    let mut iterations = 0;
    while !state.is_last_slice() {
        state.update(99);
        iterations += 1;
    }
    assert!(iterations <= MAX_NUM_SLICES);
}

#[test]
fn pause_and_resume_works() {
    let (tx, rx): (Sender<PausedExecution>, Receiver<PausedExecution>) = mpsc::channel();
    let total_instruction_limit = 2500;
    let dts = DeterministicTimeSlicingHandler::new(
        total_instruction_limit,
        total_instruction_limit,
        1000,
        move |_slice, paused| {
            tx.send(paused).unwrap();
        },
    );
    let control_thread = thread::spawn(move || {
        for _ in 0..2 {
            let paused_execution = rx.recv().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
            paused_execution.resume();
        }
    });
    // Slice 1: executes 1000 instructions before calling `out_of_instructions()`.
    let next_slice_limit = dts.out_of_instructions(0).unwrap();
    assert_eq!(1000, next_slice_limit);
    // Slice 2: executes 1000 instructions before calling `out_of_instructions()`.
    let next_slice_limit = dts.out_of_instructions(0).unwrap();
    assert_eq!(500, next_slice_limit);
    // Slice 3: executes 500 instructions before calling `out_of_instructions()`.
    let error = dts.out_of_instructions(0);
    assert_eq!(
        error,
        Err(HypervisorError::InstructionLimitExceeded(
            NumInstructions::from(total_instruction_limit as u64)
        ))
    );
    drop(dts);
    control_thread.join().unwrap();
}

#[test]
fn early_exit_if_slice_does_not_any_instructions_left() {
    let (tx, rx): (Sender<PausedExecution>, Receiver<PausedExecution>) = mpsc::channel();
    let dts = DeterministicTimeSlicingHandler::new(10_000, 10_000, 1_000, move |_slice, paused| {
        tx.send(paused).unwrap();
    });
    let control_thread = thread::spawn(move || {
        let paused_execution = rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        paused_execution.resume();
    });
    // Slice 1: executes 1500 instructions before calling `out_of_instructions()`.
    let new_slice_limit = dts.out_of_instructions(-500).unwrap();
    assert_eq!(500, new_slice_limit);
    // Slice 2: executes 1500 instructions before calling `out_of_instructions()`
    // and fails because the next slice wouldn't have any slice instructions left.
    let error = dts.out_of_instructions(-1000);
    assert_eq!(
        error,
        Err(HypervisorError::SliceOverrun {
            instructions: NumInstructions::from(1500),
            limit: NumInstructions::from(1000)
        })
    );
    drop(dts);
    control_thread.join().unwrap();
}

#[test]
fn charge_past_message_budget_fails_instead_of_pausing() {
    let dts = super::DeterministicTimeSlicing::new(2500, 2500, 1000);

    // The first slice uses its full limit, leaving 1500 instructions for the
    // message. A later system API charge can take the next slice's counter
    // below zero even when the charge itself passes the API's bounds checks.
    assert_eq!(
        dts.try_pause(0).unwrap().executed_instructions,
        NumInstructions::from(1000)
    );
    dts.resume();

    // This slice charges 1600 instructions, 100 more than the message has
    // left. Without the cap in State::newly_executed, DTS incorrectly reports
    // a paused slice, even though the message has exhausted its budget.
    assert_eq!(
        dts.try_pause(-600),
        Err(HypervisorError::InstructionLimitExceeded(
            NumInstructions::from(2500)
        ))
    );
}

#[test]
fn exhausting_message_budget_within_maximum_slice_limit_fails_with_instruction_limit_exceeded() {
    let dts = super::DeterministicTimeSlicing::new(2500, 2500, 1000);

    // The first slice overruns its limit by 800 instructions, leaving 700
    // instructions for the message and 200 instructions for the next slice.
    assert_eq!(
        dts.try_pause(-800).unwrap().executed_instructions,
        NumInstructions::from(1800)
    );
    dts.resume();

    // This slice executes the remaining 700 instructions of the message,
    // exceeding the current slice limit of 200 but staying below the maximum
    // slice limit of 1000. Execution fails because the message budget is exhausted.
    assert_eq!(
        dts.try_pause(-500),
        Err(HypervisorError::InstructionLimitExceeded(
            NumInstructions::from(2500)
        ))
    );
}

#[test]
fn invalid_instructions() {
    let (tx, rx): (Sender<PausedExecution>, Receiver<PausedExecution>) = mpsc::channel();
    let dts = DeterministicTimeSlicingHandler::new(2500, 2500, 1000, move |_slice, paused| {
        tx.send(paused).unwrap();
    });
    let control_thread = thread::spawn(move || {
        for _ in 0..2 {
            let paused_execution = rx.recv().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
            paused_execution.resume();
        }
    });
    // Slice 1: executes 1000 instructions before calling `out_of_instructions()`.
    let new_instructions = dts.out_of_instructions(0).unwrap();
    assert_eq!(1000, new_instructions);
    // Slice 2: executes 0 instructions before calling `out_of_instructions()`.
    let new_instructions = dts.out_of_instructions(i64::MAX).unwrap();
    assert_eq!(1000, new_instructions);
    // Slice 3: charges more than i64::MAX instructions before calling
    // `out_of_instructions()`, as if a system API call charged a huge fee
    // before failing. `newly_executed` is capped at the 1500 instructions
    // left in the total budget (2500 - 1000 executed so far), which exhausts
    // the total budget.
    let error = dts.out_of_instructions(i64::MIN);
    assert_eq!(
        error,
        Err(HypervisorError::InstructionLimitExceeded(
            NumInstructions::from(2500)
        ))
    );
    drop(dts);
    control_thread.join().unwrap();
}

#[test]
fn max_num_slices() {
    let (tx, rx): (Sender<PausedExecution>, Receiver<PausedExecution>) = mpsc::channel();
    let total_instruction_limit = 1000000;
    let dts = DeterministicTimeSlicingHandler::new(
        total_instruction_limit,
        total_instruction_limit,
        100,
        move |_slice, paused| {
            tx.send(paused).unwrap();
        },
    );
    let control_thread = thread::spawn(move || {
        for _ in 0..MAX_NUM_SLICES - 1 {
            let paused_execution = rx.recv().unwrap();
            paused_execution.resume();
        }
    });

    let mut result = Ok(0);
    for i in 0..MAX_NUM_SLICES {
        result = dts.out_of_instructions(99);
        if i < MAX_NUM_SLICES - 1 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
    assert_eq!(
        result,
        Err(HypervisorError::InstructionLimitExceeded(
            NumInstructions::from(total_instruction_limit as u64)
        ))
    );
    drop(dts);
    control_thread.join().unwrap();
}
