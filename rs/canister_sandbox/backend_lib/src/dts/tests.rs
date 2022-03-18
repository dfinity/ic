use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use ic_interfaces::execution_environment::{HypervisorError, OutOfInstructionsHandler};
use ic_types::NumInstructions;

use super::{DeterministicTimeSlicingHandler, PausedExecution};

#[test]
fn test_pause_and_resume() {
    let (tx, rx): (Sender<PausedExecution>, Receiver<PausedExecution>) = mpsc::channel();
    let dts = DeterministicTimeSlicingHandler::new(
        NumInstructions::from(2500),
        NumInstructions::from(1000),
        move |paused| {
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
    let new_instructions = dts.out_of_instructions(NumInstructions::from(0)).unwrap();
    assert_eq!(1000, new_instructions.get());
    // Slice 2: executes 1000 instructions before calling `out_of_instructions()`.
    let new_instructions = dts.out_of_instructions(NumInstructions::from(0)).unwrap();
    assert_eq!(500, new_instructions.get());
    // Slice 3: executes 500 instructions before calling `out_of_instructions()`.
    let error = dts.out_of_instructions(NumInstructions::from(0));
    assert_eq!(error, Err(HypervisorError::InstructionLimitExceeded));
    drop(dts);
    control_thread.join().unwrap();
}
