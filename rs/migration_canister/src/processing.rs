//! This module contains the request processing methods.
//! They are scheduled every few seconds with a timer.
//! Each method processes a specific type of request, and it may
//! process several requests in sequence before terminating.

use crate::{
    canister_state::requests::{
        insert_request, list_accepted, list_controllers_changed, list_renamed_target, list_stopped,
        remove_request,
    },
    Request, RequestState,
};
use ic_cdk::println;

pub fn process_accepted() {
    list_accepted()
        .into_iter()
        .map(|r| process_accepted_2(r))
        .map(ProcessingResult::transition)
        .collect();
}

fn process_accepted_2(request: RequestState) -> ProcessingResult {
    let RequestState::Accepted { request } = request else {
        println!("Error: list_accepted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // TODO
    todo!()
}

pub fn process_controllers_changed() {
    for request in list_controllers_changed().into_iter() {
        let RequestState::ControllersChanged { request } = request else {
            println!("Error: list_controllers_changed returned bad variant");
            continue;
        };
        // TODO
    }
}

pub fn process_stopped() {
    for request in list_stopped().into_iter() {
        let RequestState::StoppedAndReady {
            request,
            stopped_since,
            canister_version,
            canister_history_total_num,
        } = request
        else {
            println!("Error: list_stopped returned bad variant");
            continue;
        };
        // TODO
    }
}

pub fn process_renamed() {
    for request in list_renamed_target().into_iter() {
        let RequestState::RenamedTarget {
            request,
            stopped_since,
        } = request
        else {
            println!("Error: list_renamed_target returned bad variant");
            continue;
        };
        // TODO
    }
}

// - fails with Failstate
// - fails but can be repeated: nothing to do
// - succeed with successor state
/// None: Failed but can be retried. Nothing to do.
/// Some(Ok(successor)): Succeeded, need to write successor to REQUESTS.
/// Some(Err(failstate)): Failed fatally, need to write failstate to HISTORY.

#[must_use]
enum ProcessingResult {
    Success {
        old_state: RequestState,
        next_state: RequestState,
    },
    NoProgress,
    FatalFailure {
        old_state: RequestState,
        error_state: RequestState, /* TODO: or HistoryEntry */
    },
}

impl ProcessingResult {
    /// Removes the old state from REQUESTS and inserts the new state in the correct
    /// collection (REQUESTS or HISTORY).
    fn transition(self) {
        match self {
            ProcessingResult::Success {
                old_state,
                next_state,
            } => {
                remove_request(&old_state);
                insert_request(next_state);
            }
            ProcessingResult::NoProgress => {}
            ProcessingResult::FatalFailure {
                old_state,
                error_state,
            } => {
                remove_request(&old_state);
                // TODO: history
            }
        }
    }
}
