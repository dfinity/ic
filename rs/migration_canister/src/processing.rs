//! This module contains the request processing methods.
//! They are scheduled every few seconds with a timer.
//! Each method processes a specific type of request, and it may
//! process several requests in sequence before terminating.

use crate::{
    canister_state::requests::{insert_request, list_by, remove_request},
    RequestState,
};
use ic_cdk::println;

pub fn process_all_accepted() {
    // only one of this method must run at the same time.
    // lock
    list_by(|r| matches!(r, RequestState::Accepted { .. }));

    // list_accepted()
    //     .into_iter()
    //     .map(|r| process_accepted_2(r))
    //     .map(ProcessingResult::transition)
    //     .collect::<_>();
}

pub fn process_accepted() {
    //TODO
}

fn process_accepted_2(request: RequestState) -> ProcessingResult {
    let RequestState::Accepted { request } = request else {
        println!("Error: list_accepted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // TODO
    todo!()
}

// TODO: dispatch all requests in parallel and join_all -> waiting times are bounded.
// bounded wait helps

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
