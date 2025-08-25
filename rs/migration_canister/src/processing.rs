//! This module contains the request processing methods.
//! They are scheduled every few seconds with a timer.
//! Each method processes a specific type of request, and it may
//! process several requests in sequence before terminating.

use std::iter::zip;

use crate::{
    canister_state::{
        requests::{insert_request, list_by, remove_request},
        MethodGuard,
    },
    external_interfaces::management::set_exclusive_controller,
    RequestState,
};
use futures::future::join_all;
use ic_cdk::println;

pub async fn process_all_accepted() {
    // This guard ensures this method runs only once at any given time.
    let Ok(_guard) = MethodGuard::new("accepted") else {
        return;
    };

    let mut tasks = vec![];
    let requests = list_by(|r| matches!(r, RequestState::Accepted { .. }));
    for request in requests.iter() {
        tasks.push(process_accepted(request.clone()));
    }
    let results = join_all(tasks).await;
    for (req, res) in zip(&requests, &results) {}
    // list_accepted()
    //     .into_iter()
    //     .map(|r| process_accepted_2(r))
    //     .map(ProcessingResult::transition)
    //     .collect::<_>();
}

async fn process_accepted(request: RequestState) -> ProcessingResult<(), String> {
    let RequestState::Accepted { request } = request else {
        println!("Error: list_accepted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // set controller of source
    let res = set_exclusive_controller(request.source).await;
    // if only we could implement `FromResidual` in stable Rust...
    if !res.is_success() {
        return res;
    }
    // set controller of target
    set_exclusive_controller(request.target).await
}

// TODO: dispatch all requests in parallel and join_all -> waiting times are bounded.
// bounded wait helps

// #[must_use]
// enum ProcessingResult {
//     Success {
//         old_state: RequestState,
//         next_state: RequestState,
//     },
//     NoProgress,
//     FatalFailure {
//         old_state: RequestState,
//         error_state: RequestState, /* TODO: or HistoryEntry */
//     },
// }

#[must_use]
pub enum ProcessingResult<S, F> {
    Success(S),
    NoProgress,
    FatalFailure(F),
}

impl<S, F> ProcessingResult<S, F> {
    pub fn map<T>(self, f: impl FnOnce(S) -> T) -> ProcessingResult<T, F> {
        match self {
            ProcessingResult::Success(x) => ProcessingResult::Success(f(x)),
            ProcessingResult::NoProgress => ProcessingResult::NoProgress,
            ProcessingResult::FatalFailure(x) => ProcessingResult::FatalFailure(x),
        }
    }

    pub fn map_failure<T>(self, f: impl FnOnce(F) -> T) -> ProcessingResult<S, T> {
        match self {
            ProcessingResult::Success(x) => ProcessingResult::Success(x),
            ProcessingResult::NoProgress => ProcessingResult::NoProgress,
            ProcessingResult::FatalFailure(x) => ProcessingResult::FatalFailure(f(x)),
        }
    }

    pub fn is_success(&self) -> bool {
        match self {
            ProcessingResult::Success(_) => true,
            _ => false,
        }
    }
    pub fn is_no_progress(&self) -> bool {
        match self {
            ProcessingResult::NoProgress => true,
            _ => false,
        }
    }
    pub fn is_fatal_failure(&self) -> bool {
        match self {
            ProcessingResult::FatalFailure(_) => true,
            _ => false,
        }
    }

    // fn transition(
    //     self,
    //     old_state: &RequestState,
    //     f: impl FnOnce(&RequestState, S) -> RequestState,
    //     g: impl FnOnce(&RequestState, F) -> RequestState,
    // ) {
    //     match self {
    //         ProcessingResult::Success(s) => {
    //             remove_request(old_state);
    //             insert_request(f(old_state, s));
    //         }
    //         ProcessingResult::NoProgress => {}
    //         ProcessingResult::FatalFailure(f) => {
    //             remove_request(&old_state);
    //             // TODO: history
    //         }
    //     }
    // }
}

/// Removes the old state from REQUESTS and inserts the new state in the correct
/// collection (REQUESTS or HISTORY).
impl ProcessingResult<RequestState, RequestState> {
    fn transition2(self, old_state: &RequestState) {
        match self {
            ProcessingResult::Success(new_state) => {
                remove_request(old_state);
                insert_request(new_state);
            }
            ProcessingResult::NoProgress => {}
            ProcessingResult::FatalFailure(fail_state) => {
                remove_request(old_state);
                // TODO:
            }
        }
    }
}

// impl ProcessingResult {
//     /// Removes the old state from REQUESTS and inserts the new state in the correct
//     /// collection (REQUESTS or HISTORY).
//     fn transition(self) {
//         match self {
//             ProcessingResult::Success {
//                 old_state,
//                 next_state,
//             } => {
//                 remove_request(&old_state);
//                 insert_request(next_state);
//             }
//             ProcessingResult::NoProgress => {}
//             ProcessingResult::FatalFailure {
//                 old_state,
//                 error_state,
//             } => {
//                 remove_request(&old_state);
//                 // TODO: history
//             }
//         }
//     }
// }
