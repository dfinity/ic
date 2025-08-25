//! This module contains the request processing methods.
//! They are scheduled every few seconds with a timer.
//! Each method processes a specific type of request, and it may
//! process several requests in sequence before terminating.

use std::{future::Future, iter::zip};

use crate::{
    canister_state::{
        requests::{insert_request, list_by, remove_request},
        MethodGuard,
    },
    external_interfaces::management::set_exclusive_controller,
    Event, RequestState,
};
use futures::future::join_all;
use ic_cdk::println;

pub async fn process_all_generic<F>(
    tag: &str,
    predicate: impl Fn(&RequestState) -> bool,
    processor: impl Fn(RequestState) -> F,
) where
    F: Future<Output = ProcessingResult<RequestState, RequestState>>,
{
    // Ensures this method runs only once at any given time.
    let Ok(_guard) = MethodGuard::new(tag) else {
        return;
    };
    let mut tasks = vec![];
    let requests = list_by(predicate);
    for request in requests.iter() {
        tasks.push(processor(request.clone()));
    }
    let results = join_all(tasks).await;
    for (req, res) in zip(requests, results) {
        res.transition(req);
    }
}

/// Accepts an `Accepted` request, returns `SourceControllersChanged` or `Failed`.
pub async fn process_accepted(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::Accepted { request } = request else {
        println!("Error: list_accepted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // set controller of source
    set_exclusive_controller(request.source)
        .await
        .map_success(|_| RequestState::SourceControllersChanged {
            request: request.clone(),
        })
        .map_failure(|reason| RequestState::Failed { request, reason })
}

pub async fn process_all_failed() {
    let Ok(_guard) = MethodGuard::new("failed") else {
        return;
    };
    let mut tasks = vec![];
    let requests = list_by(|r| matches!(r, RequestState::Failed { .. }));
    for request in requests.iter() {
        tasks.push(process_failed(request.clone()));
    }
    let results = join_all(tasks).await;
    for (req, res) in zip(requests, results) {
        res.transition(req);
    }
}

/// Accepts a `Failed` request, returns `Event::Failed` or must be retried.
async fn process_failed(request: RequestState) -> ProcessingResult<Event, ()> {
    let RequestState::Failed { request, reason } = request else {
        println!("Error: list_failed returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // 1. If source controllers are the original controllers, or we are NOT controllers of source any more,
    //    then we continue. Otherwise, we set the source controllers to the original. If we fail, return NoProgress.
    // TODO

    // 2. Same for target
    // TODO

    ProcessingResult::NoProgress
}

#[must_use]
pub enum ProcessingResult<S, F> {
    Success(S),
    NoProgress,
    FatalFailure(F),
}

impl<S, F> ProcessingResult<S, F> {
    pub fn map_success<T>(self, f: impl FnOnce(S) -> T) -> ProcessingResult<T, F> {
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
}

/// Removes the old state from REQUESTS and inserts the new state in the correct
/// collection (REQUESTS or HISTORY).
impl ProcessingResult<RequestState, RequestState> {
    fn transition(self, old_state: RequestState) {
        match self {
            ProcessingResult::Success(new_state) => {
                remove_request(&old_state);
                insert_request(new_state);
            }
            ProcessingResult::NoProgress => {}
            // If the transition failed fatally with a RequestState::Failure, we have to process it.
            ProcessingResult::FatalFailure(fail_state) => {
                remove_request(&old_state);
                insert_request(fail_state);
            }
        }
    }
}

// Processing a `RequestState::Failure` successfully results in an `Event::Failed`.
impl ProcessingResult<Event, ()> {
    fn transition(self, old_state: RequestState) {
        match self {
            ProcessingResult::Success(event) => {
                // Cleanup successful.
                remove_request(&old_state);
                // TODO: insert_event(event);
            }
            ProcessingResult::NoProgress => {}
            ProcessingResult::FatalFailure(_) => {
                println!("Error: Processing failed states must not fail, should return `NoProgress` instead.");
            }
        }
    }
}
