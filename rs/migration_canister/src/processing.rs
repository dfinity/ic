//! This module contains the request processing methods.
//! They are scheduled every few seconds with a timer.
//! Each method processes a specific type of request, and may
//! process several requests concurrently.

use crate::{
    CYCLES_COST_PER_MIGRATION, EventType, RecoveryState, RequestState, ValidationError,
    canister_state::{
        MethodGuard,
        events::insert_event,
        requests::{insert_request, list_by, remove_request},
    },
    external_interfaces::{
        management::{
            CanisterStatusType, assert_no_snapshots, canister_status, delete_canister,
            get_canister_info, get_registry_version, rename_canister, set_exclusive_controller,
            set_original_controllers,
        },
        registry::migrate_canister,
    },
};
use candid::Principal;
use futures::future::join_all;
use ic_cdk::{
    api::{canister_self, time},
    println,
};
use std::{future::Future, iter::zip};

/// Given a lock tag, a filter predicate on `RequestState` and a processor function,
/// invokes the processor on all requests in the given state concurrently and
/// transitions the result into either the next state, an error or a retry.
pub async fn process_all_by_predicate<F>(
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
    if requests.is_empty() {
        return;
    }
    println!(
        "Entering `{}` with {} pending requests",
        tag,
        requests.len()
    );
    for request in requests.iter() {
        tasks.push(processor(request.clone()));
    }
    let results = join_all(tasks).await;
    let mut success_counter = 0;
    for (req, res) in zip(requests, results) {
        if res.is_success() {
            success_counter += 1;
        }
        res.transition(req);
    }
    println!(
        "Exiting `{}` with {} successful transitions.",
        tag, success_counter
    );
}

/// Accepts an `Accepted` request, returns `ControllersChanged` on success.
/// This function is an exception in that it tries to make _two_ effectful calls.
pub async fn process_accepted(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::Accepted { request } = request else {
        println!("Error: list_by Accepted returned bad variant");
        return ProcessingResult::NoProgress;
    };

    // Set controller of source
    let res = set_exclusive_controller(request.source)
        .await
        .map_success(|_| RequestState::ControllersChanged {
            request: request.clone(),
        })
        .map_failure(|reason| RequestState::Failed {
            request: request.clone(),
            recovery_state: RecoveryState::done(),
            reason,
        });
    if !res.is_success() {
        return res;
    }

    // Set controller of target
    set_exclusive_controller(request.target)
        .await
        .map_success(|_| RequestState::ControllersChanged {
            request: request.clone(),
        })
        .map_failure(|reason| RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_source(),
            reason,
        })
}

pub async fn process_controllers_changed(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::ControllersChanged { request } = request else {
        println!("Error: list_by ControllersChanged returned bad variant");
        return ProcessingResult::NoProgress;
    };

    // These checks are repeated because the canisters may have changed since validation:
    let ProcessingResult::Success(source_status) = canister_status(request.source).await else {
        return ProcessingResult::NoProgress;
    };
    if source_status.status != CanisterStatusType::Stopped {
        return ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_both(),
            reason: "Source is not stopped.".to_string(),
        });
    }
    if !source_status.ready_for_migration {
        return ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_both(),
            reason: "Source is not ready for migration.".to_string(),
        });
    }
    let canister_version = source_status.version;
    if canister_version > u64::MAX / 2 {
        return ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_both(),
            reason: "Source version is too large.".to_string(),
        });
    }

    let ProcessingResult::Success(target_status) = canister_status(request.target).await else {
        return ProcessingResult::NoProgress;
    };
    if target_status.status != CanisterStatusType::Stopped {
        return ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_both(),
            reason: "Target is not stopped.".to_string(),
        });
    }
    match assert_no_snapshots(request.target).await {
        ProcessingResult::Success(_) => {}
        ProcessingResult::NoProgress => return ProcessingResult::NoProgress,
        ProcessingResult::FatalFailure(_) => {
            return ProcessingResult::FatalFailure(RequestState::Failed {
                request,
                recovery_state: RecoveryState::restore_both(),
                reason: "Target has snapshots.".to_string(),
            });
        }
    }

    if source_status.cycles < CYCLES_COST_PER_MIGRATION {
        return ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state: RecoveryState::restore_both(),
            reason: format!(
                "Source does not have sufficient cycles: {} < {}.",
                source_status.cycles, CYCLES_COST_PER_MIGRATION
            ),
        });
    }

    // Determine history length of source
    get_canister_info(request.source)
        .await
        .map_success(|canister_info_result| RequestState::StoppedAndReady {
            request,
            stopped_since: time(),
            canister_version,
            canister_history_total_num: canister_info_result.total_num_changes,
        })
        .or_retry()
}

pub async fn process_stopped(
    request: RequestState,
) -> ProcessingResult<
    RequestState,
    RequestState, /* Should be `Infallible` but we want `transition` to be available */
> {
    let RequestState::StoppedAndReady {
        request,
        stopped_since,
        canister_version,
        canister_history_total_num,
    } = request
    else {
        println!("Error: list_by StoppedAndReady returned bad variant");
        return ProcessingResult::NoProgress;
    };
    rename_canister(
        request.source,
        canister_version,
        request.target,
        request.target_subnet,
        canister_history_total_num,
        request.caller,
    )
    .await
    .map_success(|_| RequestState::RenamedTarget {
        request,
        stopped_since,
    })
    .or_retry()
}

pub async fn process_renamed(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::RenamedTarget {
        request,
        stopped_since,
    } = request
    else {
        println!("Error: list_by RenamedTarget returned bad variant");
        return ProcessingResult::NoProgress;
    };

    migrate_canister(request.source, request.target_subnet)
        .await
        .map_success(|registry_version| RequestState::UpdatedRoutingTable {
            request,
            stopped_since,
            registry_version,
        })
        .or_retry()
}

pub async fn process_updated(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::UpdatedRoutingTable {
        request,
        stopped_since,
        registry_version,
    } = request
    else {
        println!("Error: list_by UpdatedRoutingTable returned bad variant");
        return ProcessingResult::NoProgress;
    };
    // call both subnets
    let ProcessingResult::Success(source_subnet_version) =
        get_registry_version(request.source_subnet).await
    else {
        return ProcessingResult::NoProgress;
    };
    let ProcessingResult::Success(target_subnet_version) =
        get_registry_version(request.target_subnet).await
    else {
        return ProcessingResult::NoProgress;
    };
    if source_subnet_version < registry_version || target_subnet_version < registry_version {
        return ProcessingResult::NoProgress;
    }
    ProcessingResult::Success(RequestState::RoutingTableChangeAccepted {
        request,
        stopped_since,
    })
}

pub async fn process_routing_table(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::RoutingTableChangeAccepted {
        request,
        stopped_since,
    } = request
    else {
        println!("Error: list_by RoutingTableChangeAccepted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    let ProcessingResult::Success(()) =
        delete_canister(request.source, request.source_subnet).await
    else {
        return ProcessingResult::NoProgress;
    };
    ProcessingResult::Success(RequestState::SourceDeleted {
        request,
        stopped_since,
    })
}

pub async fn process_source_deleted(
    request: RequestState,
) -> ProcessingResult<RequestState, RequestState> {
    let RequestState::SourceDeleted {
        request,
        stopped_since,
    } = request
    else {
        println!("Error: list_by SourceDeleted returned bad variant");
        return ProcessingResult::NoProgress;
    };
    if time().saturating_sub(stopped_since) < 5 * 60 * 1_000_000_000 {
        return ProcessingResult::NoProgress;
    }
    // restore controllers of target
    let controllers = request
        .source_original_controllers
        .iter()
        .filter(|x| **x != canister_self())
        .cloned()
        .collect::<Vec<Principal>>();
    let ProcessingResult::Success(()) =
        set_original_controllers(request.source, controllers, request.target_subnet).await
    else {
        return ProcessingResult::NoProgress;
    };
    ProcessingResult::Success(RequestState::RestoredControllers { request })
}

// ----------------------------------------------------------------------------
pub async fn process_all_failed() {
    let Ok(_guard) = MethodGuard::new("failed") else {
        return;
    };
    let mut tasks = vec![];
    let requests = list_by(|r| matches!(r, RequestState::Failed { .. }));
    if requests.is_empty() {
        return;
    }
    println!("Entering `failed` with {} pending requests", requests.len());
    for request in requests.iter() {
        tasks.push(process_failed(request.clone()));
    }
    let results = join_all(tasks).await;
    let mut success_counter = 0;
    for (req, res) in zip(requests, results) {
        if res.is_success() {
            success_counter += 1;
        }
        res.transition(req);
    }
    println!(
        "Exiting `failed` with {} successful transitions.",
        success_counter
    );
}

/// Accepts a `Failed` request, returns `EventType::Failed` or
/// `RequestState::Failed` with updated recovery state.
async fn process_failed(request: RequestState) -> ProcessingResult<EventType, RequestState> {
    let RequestState::Failed {
        request,
        mut recovery_state,
        reason,
    } = request
    else {
        println!("Error: list_failed returned bad variant");
        return ProcessingResult::NoProgress;
    };

    if recovery_state.restore_source_controllers {
        let res1 = set_original_controllers(
            request.source,
            request.source_original_controllers.clone(),
            request.source_subnet,
        )
        .await;
        match res1 {
            ProcessingResult::Success(_) => {
                recovery_state.restore_source_controllers = false;
            }
            ProcessingResult::NoProgress => println!(
                "Error: no progress when restoring controllers of canister {}",
                request.source
            ),
            ProcessingResult::FatalFailure(ref reason) => println!("Error: {}", reason),
        };
    }

    if recovery_state.restore_target_controllers {
        let res2 = set_original_controllers(
            request.target,
            request.target_original_controllers.clone(),
            request.target_subnet,
        )
        .await;
        match res2 {
            ProcessingResult::Success(_) => {
                recovery_state.restore_target_controllers = false;
            }
            ProcessingResult::NoProgress => println!(
                "Error: no progress when restoring controllers of canister {}",
                request.target
            ),
            ProcessingResult::FatalFailure(ref reason) => println!("Error: {}", reason),
        };
    }

    if recovery_state.is_done() {
        ProcessingResult::Success(EventType::Failed { request, reason })
    } else {
        ProcessingResult::FatalFailure(RequestState::Failed {
            request,
            recovery_state,
            reason,
        })
    }
}

pub async fn process_all_succeeded() {
    let Ok(_guard) = MethodGuard::new("succeeded") else {
        return;
    };
    let requests = list_by(|r| matches!(r, RequestState::RestoredControllers { .. }));
    for request in requests.into_iter() {
        remove_request(&request);
        if let RequestState::RestoredControllers { request } = request {
            let event = EventType::Succeeded { request };
            insert_event(event);
        }
    }
}

#[must_use]
pub enum ProcessingResult<S, F> {
    Success(S),
    NoProgress,
    FatalFailure(F),
}

#[allow(dead_code)]
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
        matches!(self, ProcessingResult::Success(_))
    }
    pub fn is_no_progress(&self) -> bool {
        matches!(self, ProcessingResult::NoProgress)
    }
    pub fn is_fatal_failure(&self) -> bool {
        matches!(self, ProcessingResult::FatalFailure(_))
    }
}

impl<S, F> ProcessingResult<S, F>
where
    F: std::fmt::Display,
{
    /// Turns any `FatalFailure` into a `NoProgress`.
    ///
    /// Use for results of infallible calls to ensure retrying in the presence of bugs.
    pub fn or_retry<T>(self) -> ProcessingResult<S, T> {
        match self {
            ProcessingResult::Success(x) => ProcessingResult::Success(x),
            ProcessingResult::NoProgress => ProcessingResult::NoProgress,
            ProcessingResult::FatalFailure(f) => {
                println!("Unreachable: Ignore failure {} and retry.", f);
                ProcessingResult::NoProgress
            }
        }
    }
}

impl<S> ProcessingResult<S, ValidationError> {
    /// Use during validation only, where `NoProgress` should lead to an error.
    pub fn into_result(self, reason: &str) -> Result<S, ValidationError> {
        match self {
            ProcessingResult::Success(s) => Ok(s),
            ProcessingResult::NoProgress => Err(ValidationError::CallFailed {
                reason: reason.to_string(),
            }),
            ProcessingResult::FatalFailure(e) => Err(e),
        }
    }
}

/// Removes the old state from REQUESTS and inserts the new state in the correct
/// collection.
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
impl ProcessingResult<EventType, RequestState> {
    fn transition(self, old_state: RequestState) {
        match self {
            ProcessingResult::Success(event) => {
                // Cleanup successful.
                remove_request(&old_state);
                insert_event(event);
            }
            ProcessingResult::NoProgress => {}
            ProcessingResult::FatalFailure(fail_state) => {
                remove_request(&old_state);
                insert_request(fail_state);
            }
        }
    }
}
