#[cfg(test)]
mod tests;

use crate::state::{mutate_state, State, TaskType};
use candid::Principal;
use std::collections::BTreeSet;
use std::marker::PhantomData;

pub const MAX_CONCURRENT: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum GuardError {
    AlreadyProcessing,
    TooManyConcurrentRequests,
}

pub trait RequestsGuardedByPrincipal {
    fn guarded_principals(state: &mut State) -> &mut BTreeSet<Principal>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct PendingRetrieveEthRequests;

impl RequestsGuardedByPrincipal for PendingRetrieveEthRequests {
    fn guarded_principals(state: &mut State) -> &mut BTreeSet<Principal> {
        &mut state.retrieve_eth_principals
    }
}

/// Guards a block from executing twice when called by the same user and from being
/// executed [MAX_CONCURRENT] or more times in parallel.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct Guard<PR: RequestsGuardedByPrincipal> {
    principal: Principal,
    _marker: PhantomData<PR>,
}

impl<PR: RequestsGuardedByPrincipal> Guard<PR> {
    /// Attempts to create a new guard for the current block. Fails if there is
    /// already a pending request for the specified [principal] or if there
    /// are at least [MAX_CONCURRENT] pending requests.
    fn new(principal: Principal) -> Result<Self, GuardError> {
        mutate_state(|s| {
            let principals = PR::guarded_principals(s);
            if principals.contains(&principal) {
                return Err(GuardError::AlreadyProcessing);
            }
            if principals.len() >= MAX_CONCURRENT {
                return Err(GuardError::TooManyConcurrentRequests);
            }
            principals.insert(principal);
            Ok(Self {
                principal,
                _marker: PhantomData,
            })
        })
    }
}

impl<PR: RequestsGuardedByPrincipal> Drop for Guard<PR> {
    fn drop(&mut self) {
        mutate_state(|s| PR::guarded_principals(s).remove(&self.principal));
    }
}

pub fn retrieve_eth_guard(
    principal: Principal,
) -> Result<Guard<PendingRetrieveEthRequests>, GuardError> {
    Guard::new(principal)
}

#[derive(Debug, PartialEq, Eq)]
pub enum TimerGuardError {
    AlreadyProcessing,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TimerGuard {
    task: TaskType,
}

impl TimerGuard {
    pub fn new(task: TaskType) -> Result<Self, TimerGuardError> {
        mutate_state(|s| {
            if !s.active_tasks.insert(task) {
                return Err(TimerGuardError::AlreadyProcessing);
            }
            Ok(Self { task })
        })
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.active_tasks.remove(&self.task);
        });
    }
}
