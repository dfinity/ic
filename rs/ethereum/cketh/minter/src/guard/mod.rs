#[cfg(test)]
mod tests;

use crate::state::{mutate_state, State};
use candid::Principal;
use std::collections::BTreeSet;
use std::marker::PhantomData;

const MAX_CONCURRENT: usize = 100;

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

/// Guards a block from being executed by different timers at the same time.
/// This could happen if the execution of a timer takes longer than the interval between two timers.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct RetrieveEthTimerGuard(());

#[derive(Debug, PartialEq, Eq)]
pub enum TimerGuardError {
    AlreadyProcessing,
}

impl RetrieveEthTimerGuard {
    fn new() -> Result<Self, TimerGuardError> {
        mutate_state(|s| {
            if s.retrieve_eth_guarded {
                return Err(TimerGuardError::AlreadyProcessing);
            }
            s.retrieve_eth_guarded = true;
            Ok(RetrieveEthTimerGuard(()))
        })
    }
}

impl Drop for RetrieveEthTimerGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.retrieve_eth_guarded = false;
        });
    }
}

pub fn retrieve_eth_timer_guard() -> Result<RetrieveEthTimerGuard, TimerGuardError> {
    RetrieveEthTimerGuard::new()
}

/// Guards the ckETH mintingnlogic to prevent concurrent execution.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct MintCkEthGuard(());

impl MintCkEthGuard {
    pub fn new() -> Result<Self, TimerGuardError> {
        mutate_state(|s| {
            if s.cketh_mint_guarded {
                return Err(TimerGuardError::AlreadyProcessing);
            }
            s.cketh_mint_guarded = true;
            Ok(MintCkEthGuard(()))
        })
    }
}

impl Drop for MintCkEthGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.cketh_mint_guarded = false;
        });
    }
}

pub fn mint_cketh_guard() -> Result<MintCkEthGuard, TimerGuardError> {
    MintCkEthGuard::new()
}
