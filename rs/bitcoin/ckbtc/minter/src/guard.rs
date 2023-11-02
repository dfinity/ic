use crate::state::{mutate_state, CkBtcMinterState};
use candid::Principal;
use std::collections::BTreeSet;
use std::marker::PhantomData;

const MAX_CONCURRENT: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub enum GuardError {
    AlreadyProcessing,
    TooManyConcurrentRequests,
}

pub trait PendingRequests {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Principal>;
}

pub struct PendingBalanceUpdates;

impl PendingRequests for PendingBalanceUpdates {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Principal> {
        &mut state.update_balance_principals
    }
}
pub struct RetrieveBtcUpdates;

impl PendingRequests for RetrieveBtcUpdates {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Principal> {
        &mut state.retrieve_btc_principals
    }
}

/// Guards a block from executing twice when called by the same user and from being
/// executed [MAX_CONCURRENT] or more times in parallel.
#[must_use]
pub struct Guard<PR: PendingRequests> {
    principal: Principal,
    _marker: PhantomData<PR>,
}

impl<PR: PendingRequests> Guard<PR> {
    /// Attempts to create a new guard for the current block. Fails if there is
    /// already a pending request for the specified [principal] or if there
    /// are at least [MAX_CONCURRENT] pending requests.
    pub fn new(principal: Principal) -> Result<Self, GuardError> {
        mutate_state(|s| {
            let principals = PR::pending_requests(s);
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

impl<PR: PendingRequests> Drop for Guard<PR> {
    fn drop(&mut self) {
        mutate_state(|s| PR::pending_requests(s).remove(&self.principal));
    }
}

#[must_use]
pub struct TimerLogicGuard(());

impl TimerLogicGuard {
    pub fn new() -> Option<Self> {
        mutate_state(|s| {
            if s.is_timer_running {
                return None;
            }
            s.is_timer_running = true;
            Some(TimerLogicGuard(()))
        })
    }
}

impl Drop for TimerLogicGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.is_timer_running = false;
        });
    }
}

#[must_use]
pub struct DistributeKytFeeGuard(());

impl DistributeKytFeeGuard {
    pub fn new() -> Option<Self> {
        mutate_state(|s| {
            if s.is_distributing_fee {
                return None;
            }
            s.is_distributing_fee = true;
            Some(DistributeKytFeeGuard(()))
        })
    }
}

impl Drop for DistributeKytFeeGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.is_distributing_fee = false;
        });
    }
}

pub fn balance_update_guard(p: Principal) -> Result<Guard<PendingBalanceUpdates>, GuardError> {
    Guard::new(p)
}

pub fn retrieve_btc_guard(p: Principal) -> Result<Guard<RetrieveBtcUpdates>, GuardError> {
    Guard::new(p)
}

#[cfg(test)]
mod tests {
    use crate::{
        guard::{GuardError, MAX_CONCURRENT},
        lifecycle::init::{init, BtcNetwork, InitArgs},
        state::read_state,
    };
    use candid::Principal;
    use ic_base_types::CanisterId;

    use super::{balance_update_guard, TimerLogicGuard};

    fn test_principal(id: u64) -> Principal {
        Principal::try_from_slice(&id.to_le_bytes()).unwrap()
    }

    fn test_state_args() -> InitArgs {
        InitArgs {
            btc_network: BtcNetwork::Regtest,
            ecdsa_key_name: "some_key".to_string(),
            retrieve_btc_min_amount: 2000,
            ledger_id: CanisterId::from_u64(42),
            max_time_in_queue_nanos: 0,
            min_confirmations: None,
            mode: crate::state::Mode::GeneralAvailability,
            kyt_principal: Some(CanisterId::from(0)),
            kyt_fee: None,
        }
    }

    #[test]
    fn guard_limits_one_principal() {
        // test that two guards for the same principal cannot exist in the same block
        // and that a guard is properly dropped at end of the block

        init(test_state_args());
        let p = test_principal(0);
        {
            let _guard = balance_update_guard(p).unwrap();
            let res = balance_update_guard(p).err();
            assert_eq!(res, Some(GuardError::AlreadyProcessing));
        }
        let _ = balance_update_guard(p).unwrap();
    }

    #[test]
    #[allow(clippy::needless_collect)]
    fn guard_prevents_more_than_max_concurrent_principals() {
        // test that at most MAX_CONCURRENT guards can be created if each one
        // is for a different principal

        init(test_state_args());
        let guards: Vec<_> = (0..MAX_CONCURRENT)
            .map(|id| {
                balance_update_guard(test_principal(id as u64)).unwrap_or_else(|e| {
                    panic!("Could not create guard for principal num {}: {:#?}", id, e)
                })
            })
            .collect();
        assert_eq!(guards.len(), MAX_CONCURRENT);
        let pid = test_principal(MAX_CONCURRENT as u64 + 1);
        let res = balance_update_guard(pid).err();
        assert_eq!(res, Some(GuardError::TooManyConcurrentRequests));
    }

    #[test]
    fn guard_timer_guard() {
        init(test_state_args());
        assert!(!read_state(|s| s.is_timer_running));

        let guard = TimerLogicGuard::new().expect("could not grab timer logic guard");
        assert!(TimerLogicGuard::new().is_none());
        assert!(read_state(|s| s.is_timer_running));

        drop(guard);
        assert!(!read_state(|s| s.is_timer_running));
    }
}
