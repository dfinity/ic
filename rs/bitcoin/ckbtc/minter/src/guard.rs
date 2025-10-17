use crate::state::{CkBtcMinterState, mutate_state};
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;
use std::marker::PhantomData;

const MAX_CONCURRENT: usize = 100;

#[derive(Eq, PartialEq, Debug)]
pub enum GuardError {
    AlreadyProcessing,
    TooManyConcurrentRequests,
}

pub trait PendingRequests {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Account>;
}

pub struct PendingBalanceUpdates;

impl PendingRequests for PendingBalanceUpdates {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Account> {
        &mut state.update_balance_accounts
    }
}
pub struct RetrieveBtcUpdates;

impl PendingRequests for RetrieveBtcUpdates {
    fn pending_requests(state: &mut CkBtcMinterState) -> &mut BTreeSet<Account> {
        &mut state.retrieve_btc_accounts
    }
}

/// Guards a block from executing twice when called by the same user and from being
/// executed [MAX_CONCURRENT] or more times in parallel.
#[must_use]
pub struct Guard<PR: PendingRequests> {
    account: Account,
    _marker: PhantomData<PR>,
}

impl<PR: PendingRequests> Guard<PR> {
    /// Attempts to create a new guard for the current block. Fails if there is
    /// already a pending request for the specified [principal] or if there
    /// are at least [MAX_CONCURRENT] pending requests.
    pub fn new(account: Account) -> Result<Self, GuardError> {
        mutate_state(|s| {
            let accounts = PR::pending_requests(s);
            if accounts.contains(&account) {
                return Err(GuardError::AlreadyProcessing);
            }
            if accounts.len() >= MAX_CONCURRENT {
                return Err(GuardError::TooManyConcurrentRequests);
            }
            accounts.insert(account);
            Ok(Self {
                account,
                _marker: PhantomData,
            })
        })
    }
}

impl<PR: PendingRequests> Drop for Guard<PR> {
    fn drop(&mut self) {
        mutate_state(|s| PR::pending_requests(s).remove(&self.account));
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

pub fn balance_update_guard(account: Account) -> Result<Guard<PendingBalanceUpdates>, GuardError> {
    Guard::new(account)
}

pub fn retrieve_btc_guard(account: Account) -> Result<Guard<RetrieveBtcUpdates>, GuardError> {
    Guard::new(account)
}

#[cfg(test)]
mod tests {
    use crate::{
        IC_CANISTER_RUNTIME, Network,
        guard::{GuardError, MAX_CONCURRENT},
        lifecycle::init::{InitArgs, init},
        state::read_state,
    };
    use candid::Principal;
    use ic_base_types::CanisterId;

    use super::{Account, TimerLogicGuard, balance_update_guard};

    fn test_principal(id: u64) -> Principal {
        Principal::try_from_slice(&id.to_le_bytes()).unwrap()
    }

    fn test_account(id: u64, sub: Option<u8>) -> Account {
        Account {
            owner: test_principal(id),
            subaccount: sub.map(|i| [i; 32]),
        }
    }

    #[allow(deprecated)]
    fn test_state_args() -> InitArgs {
        InitArgs {
            btc_network: Network::Regtest,
            ecdsa_key_name: "some_key".to_string(),
            retrieve_btc_min_amount: 2000,
            ledger_id: CanisterId::from_u64(42),
            max_time_in_queue_nanos: 0,
            min_confirmations: None,
            mode: crate::state::Mode::GeneralAvailability,
            btc_checker_principal: Some(CanisterId::from(0)),
            check_fee: None,
            kyt_principal: None,
            kyt_fee: None,
            get_utxos_cache_expiration_seconds: None,
        }
    }

    #[test]
    fn guard_limits_one_account() {
        // test that two guards for the same principal cannot exist in the same block
        // and that a guard is properly dropped at end of the block

        init(test_state_args(), &IC_CANISTER_RUNTIME);
        // a1 and a2 are effectively the same Account
        let a1 = test_account(0, None);
        let a2 = test_account(0, Some(0));
        {
            let _guard = balance_update_guard(a1).unwrap();
            let res = balance_update_guard(a2).err();
            assert_eq!(res, Some(GuardError::AlreadyProcessing));
        }
        let _ = balance_update_guard(a1).unwrap();
    }

    #[test]
    fn guard_prevents_more_than_max_concurrent_accounts() {
        // test that at most MAX_CONCURRENT guards can be created if each one
        // is for a different principal

        init(test_state_args(), &IC_CANISTER_RUNTIME);
        let guards: Vec<_> = (0..MAX_CONCURRENT / 2)
            .map(|id| {
                balance_update_guard(test_account(0, Some(id as u8))).unwrap_or_else(|e| {
                    panic!("Could not create guard for subaccount num {id}: {e:#?}")
                })
            })
            .chain((MAX_CONCURRENT / 2..MAX_CONCURRENT).map(|id| {
                balance_update_guard(test_account(id as u64, None)).unwrap_or_else(|e| {
                    panic!("Could not create guard for principal num {id}: {e:#?}")
                })
            }))
            .collect();
        assert_eq!(guards.len(), MAX_CONCURRENT);
        let account = test_account(MAX_CONCURRENT as u64 + 1, None);
        let res = balance_update_guard(account).err();
        assert_eq!(res, Some(GuardError::TooManyConcurrentRequests));
    }

    #[test]
    fn guard_timer_guard() {
        init(test_state_args(), &IC_CANISTER_RUNTIME);
        assert!(!read_state(|s| s.is_timer_running));

        let guard = TimerLogicGuard::new().expect("could not grab timer logic guard");
        assert!(TimerLogicGuard::new().is_none());
        assert!(read_state(|s| s.is_timer_running));

        drop(guard);
        assert!(!read_state(|s| s.is_timer_running));
    }
}
