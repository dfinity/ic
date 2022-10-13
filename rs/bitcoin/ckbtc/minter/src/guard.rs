use crate::state::{mutate_state, CkBtcMinterState};
use candid::Principal;
use std::collections::BTreeSet;
use std::marker::PhantomData;

const MAX_CONCURRENT: usize = 100;

#[derive(Debug, PartialEq)]
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
            if principals.len() >= MAX_CONCURRENT as usize {
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
        lifecycle::init::DEFAULT_MIN_CONFIRMATIONS,
        state::{replace_state, CkBtcMinterState},
    };
    use ic_base_types::CanisterId;
    use ic_btc_types::Network;
    use ic_cdk::export::Principal;

    use super::balance_update_guard;

    fn test_principal(id: u64) -> Principal {
        Principal::try_from_slice(&id.to_le_bytes()).unwrap()
    }

    fn test_state() -> CkBtcMinterState {
        CkBtcMinterState {
            btc_network: Network::Regtest,
            ecdsa_key_name: "".to_string(),
            ecdsa_public_key: None,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            retrieve_btc_principals: Default::default(),
            retrieve_btc_min_fee: 0,
            retrieve_btc_min_amount: 0,
            pending_retrieve_btc_requests: Default::default(),
            update_balance_principals: Default::default(),
            ledger_id: CanisterId::from_u64(42),
            utxos_state_addresses: Default::default(),
        }
    }

    #[test]
    fn guard_limits_one_principal() {
        // test that two guards for the same principal cannot exist in the same block
        // and that a guard is properly dropped at end of the block

        replace_state(test_state());
        let p = test_principal(0);
        {
            let _guard = balance_update_guard(p).unwrap();
            let res = balance_update_guard(p).err();
            assert_eq!(res, Some(GuardError::AlreadyProcessing));
        }
        balance_update_guard(p).unwrap();
    }

    #[test]
    #[allow(clippy::needless_collect)]
    fn guard_prevents_more_than_max_concurrent_principals() {
        // test that at most MAX_CONCURRENT guards can be created if each one
        // is for a different principal

        replace_state(test_state());
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
}
