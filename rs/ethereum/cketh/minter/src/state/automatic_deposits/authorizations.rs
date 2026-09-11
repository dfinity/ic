#[cfg(test)]
mod tests;

use crate::numeric::TransactionNonce;
use crate::state::transactions::SweepId;
use crate::tx::{Authorization, AuthorizationRequest, TransactionSignature};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

/// Every EIP-7702 authorization the minter has signed for its deposit addresses and is still
/// accountable for, per account: the tuples signed but not yet settled, and the one delegation
/// the account's deposit address carries on chain. At most one tuple ever applies per account
/// nonce; applying one settles that nonce and discards its rival tuples, the same way the
/// transaction pipeline finalizes one sent transaction per nonce and drops the superseded
/// resubmissions.
///
/// The store grows with the number of accounts that have ever been swept and is never emptied:
/// an account keeps its applied delegation forever. [`Self::stored_len`] is exported as a metric
/// so that growth is visible before it needs bounding.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct AuthorizationStore {
    accounts: BTreeMap<Account, Authorizations>,
}

impl AuthorizationStore {
    /// The signature already stored for `request`, whether still pending or already applied:
    /// signing another would cost a threshold-ECDSA signature for the same tuple.
    pub fn signature(&self, request: &AuthorizationRequest) -> Option<&TransactionSignature> {
        let stored = self.accounts.get(&request.account())?;
        let authorization = request.authorization();
        stored
            .pending
            .get(&authorization)
            .or_else(|| stored.applied_signature(&authorization))
    }

    pub fn record_signed(
        &mut self,
        request: AuthorizationRequest,
        signature: TransactionSignature,
    ) {
        self.accounts
            .entry(request.account())
            .or_default()
            .pending
            .insert(request.authorization(), signature);
    }

    /// Record that `sweep_id` applied `request`'s tuple on chain, unless the protocol skipped it:
    /// a tuple applies only at the authority's current nonce, and applying one spends that nonce,
    /// so a tuple signed for any other leaves the address as it was. Applying settles the nonce:
    /// the tuple becomes the account's delegation and the rival tuples the spent nonce
    /// invalidated are dropped.
    ///
    /// Callers must settle finalized sweeps in the order the chain executed them: a receipt does
    /// not say which of its tuples applied, so the store infers it from the nonce each account
    /// has reached.
    ///
    /// # Panics
    ///
    /// If the tuple is at the account's current nonce but was never signed. The minter is the
    /// only signer for its deposit addresses, so a sweep carrying an unknown tuple means the
    /// store has stopped describing what the minter signed.
    pub fn record_applied(&mut self, request: AuthorizationRequest, sweep_id: SweepId) {
        if request.nonce() != self.next_nonce(&request.account()) {
            return;
        }
        let stored = self
            .accounts
            .get_mut(&request.account())
            .expect("BUG: a sweep carried an authorization the minter never signed");
        let authorization = request.authorization();
        let signature = stored
            .pending
            .remove(&authorization)
            .expect("BUG: a sweep carried an authorization the minter never signed");
        stored
            .pending
            .retain(|pending, _signature| pending.nonce > authorization.nonce);
        stored.delegation = Some(AppliedDelegation {
            authorization,
            signature,
            applied_by: sweep_id,
        });
    }

    /// The delegation `account`'s deposit address carries on chain, as the tuples applied to it
    /// say. `None` while none of the minter's tuples for the address has been applied, which for
    /// a deposit address means it holds no delegation at all: only the minter ever authorizes
    /// one.
    pub fn delegation(&self, account: &Account) -> Option<Delegation> {
        self.accounts
            .get(account)?
            .delegation
            .as_ref()
            .map(AppliedDelegation::delegation)
    }

    /// The number of tuples the store holds, pending and applied.
    pub fn stored_len(&self) -> usize {
        self.accounts.values().map(Authorizations::len).sum()
    }

    /// The number of accounts whose deposit address carries a delegation.
    pub fn applied_len(&self) -> usize {
        self.accounts
            .values()
            .filter(|authorizations| authorizations.is_delegated())
            .count()
    }

    fn next_nonce(&self, account: &Account) -> TransactionNonce {
        self.delegation(account)
            .map_or(TransactionNonce::ZERO, |delegation| delegation.nonce)
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
struct Authorizations {
    delegation: Option<AppliedDelegation>,
    pending: BTreeMap<Authorization, TransactionSignature>,
}

impl Authorizations {
    fn applied_signature(&self, authorization: &Authorization) -> Option<&TransactionSignature> {
        self.delegation
            .as_ref()
            .filter(|applied| &applied.authorization == authorization)
            .map(|applied| &applied.signature)
    }

    fn len(&self) -> usize {
        self.pending.len() + usize::from(self.delegation.is_some())
    }

    fn is_delegated(&self) -> bool {
        self.delegation.is_some()
    }
}

#[derive(Clone, PartialEq, Debug)]
struct AppliedDelegation {
    authorization: Authorization,
    signature: TransactionSignature,
    applied_by: SweepId,
}

impl AppliedDelegation {
    fn delegation(&self) -> Delegation {
        Delegation {
            delegate: self.authorization.delegate,
            nonce: self
                .authorization
                .nonce
                .checked_increment()
                .expect("BUG: authorization nonce space exhausted"),
        }
    }
}

/// The delegation a deposit address carries on chain.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Delegation {
    /// The contract the address' code points at.
    pub delegate: Address,
    /// The nonce the address has reached, one past the nonce of the authorization that installed
    /// the delegation.
    pub nonce: TransactionNonce,
}
