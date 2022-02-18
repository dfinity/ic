//! Utilities to help with testing interleavings of calls to the governance
//! canister
use async_trait::async_trait;
use futures::channel::mpsc::UnboundedSender as USender;
use futures::channel::oneshot::{self, Sender as OSender};
use ic_nervous_system_common::{ledger::Ledger, NervousSystemError};
use std::sync::atomic;
use std::sync::atomic::Ordering as AOrdering;

use ledger_canister::Subaccount;
use ledger_canister::{AccountIdentifier, Tokens};

/// Reifies the methods of the Ledger trait, such that they can be sent over a
/// channel
#[derive(Debug)]
pub enum LedgerMessage {
    Transfer {
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    },
    TotalSupply,
    BalanceQuery(AccountIdentifier),
}

pub type LedgerControlMessage = (LedgerMessage, OSender<Result<(), NervousSystemError>>);

pub type LedgerObserver = USender<LedgerControlMessage>;

/// A mock ledger to test interleavings of governance method calls.
pub struct InterleavingTestLedger {
    underlying: Box<dyn Ledger>,
    observer: LedgerObserver,
}

impl InterleavingTestLedger {
    /// The ledger intercepts calls to an underlying ledger implementation,
    /// sends the reified calls over the provided observer channel, and
    /// blocks. The receiver side of the channel can then inspect the
    /// results, and decide at what point to go ahead with the call to the
    /// underlying ledger, or, alternatively, return an error. This is done
    /// through a one-shot channel, the sender side of which is sent to the
    /// observer.
    pub fn new(underlying: Box<dyn Ledger>, observer: LedgerObserver) -> Self {
        InterleavingTestLedger {
            underlying,
            observer,
        }
    }

    // Notifies the observer that a ledger method has been called, and blocks until
    // it receives a message to continue.
    async fn notify(&self, msg: LedgerMessage) -> Result<(), NervousSystemError> {
        let (tx, rx) = oneshot::channel::<Result<(), NervousSystemError>>();
        self.observer.unbounded_send((msg, tx)).unwrap();
        rx.await
            .map_err(|_e| NervousSystemError::new_with_message("Operation unavailable"))?
    }
}

#[async_trait]
impl Ledger for InterleavingTestLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let msg = LedgerMessage::Transfer {
            amount_e8s,
            fee_e8s,
            from_subaccount,
            to,
            memo,
        };
        atomic::fence(AOrdering::SeqCst);
        self.notify(msg).await?;
        self.underlying
            .transfer_funds(amount_e8s, fee_e8s, from_subaccount, to, memo)
            .await
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        atomic::fence(AOrdering::SeqCst);
        self.notify(LedgerMessage::TotalSupply).await?;
        self.underlying.total_supply().await
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        atomic::fence(AOrdering::SeqCst);
        self.notify(LedgerMessage::BalanceQuery(account)).await?;
        self.underlying.account_balance(account).await
    }
}
