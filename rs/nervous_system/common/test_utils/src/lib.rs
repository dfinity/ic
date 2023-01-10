//! Utilities to help with testing interleavings of calls to canisters
use async_trait::async_trait;
use dfn_core::CanisterId;
use futures::{
    channel::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender as OneShotSender},
    },
    StreamExt,
};
use ic_icrc1::{Account, Subaccount};
use ic_nervous_system_common::{ledger::ICRC1Ledger, NervousSystemError};
use icp_ledger::Tokens;
use std::sync::{atomic, atomic::Ordering as AtomicOrdering};

/// Reifies the methods of the Ledger trait, such that they can be sent over a
/// channel
#[derive(Debug)]
pub enum LedgerMessage {
    Transfer {
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    },
    TotalSupply,
    BalanceQuery(Account),
}

pub type LedgerControlMessage = (LedgerMessage, OneShotSender<Result<(), NervousSystemError>>);

pub type LedgerObserver = UnboundedSender<LedgerControlMessage>;

/// A mock ledger to test interleavings of canister method calls using ledger.
pub struct InterleavingTestLedger {
    underlying: Box<dyn ICRC1Ledger>,
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
    pub fn new(underlying: Box<dyn ICRC1Ledger>, observer: LedgerObserver) -> Self {
        InterleavingTestLedger {
            underlying,
            observer,
        }
    }

    /// Notifies the observer that a ledger method has been called, and blocks until
    /// it receives a message to continue.
    async fn notify(&self, msg: LedgerMessage) -> Result<(), NervousSystemError> {
        let (tx, rx) = oneshot::channel::<Result<(), NervousSystemError>>();
        self.observer.unbounded_send((msg, tx)).unwrap();
        rx.await
            .map_err(|_e| NervousSystemError::new_with_message("Operation unavailable"))?
    }

    /// Closes the observer channel so the UnboundedReceiver can terminate. This
    /// should be called after the InterleavingTestLedger is no longer being used
    /// in the test, and no other calls to the underlying Ledger will be issued.
    pub fn close_channel(&self) {
        self.observer.close_channel()
    }
}

/// Closes the InterleavingTestLedger's observer channel when InterleavingTestLedger
/// exits its scope. `close_channel` is idempotent so multiple calls will not cause
/// any unexpected panics.
impl Drop for InterleavingTestLedger {
    fn drop(&mut self) {
        self.close_channel()
    }
}

#[async_trait]
impl ICRC1Ledger for InterleavingTestLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let msg = LedgerMessage::Transfer {
            amount_e8s,
            fee_e8s,
            from_subaccount,
            to: to.clone(),
            memo,
        };
        atomic::fence(AtomicOrdering::SeqCst);
        self.notify(msg).await?;
        self.underlying
            .transfer_funds(amount_e8s, fee_e8s, from_subaccount, to, memo)
            .await
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        atomic::fence(AtomicOrdering::SeqCst);
        self.notify(LedgerMessage::TotalSupply).await?;
        self.underlying.total_supply().await
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        atomic::fence(AtomicOrdering::SeqCst);
        self.notify(LedgerMessage::BalanceQuery(account.clone()))
            .await?;
        self.underlying.account_balance(account).await
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from_u64(1)
    }
}

/// Drains an UnboundedReceiver channel by sending `Ok()` signals for all incoming
/// LedgerControlMessages messages, ignoring the response.
pub async fn drain_receiver_channel(
    receiver_channel: &mut UnboundedReceiver<LedgerControlMessage>,
) {
    // Drain the channel to finish the test.
    while let Some((_msg, ledger_control_message)) = receiver_channel.next().await {
        ledger_control_message
            .send(Ok(()))
            .expect("Error draining the receiver_channel");
    }
}
