//! Utilities to help with testing interleavings of calls to canisters
pub use crate::prometheus::{get_counter, get_gauge, get_samples};

use async_trait::async_trait;
use dfn_core::CanisterId;
use futures::{
    channel::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender as OneShotSender},
    },
    StreamExt,
};
use ic_nervous_system_common::{
    ledger::{ICRC1Ledger, IcpLedger},
    NervousSystemError,
};
use icp_ledger::{AccountIdentifier, Tokens};
use icrc_ledger_types::icrc1::account::Account;
use std::sync::{atomic, atomic::Ordering as AtomicOrdering, Arc, Mutex};

mod prometheus;
pub mod wasm_helpers;

/// Reifies the methods of the Ledger trait, such that they can be sent over a
/// channel
#[derive(Debug)]
pub enum LedgerMessage {
    Transfer {
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
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
        from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let msg = LedgerMessage::Transfer {
            amount_e8s,
            fee_e8s,
            from_subaccount,
            to,
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
        self.notify(LedgerMessage::BalanceQuery(account)).await?;
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LedgerCall {
    TransferFundsICRC1 {
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        to: Account,
        memo: u64,
    },
    TransferFundsICP {
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<icp_ledger::Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    },
    AccountBalanceICRC1 {
        account: Account,
    },
    AccountBalanceICP {
        account: AccountIdentifier,
    },
}

#[derive(Debug)]
pub enum LedgerReply {
    TransferFunds(Result</* block_height */ u64, NervousSystemError>),
    AccountBalance(Result<Tokens, NervousSystemError>),
}

/// Struct that allows tests to spy on the calls made
#[derive(Default)]
pub struct SpyLedger {
    calls: Arc<Mutex<Vec<LedgerCall>>>,
    replies: Arc<Mutex<Vec<LedgerReply>>>,
}

/// Struct that allows tests to mock replies from the ledger
impl SpyLedger {
    pub fn new(replies: Vec<LedgerReply>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::<LedgerCall>::new())),
            replies: Arc::new(Mutex::new(replies)),
        }
    }

    pub fn get_calls_snapshot(&self) -> Vec<LedgerCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl ICRC1Ledger for SpyLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        to: Account,
        memo: u64,
    ) -> Result</* block_height: */ u64, NervousSystemError> {
        self.calls
            .lock()
            .unwrap()
            .push(LedgerCall::TransferFundsICRC1 {
                amount_e8s,
                fee_e8s,
                from_subaccount,
                to,
                memo,
            });

        let ledger_reply = self
            .replies
            .lock()
            .unwrap()
            .pop()
            .expect("Expected a LedgerReply to be on the queue");

        match ledger_reply {
            LedgerReply::TransferFunds(reply) => reply,
            reply => panic!(
                "Expected LedgerReply::TransferFunds to be at the front of the queue. Had {:?}",
                reply
            ),
        }
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!();
    }

    async fn account_balance(&self, account_id: Account) -> Result<Tokens, NervousSystemError> {
        self.calls
            .lock()
            .unwrap()
            .push(LedgerCall::AccountBalanceICRC1 {
                account: account_id,
            });

        let ledger_reply = self
            .replies
            .lock()
            .unwrap()
            .pop()
            .expect("Expected a LedgerReply to be on the queue");

        match ledger_reply {
            LedgerReply::AccountBalance(reply) => reply,
            reply => panic!(
                "Expected LedgerReply::AccountBalance to be at the front of the queue. Had {:?}",
                reply
            ),
        }
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from_u64(1)
    }
}

#[async_trait]
impl IcpLedger for SpyLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<icp_ledger::Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result</* block_height: */ u64, NervousSystemError> {
        self.calls
            .lock()
            .unwrap()
            .push(LedgerCall::TransferFundsICP {
                amount_e8s,
                fee_e8s,
                from_subaccount,
                to,
                memo,
            });

        let ledger_reply = self
            .replies
            .lock()
            .unwrap()
            .pop()
            .expect("Expected a LedgerReply to be on the queue");

        match ledger_reply {
            LedgerReply::TransferFunds(reply) => reply,
            reply => panic!(
                "Expected LedgerReply::TransferFunds to be at the front of the queue. Had {:?}",
                reply
            ),
        }
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        self.calls
            .lock()
            .unwrap()
            .push(LedgerCall::AccountBalanceICP { account });

        let ledger_reply = self
            .replies
            .lock()
            .unwrap()
            .pop()
            .expect("Expected a LedgerReply to be on the queue");

        match ledger_reply {
            LedgerReply::AccountBalance(reply) => reply,
            reply => panic!(
                "Expected LedgerReply::AccountBalance to be at the front of the queue. Had {:?}",
                reply
            ),
        }
    }

    fn canister_id(&self) -> CanisterId {
        unimplemented!()
    }
}
