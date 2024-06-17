//! Utilities to help with testing interleavings of calls to the governance
//! canister
use async_trait::async_trait;
use futures::channel::{
    mpsc::UnboundedSender as USender,
    oneshot::{self, Sender as OSender},
};
use ic_base_types::CanisterId;
use ic_nervous_system_common::{ledger::IcpLedger, NervousSystemError};
use ic_nns_governance::{
    governance::{Environment, HeapGrowthPotential},
    pb::v1::{ExecuteNnsFunction, GovernanceError},
};
use icp_ledger::{AccountIdentifier, Subaccount, Tokens};
use std::sync::{atomic, atomic::Ordering as AOrdering};

pub mod test_data;

/// Reifies the methods of the Ledger trait, such that they can be sent over a
/// channel
#[derive(Debug)]
pub enum LedgerMessage {
    Transfer,
    TotalSupply,
    BalanceQuery,
}

pub type LedgerControlMessage = (LedgerMessage, OSender<Result<(), NervousSystemError>>);

pub type LedgerObserver = USender<LedgerControlMessage>;

/// A mock ledger to test interleavings of governance method calls.
pub struct InterleavingTestLedger {
    underlying: Box<dyn IcpLedger>,
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
    pub fn new(underlying: Box<dyn IcpLedger>, observer: LedgerObserver) -> Self {
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
}

#[async_trait]
impl IcpLedger for InterleavingTestLedger {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: AccountIdentifier,
        memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let msg = LedgerMessage::Transfer;
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
        self.notify(LedgerMessage::BalanceQuery).await?;
        self.underlying.account_balance(account).await
    }

    fn canister_id(&self) -> CanisterId {
        self.underlying.canister_id()
    }
}

/// Reifies the methods of the Environment trait, such that they can be sent over a
/// channel
#[derive(Debug)]
pub enum EnvironmentMessage {
    CallCanisterMethod,
}

pub type EnvironmentControlMessage = (
    EnvironmentMessage,
    OSender<Result<(), (Option<i32>, String)>>,
);

pub type EnvironmentObserver = USender<EnvironmentControlMessage>;

/// A mock environment to test interleavings of governance method calls.
pub struct InterleavingTestEnvironment {
    underlying: Box<dyn Environment>,
    observer: EnvironmentObserver,
}

impl InterleavingTestEnvironment {
    /// Notifies the observer that an environment method has been called, and blocks until
    /// it receives a message to continue.
    async fn notify(&self, msg: EnvironmentMessage) -> Result<(), (Option<i32>, String)> {
        let (tx, rx) = oneshot::channel::<Result<(), (Option<i32>, String)>>();
        self.observer.unbounded_send((msg, tx)).unwrap();
        rx.await
            .map_err(|_e| (None, "Operation unavailable".to_string()))?
    }

    /// Closes the observer channel so the UnboundedReceiver can terminate. This
    /// should be called after the InterleavingTestEnvironment is no longer being used
    /// in the test, and no other calls to the underlying Ledger will be issued.
    pub fn close_channel(&self) {
        self.observer.close_channel()
    }
}

#[async_trait]
impl Environment for InterleavingTestEnvironment {
    /// Since this is not asynchronous we cannot interleave calls. Just forward
    /// the call to the underlying trait
    fn now(&self) -> u64 {
        atomic::fence(AOrdering::SeqCst);
        self.underlying.now()
    }

    fn random_u64(&mut self) -> u64 {
        atomic::fence(AOrdering::SeqCst);
        self.underlying.random_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        unimplemented!()
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        unimplemented!()
    }

    /// Since this is not asynchronous we cannot interleave calls. Just forward
    /// the call to the underlying trait
    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        atomic::fence(AOrdering::SeqCst);
        self.underlying.heap_growth_potential()
    }

    async fn call_canister_method(
        &mut self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        let msg = EnvironmentMessage::CallCanisterMethod;
        atomic::fence(AOrdering::SeqCst);
        self.notify(msg).await?;
        self.underlying
            .call_canister_method(target, method_name, request)
            .await
    }
}

/// Closes the InterleavingTestLedger's observer channel when InterleavingTestLedger
/// exits its scope. `close_channel` is idempotent so multiple calls will not cause
/// any unexpected panics.
impl Drop for InterleavingTestEnvironment {
    fn drop(&mut self) {
        self.close_channel()
    }
}
