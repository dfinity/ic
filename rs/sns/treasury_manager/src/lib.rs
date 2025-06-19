use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct TreasuryManagerInit {
    pub allowances: Vec<Allowance>,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct TreasuryManagerUpgrade {}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub enum TreasuryManagerArg {
    Init(TreasuryManagerInit),
    Upgrade(TreasuryManagerUpgrade),
}

pub type TreasuryManagerResult = Result<BTreeMap<Asset, Nat>, TransactionError>;

pub trait TreasuryManager {
    fn deposit(
        &mut self,
        request: DepositRequest,
    ) -> impl std::future::Future<Output = TreasuryManagerResult> + Send;

    fn withdraw(
        &mut self,
        request: WithdrawRequest,
    ) -> impl std::future::Future<Output = TreasuryManagerResult> + Send;

    fn balances(&self, request: BalancesRequest) -> TreasuryManagerResult;

    fn audit_trail(&self, request: AuditTrailRequest) -> AuditTrail;
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct DepositRequest {
    pub allowances: Vec<Allowance>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct BalancesRequest {}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct WithdrawRequest {}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AuditTrailRequest {}

#[derive(CandidType, Clone, Copy, Debug, Deserialize)]
pub enum TreasuryManagerOperation {
    Deposit,
    Balances,
    IssueReward,
    Withdraw,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum TransactionError {
    /// Prevents the call from being attempted.
    Precondition(String),

    /// An error that occurred while calling a canister.
    Call {
        canister_id: Principal,
        method: String,
        error: String,
    },

    /// Backend refers to, e.g., the DEX canister that this asset manager talks to.
    Backend(String),

    /// Prevents the response from being interpreted.
    Postcondition(String),
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct Transaction {
    pub canister_id: Principal,
    // TODO: add low-level traces stores as JSON.
    pub result: Result<TransactionWitness, TransactionError>,
    pub human_readable: String,
    pub timestamp_ns: u64,
    pub treasury_operation_phase: TreasuryManagerOperation,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct AuditTrail {
    transactions: Vec<Transaction>,
}

impl AuditTrail {
    pub fn new() -> Self {
        AuditTrail {
            transactions: vec![],
        }
    }

    pub fn record_event(&mut self, event: Transaction) {
        self.transactions.push(event);
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Asset {
    Token {
        symbol: String,
        ledger_canister_id: Principal,
    },
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Deserialize)]
pub struct Allowance {
    pub asset: Asset,

    // Total amount that may be consumed, including the fees.
    pub amount_decimals: Nat,

    // Sets the expected fee per ledger transaction; transactions should fail if the actual
    // ledger fee is unexpected.
    pub expected_ledger_fee_decimals: Nat,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct Transfer {
    pub ledger_canister_id: String,
    pub amount_decimals: Nat,
    pub block_index: Nat,
}

#[derive(CandidType, Clone, Debug, Deserialize)]
pub enum TransactionWitness {
    Ledger(Vec<Transfer>),

    /// Represents a transaction that is not related to the ledger, e.g., DEX operations.
    /// The argument is a (best-effort) JSON encoding of the response (for human inspection).
    NonLedger(String),
}
