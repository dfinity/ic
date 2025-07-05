use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize, Serializer};
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

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct Balance {
    #[serde(serialize_with = "serialize_nat_as_u64")]
    pub amount_decimals: Nat,
    pub owner_account: Account,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct Balances {
    pub balances: BTreeMap<Asset, Balance>,
    pub timestamp_ns: u64,
}

pub type TreasuryManagerResult = Result<Balances, Vec<TransactionError>>;

pub trait TreasuryManager {
    /// Implements the `deposit` API function.
    fn deposit(
        &mut self,
        request: DepositRequest,
    ) -> impl std::future::Future<Output = TreasuryManagerResult> + Send;

    /// Implements the `withdraw` API function.
    fn withdraw(
        &mut self,
        request: WithdrawRequest,
    ) -> impl std::future::Future<Output = TreasuryManagerResult> + Send;

    /// Implements the `audit_trail` API query function.
    fn audit_trail(&self, request: AuditTrailRequest) -> AuditTrail;

    /// Implements the `balances` API query function.
    fn balances(&self, request: BalancesRequest) -> TreasuryManagerResult;

    /// Should not be exposed as an API function, but rather called periodically by the canister.
    fn refresh_balances(&mut self) -> impl std::future::Future<Output = ()> + Send;

    /// Should not be exposed as an API function, but rather called periodically by the canister.
    fn issue_rewards(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct DepositRequest {
    pub allowances: Vec<Allowance>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct BalancesRequest {}

pub type Subaccount = [u8; 32];

#[derive(CandidType, Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct Accounts {
    pub ledger_id_to_account: BTreeMap<Principal, Account>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct WithdrawRequest {
    /// If not set, accounts specified at the time of deposit will be used for the withdrawal.
    pub withdraw_accounts: Option<Accounts>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AuditTrailRequest {}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum TreasuryManagerOperation {
    Deposit,
    Balances,
    IssueReward,
    Withdraw,
}

/// To be used for ledger transaction memos.
impl From<TreasuryManagerOperation> for Vec<u8> {
    fn from(op: TreasuryManagerOperation) -> Self {
        const PREFIX: &str = "TreasuryManager";

        let suffix = match op {
            TreasuryManagerOperation::Deposit => "Deposit",
            TreasuryManagerOperation::Balances => "Balances",
            TreasuryManagerOperation::IssueReward => "IssueReward",
            TreasuryManagerOperation::Withdraw => "Withdraw",
        };

        format!("{}.{}", PREFIX, suffix).as_bytes().to_vec()
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
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

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Transaction {
    pub timestamp_ns: u64,
    pub canister_id: Principal,
    // TODO: add low-level traces stored as JSON.
    pub result: Result<TransactionWitness, TransactionError>,
    pub human_readable: String,
    pub treasury_manager_operation: TreasuryManagerOperation,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AuditTrail {
    pub transactions: Vec<Transaction>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Asset {
    Token {
        symbol: String,
        ledger_canister_id: Principal,
        #[serde(serialize_with = "serialize_nat_as_u64")]
        ledger_fee_decimals: Nat,
    },
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq, Hash, Deserialize)]
pub struct Allowance {
    pub asset: Asset,

    /// Total amount that may be consumed, including the fees.
    #[serde(serialize_with = "serialize_nat_as_u64")]
    pub amount_decimals: Nat,

    /// The owner account is used to return the leftover assets and issue rewards.
    pub owner_account: Account,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Transfer {
    pub ledger_canister_id: String,
    #[serde(serialize_with = "serialize_nat_as_u64")]
    pub amount_decimals: Nat,
    #[serde(serialize_with = "serialize_nat_as_u64")]
    pub block_index: Nat,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum TransactionWitness {
    Ledger(Vec<Transfer>),

    /// Represents a transaction that is not related to the ledger, e.g., DEX operations.
    /// The argument is a (best-effort) JSON encoding of the response (for human inspection).
    NonLedger(String),
}

fn serialize_nat_as_u64<S>(nat: &Nat, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert Nat to u64 for JSON serialization
    let value: String = nat.to_string();
    serializer.serialize_str(&value)
}
