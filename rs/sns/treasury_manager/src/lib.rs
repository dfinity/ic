use candid::{CandidType, Nat, Principal};
use serde::{Deserialize, Serialize, Serializer};
use std::{collections::BTreeMap, fmt::Display};

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
    pub account: Option<Account>,
    pub name: Option<String>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct BalanceBook {
    pub treasury_owner: Option<Balance>,
    pub treasury_manager: Option<Balance>,
    pub external: Option<Balance>,
    pub fee_collector: Option<Balance>,
    pub spendings: Option<Balance>,
    pub earnings: Option<Balance>,
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Balances {
    pub timestamp_ns: u64,
    pub asset_to_balances: Option<BTreeMap<Asset, BalanceBook>>,
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

    // While the following methods go beyond just the Treasury Manager API agreement, they guide
    // the implementers to organize the code in a reasonable and predictable way.

    /// Context: the source of truth for balances are some remote canisters (e.g., the ledgers).
    /// The Treasury Manager needs to have a local cache of these balances to be able to make
    /// important decisions, e.g., how much can be refunded / withdrawn. That cache should be
    /// regularly updated, and this is the function that should do that.
    ///
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

#[derive(CandidType, Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct WithdrawRequest {
    /// If not set, accounts specified at the time of deposit will be used for the withdrawal.
    pub withdraw_accounts: Option<BTreeMap<Principal, Account>>,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AuditTrailRequest {}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct Step {
    index: usize,
    is_final: bool,
}

impl Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_final {
            write!(f, "{}-fin", self.index)
        } else {
            write!(f, "{}", self.index)
        }
    }
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum Operation {
    Deposit,
    Balances,
    IssueReward,
    Withdraw,
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Deposit => "Deposit",
            Self::Balances => "Balances",
            Self::IssueReward => "IssueReward",
            Self::Withdraw => "Withdraw",
        }
    }
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct TreasuryManagerOperation {
    operation: Operation,
    step: Step,
}

impl TreasuryManagerOperation {
    pub fn new(operation: Operation) -> Self {
        Self {
            operation,
            step: Step {
                index: 0,
                is_final: false,
            },
        }
    }

    pub fn new_final(operation: Operation) -> Self {
        Self {
            operation,
            step: Step {
                index: 0,
                is_final: false,
            },
        }
    }

    pub fn next(&self) -> Self {
        let index = self.step.index.saturating_add(1);
        Self {
            operation: self.operation,
            step: Step {
                index,
                is_final: false,
            },
        }
    }

    pub fn next_final(&self) -> Self {
        let index = self.step.index.saturating_add(1);
        Self {
            operation: self.operation,
            step: Step {
                index,
                is_final: true,
            },
        }
    }
}

/// To be used for ledger transaction memos.
impl From<TreasuryManagerOperation> for Vec<u8> {
    fn from(operation: TreasuryManagerOperation) -> Self {
        const PREFIX: &str = "TreasuryManager";

        format!(
            "{}.{}-{}",
            PREFIX,
            operation.operation.name(),
            operation.step,
        )
        .as_bytes()
        .to_vec()
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum TransactionError {
    /// Prevents the call from being attempted.
    Precondition { error: String, code: u64 },

    /// Prevents the response from being interpreted.
    Postcondition { error: String, code: u64 },

    /// An error that occurred while calling a canister.
    Call {
        error: String,
        code: u64,

        canister_id: Principal,
        method: String,
    },

    /// Backend refers to, e.g., the DEX canister that this asset manager talks to.
    Backend { error: String, code: u64 },

    /// The service is currently not available; please call back later.
    TemporarilyUnavailable { code: u64 },

    /// An exotic error that cannot be categorized using the tags above.
    Generic {
        error: String,
        code: u64,
        name: Option<String>,
    },
}

/// Most operations that a Treasury Manager performs are (direct or indirect) ledger transactions.
/// However, for generality, any call from the Treasury Manager can be recorded in the audit trail,
/// even if it is not related to any literal ledger transaction, e.g., adding a token to a DEX
/// for the first time, or checking the latest ledger metadata.
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Transaction {
    pub timestamp_ns: u64,
    pub canister_id: Principal,

    pub result: Result<TransactionWitness, TransactionError>,
    pub purpose: String,

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

    pub sender: Option<Account>,
    pub receiver: Option<Account>,
}

/// Most of the time, this just points to the Ledger block index. But for generality, once can
/// also use this structure for representing witnesses of non-ledger transactions, e.g., from adding
/// a token to a DEX for the first time.
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
