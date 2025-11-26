// Prevents warnings from the Derivative macro.
#![allow(clippy::needless_lifetimes)]

use candid::{CandidType, Nat, Principal};
use derivative::Derivative;
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
};

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

impl Balance {
    pub fn new(amount_decimals: u64, account: Option<Account>, name: Option<String>) -> Self {
        Self {
            amount_decimals: Nat::from(amount_decimals),
            account,
            name,
        }
    }

    fn zero(account: Option<Account>, name: Option<String>) -> Self {
        Self::new(0, account, name)
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BalanceBook {
    pub treasury_owner: Option<Balance>,
    pub treasury_manager: Option<Balance>,
    pub external_custodian: Option<Balance>,
    pub fee_collector: Option<Balance>,
    pub payees: Option<Balance>,
    pub payers: Option<Balance>,
    /// An account in which items are entered temporarily before allocation to the correct
    /// or final account, e.g., due to transient errors.
    pub suspense: Option<Balance>,
}

impl BalanceBook {
    pub fn empty() -> Self {
        Self {
            treasury_owner: None,
            treasury_manager: None,
            external_custodian: None,
            fee_collector: None,
            payees: None,
            payers: None,
            suspense: None,
        }
    }

    pub fn with_treasury_owner(mut self, account: Account, name: String) -> Self {
        self.treasury_owner = Some(Balance::zero(Some(account), Some(name)));
        self
    }

    pub fn with_treasury_manager(mut self, account: Account, name: String) -> Self {
        self.treasury_manager = Some(Balance::zero(Some(account), Some(name)));
        self
    }

    pub fn with_external_custodian(
        mut self,
        account: Option<Account>,
        name: Option<String>,
    ) -> Self {
        self.external_custodian = Some(Balance::zero(account, name));
        self
    }

    pub fn with_fee_collector(mut self, account: Option<Account>, name: Option<String>) -> Self {
        self.fee_collector = Some(Balance::zero(account, name));
        self
    }

    pub fn with_payees(mut self, account: Option<Account>, name: Option<String>) -> Self {
        self.payees = Some(Balance::zero(account, name));
        self
    }

    pub fn with_payers(mut self, account: Option<Account>, name: Option<String>) -> Self {
        self.payers = Some(Balance::zero(account, name));
        self
    }

    pub fn with_suspense(mut self, name: Option<String>) -> Self {
        self.suspense = Some(Balance::zero(None, name));
        self
    }

    pub fn treasury_owner(mut self, amount_decimals: u64) -> Self {
        if let Some(treasury_owner) = self.treasury_owner.as_mut() {
            treasury_owner.amount_decimals = Nat::from(amount_decimals)
        }
        self
    }

    pub fn treasury_manager(mut self, amount_decimals: u64) -> Self {
        if let Some(treasury_manager) = self.treasury_manager.as_mut() {
            treasury_manager.amount_decimals = Nat::from(amount_decimals)
        }
        self
    }

    pub fn external_custodian(mut self, amount_decimals: u64) -> Self {
        if let Some(external_custodian) = self.external_custodian.as_mut() {
            external_custodian.amount_decimals = Nat::from(amount_decimals)
        }
        self
    }

    pub fn fee_collector(mut self, amount_decimals: u64) -> Self {
        if let Some(fee_collector) = self.fee_collector.as_mut() {
            fee_collector.amount_decimals = Nat::from(amount_decimals)
        }
        self
    }

    pub fn suspense(mut self, amount_decimals: u64) -> Self {
        if let Some(suspense) = self.suspense.as_mut() {
            suspense.amount_decimals = Nat::from(amount_decimals)
        }
        self
    }
}

#[derive(CandidType, Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Balances {
    pub timestamp_ns: u64,
    pub asset_to_balances: Option<BTreeMap<Asset, BalanceBook>>,
}

pub type TreasuryManagerResult = Result<Balances, Vec<Error>>;

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Error {
    pub code: u64,
    pub message: String,
    pub kind: ErrorKind,
}

fn fmt_principal_as_string(
    principal: &Principal,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{principal}")
}

#[derive(CandidType, Clone, Derivative, Deserialize, PartialEq, Serialize)]
#[derivative(Debug)]
pub enum ErrorKind {
    /// Prevents the call from being attempted.
    Precondition {},

    /// Prevents the response from being interpreted.
    Postcondition {},

    /// An error that occurred while calling a canister.
    Call {
        method: String,
        #[derivative(Debug(format_with = "fmt_principal_as_string"))]
        canister_id: Principal,
    },

    /// Backend refers to, e.g., the DEX canister that this asset manager talks to.
    Backend {},

    /// The service is currently not available; please call back later.
    TemporarilyUnavailable {},

    /// An exotic error that cannot be categorized using the tags above.
    Generic { generic_error_name: String },
}

impl Error {
    pub fn new_precondition(message: impl ToString) -> Self {
        Self {
            code: 1,
            message: message.to_string(),
            kind: ErrorKind::Precondition {},
        }
    }

    pub fn new_postcondition(message: String) -> Self {
        Self {
            code: 2,
            message,
            kind: ErrorKind::Postcondition {},
        }
    }

    pub fn new_call(method: String, canister_id: Principal, message: String) -> Self {
        Self {
            code: 3,
            message,
            kind: ErrorKind::Call {
                method,
                canister_id,
            },
        }
    }

    pub fn new_backend(message: String) -> Self {
        Self {
            code: 4,
            message,
            kind: ErrorKind::Backend {},
        }
    }

    pub fn new_temporarily_unavailable(message: String) -> Self {
        Self {
            code: 5,
            message,
            kind: ErrorKind::TemporarilyUnavailable {},
        }
    }

    pub fn new_generic(code: u64, generic_error_name: String, message: String) -> Self {
        Self {
            code,
            message,
            kind: ErrorKind::Generic { generic_error_name },
        }
    }
}

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

#[derive(CandidType, Clone, Copy, Derivative, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[derivative(Debug)]
pub struct Account {
    #[derivative(Debug(format_with = "fmt_principal_as_string"))]
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
    pub index: usize,
    pub is_final: bool,
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
    pub operation: Operation,
    pub step: Step,
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

impl Display for TreasuryManagerOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreasuryManager.{}-{}", self.operation.name(), self.step)
    }
}

/// To be used for ledger transaction memos.
impl From<TreasuryManagerOperation> for Vec<u8> {
    fn from(operation: TreasuryManagerOperation) -> Self {
        operation.to_string().as_bytes().to_vec()
    }
}

/// Most operations that a Treasury Manager performs are (direct or indirect) ledger transactions.
/// However, for generality, any call from the Treasury Manager can be recorded in the audit trail,
/// even if it is not related to any literal ledger transaction, e.g., adding a token to a DEX
/// for the first time, or checking the latest ledger metadata.
#[derive(CandidType, Clone, Derivative, Deserialize, PartialEq, Serialize)]
#[derivative(Debug)]
pub struct Transaction {
    pub timestamp_ns: u64,

    #[derivative(Debug(format_with = "fmt_principal_as_string"))]
    pub canister_id: Principal,

    pub result: Result<TransactionWitness, Error>,
    pub purpose: String,

    pub treasury_manager_operation: TreasuryManagerOperation,
}

impl Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{} {} {}",
            self.treasury_manager_operation,
            match &self.result {
                Ok(_) => "✓",
                Err(_) => "✗",
            },
            self.canister_id,
            self.purpose,
        )
    }
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct AuditTrail {
    pub transactions: Vec<Transaction>,
}

#[derive(CandidType, Clone, Derivative, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derivative(Debug)]
pub enum Asset {
    Token {
        symbol: String,

        #[derivative(Debug(format_with = "fmt_principal_as_string"))]
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

/// Most of the time, this just points to the Ledger block index. But for generality, one can
/// also use this structure for representing witnesses of non-ledger transactions, e.g., from adding
/// a token to a DEX for the first time.
#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum TransactionWitness {
    Pending,

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
