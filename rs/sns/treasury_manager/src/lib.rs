use candid::{CandidType, Nat, Principal};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::str::FromStr;

pub const MAX_SYMBOL_BYTES: usize = 10;

#[derive(CandidType, Clone, Debug, Deserialize)]
pub struct TreasuryManagerInit {
    pub assets: Vec<Asset>,
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

#[derive(CandidType, Clone, Copy, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol {
    /// An Ascii string of up to MAX_SYMBOL_BYTES, e.g., "CHAT" or "ICP".
    /// Stored as a fixed-size byte array, so the whole `Asset` type can derive `Copy`.
    /// Can be created from
    repr: [u8; MAX_SYMBOL_BYTES],
}

fn bytes_to_string(bytes: &[u8]) -> String {
    // Find the first null byte (if any)
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    // Convert only ASCII characters
    bytes[..null_pos].iter().map(|&c| c as char).collect()
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_str = bytes_to_string(&self.repr);
        write!(f, "{}", symbol_str)
    }
}

impl std::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_str = bytes_to_string(&self.repr);
        write!(f, "{}", symbol_str)
    }
}

#[derive(CandidType, Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Asset {
    Token {
        symbol: Symbol,
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

impl Asset {
    pub fn new_token(
        symbol: &str,
        ledger_canister_id: impl Into<Principal> + Send,
    ) -> Result<Self, String> {
        let symbol = Symbol::try_from(symbol)?;
        let ledger_canister_id = ledger_canister_id.into();
        Ok(Asset::Token {
            symbol,
            ledger_canister_id,
        })
    }

    pub fn symbol(&self) -> String {
        match self {
            Asset::Token { symbol, .. } => symbol.to_string(),
        }
    }

    pub fn ledger_canister_id(&self) -> Principal {
        match self {
            Asset::Token {
                ledger_canister_id, ..
            } => *ledger_canister_id,
        }
    }
}

fn take_bytes(input: &str) -> [u8; MAX_SYMBOL_BYTES] {
    let mut result = [0u8; MAX_SYMBOL_BYTES];
    let bytes = input.as_bytes();

    let copy_len = std::cmp::min(bytes.len(), MAX_SYMBOL_BYTES);
    result[..copy_len].copy_from_slice(&bytes[..copy_len]);

    result
}

fn is_valid_symbol_character(b: &u8) -> bool {
    *b == 0 || b.is_ascii() && b.is_ascii_graphic()
}

impl TryFrom<[u8; 10]> for Symbol {
    type Error = String;

    fn try_from(value: [u8; 10]) -> Result<Self, Self::Error> {
        // Check that the symbol is valid ASCII.
        if !value.iter().all(is_valid_symbol_character) {
            return Err(format!("Symbol must be ASCII and graphic; got {:?}", value));
        }

        Ok(Symbol { repr: value })
    }
}

impl TryFrom<&str> for Symbol {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > MAX_SYMBOL_BYTES {
            return Err(format!(
                "Symbol must not exceed {} bytes or characters, got {} bytes.",
                MAX_SYMBOL_BYTES,
                value.len()
            ));
        }

        let bytes = take_bytes(&value);

        let symbol = Self::try_from(bytes)?;

        Ok(symbol)
    }
}

/// (symbol, ledger_canister_id)
impl TryFrom<(String, String)> for Asset {
    type Error = String;

    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let (symbol, ledger_canister_id) = value;

        let symbol = Symbol::try_from(symbol.as_str())?;

        let ledger_canister_id = Principal::from_str(&ledger_canister_id).map_err(|_| {
            format!(
                "Cannot interpret second component as a principal: {}",
                ledger_canister_id
            )
        })?;

        Ok(Asset::Token {
            symbol,
            ledger_canister_id,
        })
    }
}
