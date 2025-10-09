//! Candid types for the canister enpoints (arguments and return types)

use candid::{CandidType, Principal};
use icrc_ledger_types::icrc1::account::Subaccount;
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct GetDogeAddressArgs {
    pub owner: Option<Principal>,
    pub subaccount: Option<Subaccount>,
}

/// The arguments of the [retrieve_btc_with_approval] endpoint.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveDogeWithApprovalArgs {
    /// Amount to retrieve in koinu (the smallest denomination of DOGE)
    pub amount: u64,

    /// Address where to send dogecoins
    pub address: String,

    /// The subaccount to burn ckDOGE from.
    pub from_subaccount: Option<Subaccount>,
}

impl From<RetrieveDogeWithApprovalArgs>
    for ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalArgs
{
    fn from(args: RetrieveDogeWithApprovalArgs) -> Self {
        Self {
            address: args.address,
            amount: args.amount,
            from_subaccount: args.from_subaccount,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveDogeOk {
    /// The index of the burn block on the ckDOGE ledger
    pub block_index: u64,
}

impl From<ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcOk> for RetrieveDogeOk {
    fn from(args: ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcOk) -> Self {
        Self {
            block_index: args.block_index,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum RetrieveDogeWithApprovalError {
    /// There is another request for this principal.
    AlreadyProcessing,

    /// The withdrawal amount is too low.
    AmountTooLow(u64),

    /// The Bitcoin address is not valid.
    MalformedAddress(String),

    /// The withdrawal account does not hold the requested ckBTC amount.
    InsufficientFunds { balance: u64 },

    /// The caller didn't approve enough funds for spending.
    InsufficientAllowance { allowance: u64 },

    /// There are too many concurrent requests, retry later.
    TemporarilyUnavailable(String),

    /// A generic error reserved for future extensions.
    GenericError {
        error_message: String,
        /// See the [ErrorCode] enum above for the list of possible values.
        error_code: u64,
    },
}

impl From<ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError>
    for RetrieveDogeWithApprovalError
{
    fn from(args: ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError) -> Self {
        match args {
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::AlreadyProcessing => Self::AlreadyProcessing,
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::AmountTooLow(amount) => Self::AmountTooLow(amount),
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::MalformedAddress(addr) => Self::MalformedAddress(addr),
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::InsufficientFunds { balance } => Self::InsufficientFunds { balance },
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::InsufficientAllowance { allowance } => Self::InsufficientAllowance { allowance },
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::TemporarilyUnavailable(msg) => Self::TemporarilyUnavailable(msg),
            ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcWithApprovalError::GenericError { error_message, error_code } => Self::GenericError { error_message, error_code },
        }
    }
}
