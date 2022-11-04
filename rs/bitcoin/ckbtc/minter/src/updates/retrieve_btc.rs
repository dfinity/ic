use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};

use super::{get_btc_address::init_ecdsa_public_key, get_withdrawal_account::compute_subaccount};
use crate::{
    address::ParseAddressError,
    guard::{retrieve_btc_guard, GuardError},
    state::{mutate_state, read_state, RetrieveBtcRequest},
};

const MAX_CONCURRENT_PENDING_REQUESTS: usize = 100;

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct RetrieveBtcArgs {
    // amount to retrieve in satoshi
    pub amount: u64,

    // bitcoin fee to use
    pub fee: Option<u64>,

    // address where to send bitcoins
    pub address: String,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub struct RetrieveBtcOk {
    // the index of the burn block on the ckbtc ledger
    pub block_index: u64,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum RetrieveBtcError {
    /// There is another request for this principle
    AlreadyProcessing,

    /// The amount to withdraw is too low
    AmountTooLow(u64),

    /// The burn call to the Ledger failed
    LedgerConnectionError(i32, String),

    /// The Ledger rejected the burn operation
    LedgerError(TransferError),

    /// The bitcoin fee is too low
    FeeTooLow(u64),

    /// The bitcoin address is not valid
    MalformedAddress(String),

    /// There are too many concurrent requests, retry later
    TooManyConcurrentRequests,
}

impl From<GuardError> for RetrieveBtcError {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::AlreadyProcessing => Self::AlreadyProcessing,
            GuardError::TooManyConcurrentRequests => Self::TooManyConcurrentRequests,
        }
    }
}

impl From<TransferError> for RetrieveBtcError {
    fn from(e: TransferError) -> Self {
        Self::LedgerError(e)
    }
}

impl From<ParseAddressError> for RetrieveBtcError {
    fn from(e: ParseAddressError) -> Self {
        Self::MalformedAddress(e.to_string())
    }
}

pub async fn retrieve_btc(args: RetrieveBtcArgs) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    let caller = ic_cdk::caller();
    init_ecdsa_public_key().await;
    let _guard = retrieve_btc_guard(caller)?;
    let (default_fee, min_amount, btc_network) = read_state(|s| {
        (
            s.retrieve_btc_min_fee,
            s.retrieve_btc_min_amount,
            s.btc_network,
        )
    });
    let fee = args.fee.unwrap_or(default_fee);
    if fee < default_fee {
        return Err(RetrieveBtcError::FeeTooLow(default_fee));
    }
    if args.amount < min_amount {
        return Err(RetrieveBtcError::AmountTooLow(min_amount));
    }
    let parsed_address = crate::address::parse_address(&args.address, btc_network)?;
    if read_state(|s| s.pending_retrieve_btc_requests.len() >= MAX_CONCURRENT_PENDING_REQUESTS) {
        return Err(RetrieveBtcError::TooManyConcurrentRequests);
    }

    let block_index = burn_ckbtcs(caller, args.amount).await?;
    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
        fee,
        block_index,
    };
    mutate_state(|s| s.pending_retrieve_btc_requests.push_back(request));
    Ok(RetrieveBtcOk { block_index })
}

async fn burn_ckbtcs(user: Principal, amount: u64) -> Result<u64, RetrieveBtcError> {
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: read_state(|s| s.ledger_id.get().into()),
    };
    let minter = PrincipalId(ic_cdk::id());
    let from_subaccount = compute_subaccount(PrincipalId(user), 0);
    let block_index = client
        .transfer(TransferArg {
            from_subaccount: Some(from_subaccount),
            to: Account {
                owner: minter,
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        })
        .await
        .map_err(|(code, msg)| RetrieveBtcError::LedgerConnectionError(code, msg))??;
    Ok(block_index)
}
