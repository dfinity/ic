use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use num_traits::cast::ToPrimitive;

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
    /// There is another request for this principal.
    AlreadyProcessing,

    /// The withdrawal amount is too low.
    AmountTooLow(u64),

    /// The bitcoin address is not valid.
    MalformedAddress(String),

    /// The withdrawal account does not hold the requested ckBTC amount.
    InsufficientFunds { balance: u64 },

    /// There are too many concurrent requests, retry later.
    TemporarilyUnavailable(String),

    /// A generic error reserved for future extensions.
    GenericError {
        error_message: String,
        error_code: u64,
    },
}

impl From<GuardError> for RetrieveBtcError {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::AlreadyProcessing => Self::AlreadyProcessing,
            GuardError::TooManyConcurrentRequests => {
                Self::TemporarilyUnavailable("too many concurrent requests".to_string())
            }
        }
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
    let (min_amount, btc_network) = read_state(|s| (s.retrieve_btc_min_amount, s.btc_network));
    if args.amount < min_amount {
        return Err(RetrieveBtcError::AmountTooLow(min_amount));
    }
    let parsed_address = crate::address::parse_address(&args.address, btc_network)?;
    if read_state(|s| s.pending_retrieve_btc_requests.len() >= MAX_CONCURRENT_PENDING_REQUESTS) {
        return Err(RetrieveBtcError::TemporarilyUnavailable(
            "too many pending retrieve_btc requests".to_string(),
        ));
    }

    let block_index = burn_ckbtcs(caller, args.amount).await?;
    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
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
    let result = client
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
        .map_err(|(code, msg)| {
            RetrieveBtcError::TemporarilyUnavailable(format!(
                "cannot enqueue a burn transaction: {} (reject_code = {})",
                msg, code
            ))
        })?;

    match result {
        Ok(block_index) => Ok(block_index),
        Err(TransferError::InsufficientFunds { balance }) => Err(RetrieveBtcError::InsufficientFunds {
            balance: balance.0.to_u64().expect("unreachable: ledger balance does not fit into u64")
        }),
        Err(TransferError::TemporarilyUnavailable) => {
            Err(RetrieveBtcError::TemporarilyUnavailable(
                "cannot burn ckBTC: the ledger is busy".to_string(),
            ))
        }
        Err(TransferError::GenericError { error_code, message }) => {
            Err(RetrieveBtcError::TemporarilyUnavailable(format!(
                "cannot burn ckBTC: the ledger fails with: {} (error code {})", message, error_code
            )))
        }
        Err(TransferError::BadFee { expected_fee }) => ic_cdk::trap(&format!(
            "unreachable: the ledger demands the fee of {} even though the fee field is unset",
            expected_fee
        )),
        Err(TransferError::Duplicate{ duplicate_of }) => ic_cdk::trap(&format!(
            "unreachable: the ledger reports duplicate ({}) even though the create_at_time field is unset",
            duplicate_of
        )),
        Err(TransferError::CreatedInFuture{..}) => ic_cdk::trap(
            "unreachable: the ledger reports CreatedInFuture even though the create_at_time field is unset"
        ),
        Err(TransferError::TooOld) => ic_cdk::trap(
            "unreachable: the ledger reports TooOld even though the create_at_time field is unset"
        ),
        Err(TransferError::BadBurn { min_burn_amount }) => ic_cdk::trap(&format!(
            "the minter is misconfigured: retrieve_btc_min_amount {} is less than ledger's min_burn_amount {}",
            read_state(|s| s.retrieve_btc_min_amount),
            min_burn_amount
        )),
    }
}
