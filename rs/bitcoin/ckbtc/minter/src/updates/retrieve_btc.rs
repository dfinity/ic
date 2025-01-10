use super::{get_btc_address::init_ecdsa_public_key, get_withdrawal_account::compute_subaccount};
use crate::logs::P0;
use crate::logs::P1;
use crate::management::check_withdrawal_destination_address;
use crate::memo::{BurnMemo, Status};
use crate::tasks::{schedule_now, TaskType};
use crate::{
    address::{account_to_bitcoin_address, BitcoinAddress, ParseAddressError},
    guard::{retrieve_btc_guard, GuardError},
    state::{self, mutate_state, read_state, RetrieveBtcRequest},
    IC_CANISTER_RUNTIME,
};
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_checker::CheckAddressResponse;
use ic_canister_log::log;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::account::Subaccount;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use num_traits::cast::ToPrimitive;

const MAX_CONCURRENT_PENDING_REQUESTS: usize = 1000;

/// The arguments of the [retrieve_btc] endpoint.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveBtcArgs {
    // amount to retrieve in satoshi
    pub amount: u64,

    // address where to send bitcoins
    pub address: String,
}

/// The arguments of the [retrieve_btc_with_approval] endpoint.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveBtcWithApprovalArgs {
    // amount to retrieve in satoshi
    pub amount: u64,

    // address where to send bitcoins
    pub address: String,

    // The subaccount to burn ckBTC from.
    pub from_subaccount: Option<Subaccount>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveBtcOk {
    // the index of the burn block on the ckbtc ledger
    pub block_index: u64,
}

pub enum ErrorCode {
    // The retrieval address didn't pass the Bitcoin check.
    TaintedAddress = 1,
    CheckCallFailed = 2,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum RetrieveBtcError {
    /// There is another request for this principal.
    AlreadyProcessing,

    /// The withdrawal amount is too low.
    AmountTooLow(u64),

    /// The Bitcoin address is not valid.
    MalformedAddress(String),

    /// The withdrawal account does not hold the requested ckBTC amount.
    InsufficientFunds { balance: u64 },

    /// There are too many concurrent requests, retry later.
    TemporarilyUnavailable(String),

    /// A generic error reserved for future extensions.
    GenericError {
        error_message: String,
        /// See the [ErrorCode] enum above for the list of possible values.
        error_code: u64,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum RetrieveBtcWithApprovalError {
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

impl From<GuardError> for RetrieveBtcWithApprovalError {
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

impl From<ParseAddressError> for RetrieveBtcWithApprovalError {
    fn from(e: ParseAddressError) -> Self {
        Self::MalformedAddress(e.to_string())
    }
}

pub async fn retrieve_btc(args: RetrieveBtcArgs) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    let caller = ic_cdk::caller();

    state::read_state(|s| s.mode.is_withdrawal_available_for(&caller))
        .map_err(RetrieveBtcError::TemporarilyUnavailable)?;

    let ecdsa_public_key = init_ecdsa_public_key().await;
    let main_address = account_to_bitcoin_address(
        &ecdsa_public_key,
        &Account {
            owner: ic_cdk::id(),
            subaccount: None,
        },
    );

    if args.address == main_address.display(state::read_state(|s| s.btc_network)) {
        ic_cdk::trap("illegal retrieve_btc target");
    }

    let _guard = retrieve_btc_guard(caller)?;
    let (min_retrieve_amount, btc_network) =
        read_state(|s| (s.fee_based_retrieve_btc_min_amount, s.btc_network));

    if args.amount < min_retrieve_amount {
        return Err(RetrieveBtcError::AmountTooLow(min_retrieve_amount));
    }

    let parsed_address = BitcoinAddress::parse(&args.address, btc_network)?;
    if read_state(|s| s.count_incomplete_retrieve_btc_requests() >= MAX_CONCURRENT_PENDING_REQUESTS)
    {
        return Err(RetrieveBtcError::TemporarilyUnavailable(
            "too many pending retrieve_btc requests".to_string(),
        ));
    }

    let balance = balance_of(caller).await?;
    if args.amount > balance {
        return Err(RetrieveBtcError::InsufficientFunds { balance });
    }

    let btc_checker_principal = read_state(|s| {
        s.btc_checker_principal
            .expect("BUG: upgrade procedure must ensure that the Bitcoin checker principal is set")
            .get()
            .into()
    });
    let status = check_address(btc_checker_principal, args.address.clone()).await?;
    match status {
        BtcAddressCheckStatus::Tainted => {
            log!(
                P1,
                "rejected an attempt to withdraw {} BTC to address {} due to failed Bitcoin check",
                crate::tx::DisplayAmount(args.amount),
                args.address,
            );
            return Err(RetrieveBtcError::GenericError {
                error_message: "Destination address is tainted".to_string(),
                error_code: ErrorCode::TaintedAddress as u64,
            });
        }
        BtcAddressCheckStatus::Clean => {}
    }

    let burn_memo = BurnMemo::Convert {
        address: Some(&args.address),
        kyt_fee: None,
        status: Some(Status::Accepted),
    };
    let block_index =
        burn_ckbtcs(caller, args.amount, crate::memo::encode(&burn_memo).into()).await?;

    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
        block_index,
        received_at: ic_cdk::api::time(),
        kyt_provider: None,
        reimbursement_account: Some(Account {
            owner: caller,
            subaccount: None,
        }),
    };

    log!(
        P1,
        "accepted a retrieve btc request for {} BTC to address {} (block_index = {})",
        crate::tx::DisplayAmount(request.amount),
        args.address,
        request.block_index
    );

    mutate_state(|s| state::audit::accept_retrieve_btc_request(s, request, &IC_CANISTER_RUNTIME));

    assert_eq!(
        crate::state::RetrieveBtcStatus::Pending,
        read_state(|s| s.retrieve_btc_status(block_index))
    );

    schedule_now(TaskType::ProcessLogic, &IC_CANISTER_RUNTIME);

    Ok(RetrieveBtcOk { block_index })
}

pub async fn retrieve_btc_with_approval(
    args: RetrieveBtcWithApprovalArgs,
) -> Result<RetrieveBtcOk, RetrieveBtcWithApprovalError> {
    let caller = ic_cdk::caller();

    state::read_state(|s| s.mode.is_withdrawal_available_for(&caller))
        .map_err(RetrieveBtcWithApprovalError::TemporarilyUnavailable)?;

    let ecdsa_public_key = init_ecdsa_public_key().await;
    let main_address = account_to_bitcoin_address(
        &ecdsa_public_key,
        &Account {
            owner: ic_cdk::id(),
            subaccount: None,
        },
    );

    if args.address == main_address.display(state::read_state(|s| s.btc_network)) {
        ic_cdk::trap("illegal retrieve_btc target");
    }

    let _guard = retrieve_btc_guard(caller)?;
    let (min_retrieve_amount, btc_network) =
        read_state(|s| (s.fee_based_retrieve_btc_min_amount, s.btc_network));
    if args.amount < min_retrieve_amount {
        return Err(RetrieveBtcWithApprovalError::AmountTooLow(
            min_retrieve_amount,
        ));
    }
    let parsed_address = BitcoinAddress::parse(&args.address, btc_network)?;
    if read_state(|s| s.count_incomplete_retrieve_btc_requests() >= MAX_CONCURRENT_PENDING_REQUESTS)
    {
        return Err(RetrieveBtcWithApprovalError::TemporarilyUnavailable(
            "too many pending retrieve_btc requests".to_string(),
        ));
    }

    let btc_checker_principal = read_state(|s| {
        s.btc_checker_principal
            .expect("BUG: upgrade procedure must ensure that the Bitcoin checker principal is set")
            .get()
            .into()
    });

    match check_address(btc_checker_principal, parsed_address.display(btc_network)).await {
        Err(error) => {
            return Err(RetrieveBtcWithApprovalError::GenericError {
                error_message: format!(
                    "Failed to call Bitcoin checker canister with error: {:?}",
                    error
                ),
                error_code: ErrorCode::CheckCallFailed as u64,
            })
        }
        Ok(status) => match status {
            BtcAddressCheckStatus::Tainted => {
                return Err(RetrieveBtcWithApprovalError::GenericError {
                    error_message: "Destination address is tainted".to_string(),
                    error_code: ErrorCode::TaintedAddress as u64,
                });
            }
            BtcAddressCheckStatus::Clean => {}
        },
    }

    let burn_memo_icrc2 = BurnMemo::Convert {
        address: Some(&args.address),
        kyt_fee: None,
        status: None,
    };
    let block_index = burn_ckbtcs_icrc2(
        Account {
            owner: caller,
            subaccount: args.from_subaccount,
        },
        args.amount,
        crate::memo::encode(&burn_memo_icrc2).into(),
    )
    .await?;

    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
        block_index,
        received_at: ic_cdk::api::time(),
        kyt_provider: None,
        reimbursement_account: Some(Account {
            owner: caller,
            subaccount: args.from_subaccount,
        }),
    };

    mutate_state(|s| state::audit::accept_retrieve_btc_request(s, request, &IC_CANISTER_RUNTIME));

    assert_eq!(
        crate::state::RetrieveBtcStatus::Pending,
        read_state(|s| s.retrieve_btc_status(block_index))
    );

    schedule_now(TaskType::ProcessLogic, &IC_CANISTER_RUNTIME);

    Ok(RetrieveBtcOk { block_index })
}

async fn balance_of(user: Principal) -> Result<u64, RetrieveBtcError> {
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: read_state(|s| s.ledger_id.get().into()),
    };
    let minter = ic_cdk::id();
    let subaccount = compute_subaccount(PrincipalId(user), 0);
    let result = client
        .balance_of(Account {
            owner: minter,
            subaccount: Some(subaccount),
        })
        .await
        .map_err(|(code, msg)| {
            RetrieveBtcError::TemporarilyUnavailable(format!(
                "cannot enqueue a balance_of request: {} (reject_code = {})",
                msg, code
            ))
        })?;
    Ok(result.0.to_u64().expect("nat does not fit into u64"))
}

async fn burn_ckbtcs(user: Principal, amount: u64, memo: Memo) -> Result<u64, RetrieveBtcError> {
    debug_assert!(memo.0.len() <= crate::CKBTC_LEDGER_MEMO_SIZE as usize);

    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: read_state(|s| s.ledger_id.get().into()),
    };
    let minter = ic_cdk::id();
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
            memo: Some(memo),
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
        Ok(block_index) => Ok(block_index.0.to_u64().expect("nat does not fit into u64")),
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

async fn burn_ckbtcs_icrc2(
    user: Account,
    amount: u64,
    memo: Memo,
) -> Result<u64, RetrieveBtcWithApprovalError> {
    debug_assert!(memo.0.len() <= crate::CKBTC_LEDGER_MEMO_SIZE as usize);

    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: read_state(|s| s.ledger_id.get().into()),
    };
    let minter = ic_cdk::id();
    let result = client
        .transfer_from(TransferFromArgs {
            spender_subaccount: None,
            from: user,
            to: Account {
                owner: minter,
                subaccount: None,
            },
            amount: Nat::from(amount),
            fee: None,
            memo: Some(memo),
            created_at_time: None,
        })
        .await
        .map_err(|(code, msg)| {
            RetrieveBtcWithApprovalError::TemporarilyUnavailable(format!(
                "cannot enqueue a burn transaction: {} (reject_code = {})",
                msg, code
            ))
        })?;

    match result {
        Ok(block_index) => Ok(block_index.0.to_u64().expect("nat does not fit into u64")),
        Err(TransferFromError::InsufficientFunds { balance }) => Err(RetrieveBtcWithApprovalError::InsufficientFunds {
            balance: balance.0.to_u64().expect("unreachable: ledger balance does not fit into u64")
        }),
        Err(TransferFromError::InsufficientAllowance { allowance }) => Err(RetrieveBtcWithApprovalError::InsufficientAllowance {
            allowance: allowance.0.to_u64().expect("unreachable: ledger balance does not fit into u64")
        }),
        Err(TransferFromError::TemporarilyUnavailable) => {
            Err(RetrieveBtcWithApprovalError::TemporarilyUnavailable(
                "cannot burn ckBTC: the ledger is busy".to_string(),
            ))
        }
        Err(TransferFromError::GenericError { error_code, message }) => {
            Err(RetrieveBtcWithApprovalError::TemporarilyUnavailable(format!(
                "cannot burn ckBTC: the ledger fails with: {} (error code {})", message, error_code
            )))
        }
        Err(TransferFromError::BadFee { expected_fee }) => ic_cdk::trap(&format!(
            "unreachable: the ledger demands the fee of {} even though the fee field is unset",
            expected_fee
        )),
        Err(TransferFromError::Duplicate { duplicate_of }) => ic_cdk::trap(&format!(
            "unreachable: the ledger reports duplicate ({}) even though the create_at_time field is unset",
            duplicate_of
        )),
        Err(TransferFromError::CreatedInFuture {..}) => ic_cdk::trap(
            "unreachable: the ledger reports CreatedInFuture even though the create_at_time field is unset"
        ),
        Err(TransferFromError::TooOld) => ic_cdk::trap(
            "unreachable: the ledger reports TooOld even though the create_at_time field is unset"
        ),
        Err(TransferFromError::BadBurn { min_burn_amount }) => ic_cdk::trap(&format!(
            "the minter is misconfigured: retrieve_btc_min_amount {} is less than ledger's min_burn_amount {}",
            read_state(|s| s.retrieve_btc_min_amount),
            min_burn_amount
        )),
    }
}

/// The outcome of a Bitcoin address check.
#[derive(Copy, Clone, Eq, PartialEq, Debug, serde::Deserialize, serde::Serialize)]
pub enum BtcAddressCheckStatus {
    /// The Bitcoin check did not find any issues with the address.
    Clean,
    /// The Bitcoin check found issues with the address in question.
    Tainted,
}
async fn check_address(
    btc_checker_principal: Principal,
    address: String,
) -> Result<BtcAddressCheckStatus, RetrieveBtcError> {
    match check_withdrawal_destination_address(btc_checker_principal, address.clone())
        .await
        .map_err(|call_err| {
            RetrieveBtcError::TemporarilyUnavailable(format!(
                "Failed to call Bitcoin checker canister: {}",
                call_err
            ))
        })? {
        CheckAddressResponse::Failed => {
            log!(P0, "Discovered a tainted btc address {}", address);
            Ok(BtcAddressCheckStatus::Tainted)
        }
        CheckAddressResponse::Passed => Ok(BtcAddressCheckStatus::Clean),
    }
}
