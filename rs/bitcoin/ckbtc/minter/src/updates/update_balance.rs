use crate::logs::{P0, P1};
use crate::memo::MintMemo;
use crate::state::{mutate_state, read_state, UtxoCheckStatus};
use crate::tasks::{schedule_now, TaskType};
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_btc_interface::{GetUtxosError, GetUtxosResponse, OutPoint, Utxo};
use ic_btc_kyt::CheckTransactionResponse;
use ic_canister_log::log;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use num_traits::ToPrimitive;
use serde::Serialize;

// Max number of times of calling check_transaction with cycle payment, to avoid spending too
// many cycles.
const MAX_CHECK_TRANSACTION_RETRY: usize = 10;

use super::get_btc_address::init_ecdsa_public_key;

use crate::{
    guard::{balance_update_guard, GuardError},
    management::{check_transaction, get_utxos, CallError, CallSource},
    state,
    tx::{DisplayAmount, DisplayOutpoint},
    updates::get_btc_address,
    IC_CANISTER_RUNTIME,
};

/// The argument of the [update_balance] endpoint.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateBalanceArgs {
    /// The owner of the account on the ledger.
    /// The minter uses the caller principal if the owner is None.
    pub owner: Option<Principal>,
    /// The desired subaccount on the ledger, if any.
    pub subaccount: Option<Subaccount>,
}

/// The outcome of UTXO processing.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum UtxoStatus {
    /// The UTXO value does not cover the KYT check cost.
    ValueTooSmall(Utxo),
    /// The KYT check found issues with the deposited UTXO.
    Tainted(Utxo),
    /// The deposited UTXO passed the KYT check, but the minter failed to mint ckBTC on the ledger.
    /// The caller should retry the [update_balance] call.
    Checked(Utxo),
    /// The minter accepted the UTXO and minted ckBTC tokens on the ledger.
    Minted {
        /// The MINT transaction index on the ledger.
        block_index: u64,
        /// The minted amount (UTXO value minus fees).
        minted_amount: u64,
        /// The UTXO that caused the balance update.
        utxo: Utxo,
    },
}

pub enum ErrorCode {
    ConfigurationError = 1,
    KytError = 2,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct PendingUtxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub confirmations: u32,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum UpdateBalanceError {
    /// The minter experiences temporary issues, try the call again later.
    TemporarilyUnavailable(String),
    /// There is a concurrent [update_balance] invocation from the same caller.
    AlreadyProcessing,
    /// The minter didn't discover new UTXOs with enough confirmations.
    NoNewUtxos {
        /// If there are new UTXOs that do not have enough
        /// confirmations yet, this field will contain the number of
        /// confirmations as observed by the minter.
        current_confirmations: Option<u32>,
        /// The minimum number of UTXO confirmation required for the minter to accept a UTXO.
        required_confirmations: u32,
        /// List of utxos that don't have enough confirmations yet to be processed.
        pending_utxos: Option<Vec<PendingUtxo>>,
    },
    GenericError {
        error_code: u64,
        error_message: String,
    },
}

impl From<GuardError> for UpdateBalanceError {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::AlreadyProcessing => Self::AlreadyProcessing,
            GuardError::TooManyConcurrentRequests => {
                Self::TemporarilyUnavailable("too many concurrent requests".to_string())
            }
        }
    }
}

impl From<GetUtxosError> for UpdateBalanceError {
    fn from(e: GetUtxosError) -> Self {
        Self::GenericError {
            error_code: ErrorCode::ConfigurationError as u64,
            error_message: format!("failed to get UTXOs from the Bitcoin canister: {}", e),
        }
    }
}

impl From<TransferError> for UpdateBalanceError {
    fn from(e: TransferError) -> Self {
        Self::GenericError {
            error_code: ErrorCode::ConfigurationError as u64,
            error_message: format!("failed to mint tokens on the ledger: {:?}", e),
        }
    }
}

impl From<CallError> for UpdateBalanceError {
    fn from(e: CallError) -> Self {
        Self::TemporarilyUnavailable(e.to_string())
    }
}

/// Notifies the ckBTC minter to update the balance of the user subaccount.
pub async fn update_balance(
    args: UpdateBalanceArgs,
) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    let caller = ic_cdk::caller();
    if args.owner.unwrap_or(caller) == ic_cdk::id() {
        ic_cdk::trap("cannot update minter's balance");
    }

    // When the minter is in the mode using a whitelist we only want a certain
    // set of principal to be able to mint. But we also want those principals
    // to mint at any desired address. Therefore the check below is on "caller".
    state::read_state(|s| s.mode.is_deposit_available_for(&caller))
        .map_err(UpdateBalanceError::TemporarilyUnavailable)?;

    init_ecdsa_public_key().await;
    let _guard = balance_update_guard(args.owner.unwrap_or(caller))?;

    let caller_account = Account {
        owner: args.owner.unwrap_or(caller),
        subaccount: args.subaccount,
    };

    let address = state::read_state(|s| {
        get_btc_address::account_to_p2wpkh_address_from_state(s, &caller_account)
    });

    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    let utxos = get_utxos(btc_network, &address, min_confirmations, CallSource::Client)
        .await?
        .utxos;

    let new_utxos = state::read_state(|s| s.new_utxos_for_account(utxos, &caller_account));

    // Remove pending finalized transactions for the affected principal.
    state::mutate_state(|s| s.finalized_utxos.remove(&caller_account.owner));

    let satoshis_to_mint = new_utxos.iter().map(|u| u.value).sum::<u64>();

    if satoshis_to_mint == 0 {
        // We bail out early if there are no UTXOs to avoid creating a new entry
        // in the UTXOs map. If we allowed empty entries, malicious callers
        // could exhaust the canister memory.

        // We get the entire list of UTXOs again with a zero
        // confirmation limit so that we can indicate the approximate
        // wait time to the caller.
        let GetUtxosResponse {
            tip_height,
            mut utxos,
            ..
        } = get_utxos(
            btc_network,
            &address,
            /*min_confirmations=*/ 0,
            CallSource::Client,
        )
        .await?;

        utxos.retain(|u| {
            tip_height
                < u.height
                    .checked_add(min_confirmations)
                    .expect("bug: this shouldn't overflow")
                    .checked_sub(1)
                    .expect("bug: this shouldn't underflow")
        });
        let pending_utxos: Vec<PendingUtxo> = utxos
            .iter()
            .map(|u| PendingUtxo {
                outpoint: u.outpoint.clone(),
                value: u.value,
                confirmations: tip_height - u.height + 1,
            })
            .collect();

        let current_confirmations = pending_utxos.iter().map(|u| u.confirmations).max();

        return Err(UpdateBalanceError::NoNewUtxos {
            current_confirmations,
            required_confirmations: min_confirmations,
            pending_utxos: Some(pending_utxos),
        });
    }

    let token_name = match btc_network {
        ic_management_canister_types::BitcoinNetwork::Mainnet => "ckBTC",
        _ => "ckTESTBTC",
    };

    let kyt_fee = read_state(|s| s.kyt_fee);
    let mut utxo_statuses: Vec<UtxoStatus> = vec![];
    for utxo in new_utxos {
        if utxo.value <= kyt_fee {
            mutate_state(|s| crate::state::audit::ignore_utxo(s, utxo.clone()));
            log!(
                P1,
                "Ignored UTXO {} for account {caller_account} because UTXO value {} is lower than the KYT fee {}",
                DisplayOutpoint(&utxo.outpoint),
                DisplayAmount(utxo.value),
                DisplayAmount(kyt_fee),
            );
            utxo_statuses.push(UtxoStatus::ValueTooSmall(utxo));
            continue;
        }
        let status = kyt_check_utxo(&utxo, &args).await?;
        mutate_state(|s| {
            crate::state::audit::mark_utxo_checked(s, &utxo, None, status, None);
        });
        match status {
            UtxoCheckStatus::Tainted => {
                utxo_statuses.push(UtxoStatus::Tainted(utxo.clone()));
                continue;
            }
            UtxoCheckStatus::Clean => {}
        }
        let amount = utxo.value - kyt_fee;
        let memo = MintMemo::Convert {
            txid: Some(utxo.outpoint.txid.as_ref()),
            vout: Some(utxo.outpoint.vout),
            kyt_fee: Some(kyt_fee),
        };

        match mint(amount, caller_account, crate::memo::encode(&memo).into()).await {
            Ok(block_index) => {
                log!(
                    P1,
                    "Minted {amount} {token_name} for account {caller_account} corresponding to utxo {} with value {}",
                    DisplayOutpoint(&utxo.outpoint),
                    DisplayAmount(utxo.value),
                );
                state::mutate_state(|s| {
                    state::audit::add_utxos(
                        s,
                        Some(block_index),
                        caller_account,
                        vec![utxo.clone()],
                    )
                });
                utxo_statuses.push(UtxoStatus::Minted {
                    block_index,
                    utxo,
                    minted_amount: amount,
                });
            }
            Err(err) => {
                log!(
                    P0,
                    "Failed to mint ckBTC for UTXO {}: {:?}",
                    DisplayOutpoint(&utxo.outpoint),
                    err
                );
                utxo_statuses.push(UtxoStatus::Checked(utxo));
            }
        }
    }

    schedule_now(TaskType::ProcessLogic, &IC_CANISTER_RUNTIME);
    Ok(utxo_statuses)
}

async fn kyt_check_utxo(
    utxo: &Utxo,
    args: &UpdateBalanceArgs,
) -> Result<UtxoCheckStatus, UpdateBalanceError> {
    use ic_btc_kyt::{CheckTransactionStatus, CHECK_TRANSACTION_CYCLES_REQUIRED};

    let new_kyt_principal = read_state(|s| {
        s.new_kyt_principal
            .expect("BUG: upgrade procedure must ensure that the new KYT principal is set")
            .get()
            .into()
    });

    if let Some(checked_utxo) = read_state(|s| s.checked_utxos.get(utxo).cloned()) {
        return Ok(checked_utxo.status);
    }
    for i in 0..MAX_CHECK_TRANSACTION_RETRY {
        match check_transaction(new_kyt_principal, utxo, CHECK_TRANSACTION_CYCLES_REQUIRED)
            .await
            .map_err(|call_err| {
                UpdateBalanceError::TemporarilyUnavailable(format!(
                    "Failed to call KYT canister: {}",
                    call_err
                ))
            })? {
            CheckTransactionResponse::Failed(addresses) => {
                log!(
                    P0,
                    "Discovered a tainted UTXO {} (due to input addresses {}) for update_balance({:?}) call",
                    DisplayOutpoint(&utxo.outpoint),
                    addresses.join(","),
                    args,
                );
                return Ok(UtxoCheckStatus::Tainted);
            }
            CheckTransactionResponse::Passed => return Ok(UtxoCheckStatus::Clean),
            CheckTransactionResponse::Unknown(CheckTransactionStatus::NotEnoughCycles) => {
                log!(
                    P1,
                    "The KYT canister requires more cycles, Remaining tries: {}",
                    MAX_CHECK_TRANSACTION_RETRY - i - 1
                );
                continue;
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(status)) => {
                log!(
                    P1,
                    "The KYT canister is temporarily unavailable: {:?}",
                    status
                );
                return Err(UpdateBalanceError::TemporarilyUnavailable(format!(
                    "The KYT canister is temporarily unavailable: {:?}",
                    status
                )));
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(error)) => {
                log!(P1, "KYT error: {:?}", error);
                return Err(UpdateBalanceError::GenericError {
                    error_code: ErrorCode::KytError as u64,
                    error_message: format!("KYT error: {:?}", error),
                });
            }
        }
    }
    Err(UpdateBalanceError::GenericError {
        error_code: ErrorCode::KytError as u64,
        error_message: "The KYT canister required too many calls to check_transaction".to_string(),
    })
}

/// Mint an amount of ckBTC to an Account.
pub(crate) async fn mint(amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError> {
    debug_assert!(memo.0.len() <= crate::CKBTC_LEDGER_MEMO_SIZE as usize);
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: state::read_state(|s| s.ledger_id.get().into()),
    };
    let block_index = client
        .transfer(TransferArg {
            from_subaccount: None,
            to,
            fee: None,
            created_at_time: None,
            memo: Some(memo),
            amount: Nat::from(amount),
        })
        .await
        .map_err(|(code, msg)| {
            UpdateBalanceError::TemporarilyUnavailable(format!(
                "cannot mint ckbtc: {} (reject_code = {})",
                msg, code
            ))
        })??;
    Ok(block_index.0.to_u64().expect("nat does not fit into u64"))
}
