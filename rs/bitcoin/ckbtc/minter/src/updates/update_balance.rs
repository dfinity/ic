use crate::logs::{P0, P1};
use crate::memo::MintMemo;
use crate::state::{mutate_state, read_state, SuspendedReason, UtxoCheckStatus};
use crate::tasks::{schedule_now, TaskType};
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_btc_checker::CheckTransactionResponse;
use ic_btc_interface::{GetUtxosError, GetUtxosResponse, OutPoint, Utxo};
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
    management::{get_utxos, CallError, CallSource},
    metrics::observe_latency,
    state,
    tx::{DisplayAmount, DisplayOutpoint},
    updates::get_btc_address,
    CanisterRuntime, Timestamp,
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
    /// The UTXO value does not cover the Bitcoin check cost.
    ValueTooSmall(Utxo),
    /// The Bitcoin check found issues with the deposited UTXO.
    Tainted(Utxo),
    /// The deposited UTXO passed the Bitcoin check, but the minter failed to mint ckBTC on the ledger.
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
pub struct SuspendedUtxo {
    pub utxo: Utxo,
    pub reason: SuspendedReason,
    pub earliest_retry: u64,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub enum UpdateBalanceError {
    /// The minter experiences temporary issues, try the call again later.
    TemporarilyUnavailable(String),
    /// There is a concurrent [update_balance] invocation from the same caller.
    AlreadyProcessing,
    /// The minter didn't discover new UTXOs to process.
    NoNewUtxos {
        /// If there are new UTXOs that do not have enough
        /// confirmations yet, this field will contain the number of
        /// confirmations as observed by the minter.
        current_confirmations: Option<u32>,
        /// The minimum number of UTXO confirmation required for the minter to accept a UTXO.
        required_confirmations: u32,
        /// List of utxos that don't have enough confirmations yet to be processed.
        pending_utxos: Option<Vec<PendingUtxo>>,
        /// List of utxos that are suspended, either due to a too low amount or being tainted, and cannot yet be retried.
        suspended_utxos: Option<Vec<SuspendedUtxo>>,
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
pub async fn update_balance<R: CanisterRuntime>(
    args: UpdateBalanceArgs,
    runtime: &R,
) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    let caller = runtime.caller();
    if args.owner.unwrap_or(caller) == runtime.id() {
        ic_cdk::trap("cannot update minter's balance");
    }

    // Record start time of method execution for metrics
    let start_time = runtime.time();

    // When the minter is in the mode using a whitelist we only want a certain
    // set of principal to be able to mint. But we also want those principals
    // to mint at any desired address. Therefore, the check below is on "caller".
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

    let utxos = get_utxos(
        btc_network,
        &address,
        min_confirmations,
        CallSource::Client,
        runtime,
    )
    .await?
    .utxos;

    let now = Timestamp::from(runtime.time());
    let (processable_utxos, suspended_utxos) =
        state::read_state(|s| s.processable_utxos_for_account(utxos, &caller_account, &now));

    // Remove pending finalized transactions for the affected principal.
    state::mutate_state(|s| s.finalized_utxos.remove(&caller_account.owner));

    let satoshis_to_mint = processable_utxos.iter().map(|u| u.value).sum::<u64>();

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
            runtime,
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

        observe_latency(0, start_time, runtime.time());

        return Err(UpdateBalanceError::NoNewUtxos {
            current_confirmations,
            required_confirmations: min_confirmations,
            pending_utxos: Some(pending_utxos),
            suspended_utxos: Some(suspended_utxos),
        });
    }

    let token_name = match btc_network {
        ic_management_canister_types::BitcoinNetwork::Mainnet => "ckBTC",
        _ => "ckTESTBTC",
    };

    let check_fee = read_state(|s| s.check_fee);
    let mut utxo_statuses: Vec<UtxoStatus> = vec![];
    for utxo in processable_utxos {
        if utxo.value <= check_fee {
            mutate_state(|s| {
                state::audit::ignore_utxo(s, utxo.clone(), caller_account, now, runtime)
            });
            log!(
                P1,
                "Ignored UTXO {} for account {caller_account} because UTXO value {} is lower than the check fee {}",
                DisplayOutpoint(&utxo.outpoint),
                DisplayAmount(utxo.value),
                DisplayAmount(check_fee),
            );
            utxo_statuses.push(UtxoStatus::ValueTooSmall(utxo));
            continue;
        }
        let status = check_utxo(&utxo, &args, runtime).await?;
        mutate_state(|s| match status {
            UtxoCheckStatus::Clean => {
                state::audit::mark_utxo_checked(s, utxo.clone(), caller_account, runtime);
            }
            UtxoCheckStatus::Tainted => {
                state::audit::quarantine_utxo(s, utxo.clone(), caller_account, now, runtime);
            }
        });
        match status {
            UtxoCheckStatus::Tainted => {
                utxo_statuses.push(UtxoStatus::Tainted(utxo.clone()));
                continue;
            }
            UtxoCheckStatus::Clean => {}
        }
        let amount = utxo.value - check_fee;
        let memo = MintMemo::Convert {
            txid: Some(utxo.outpoint.txid.as_ref()),
            vout: Some(utxo.outpoint.vout),
            kyt_fee: Some(check_fee),
        };

        match runtime
            .mint_ckbtc(amount, caller_account, crate::memo::encode(&memo).into())
            .await
        {
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
                        runtime,
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

    schedule_now(TaskType::ProcessLogic, runtime);

    observe_latency(utxo_statuses.len(), start_time, runtime.time());

    Ok(utxo_statuses)
}

async fn check_utxo<R: CanisterRuntime>(
    utxo: &Utxo,
    args: &UpdateBalanceArgs,
    runtime: &R,
) -> Result<UtxoCheckStatus, UpdateBalanceError> {
    use ic_btc_checker::{CheckTransactionStatus, CHECK_TRANSACTION_CYCLES_REQUIRED};

    let btc_checker_principal = read_state(|s| {
        s.btc_checker_principal
            .expect("BUG: upgrade procedure must ensure that the Bitcoin checker principal is set")
            .get()
            .into()
    });

    if let Some(checked_utxo) = read_state(|s| s.checked_utxos.get(utxo).cloned()) {
        return Ok(checked_utxo.status);
    }
    for i in 0..MAX_CHECK_TRANSACTION_RETRY {
        match runtime
            .check_transaction(
                btc_checker_principal,
                utxo,
                CHECK_TRANSACTION_CYCLES_REQUIRED,
            )
            .await
            .map_err(|call_err| {
                UpdateBalanceError::TemporarilyUnavailable(format!(
                    "Failed to call Bitcoin checker canister: {}",
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
                    "The Bitcoin checker canister requires more cycles, Remaining tries: {}",
                    MAX_CHECK_TRANSACTION_RETRY - i - 1
                );
                continue;
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(status)) => {
                log!(
                    P1,
                    "The Bitcoin checker canister is temporarily unavailable: {:?}",
                    status
                );
                return Err(UpdateBalanceError::TemporarilyUnavailable(format!(
                    "The Bitcoin checker canister is temporarily unavailable: {:?}",
                    status
                )));
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(error)) => {
                log!(P1, "Bitcoin checker error: {:?}", error);
                return Err(UpdateBalanceError::GenericError {
                    error_code: ErrorCode::KytError as u64,
                    error_message: format!("Bitcoin checker error: {:?}", error),
                });
            }
        }
    }
    Err(UpdateBalanceError::GenericError {
        error_code: ErrorCode::KytError as u64,
        error_message: "The Bitcoin checker canister required too many calls to check_transaction"
            .to_string(),
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
