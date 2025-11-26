use crate::GetUtxosResponse;
use crate::logs::Priority;
use crate::memo::MintMemo;
use crate::state::{SuspendedReason, UtxoCheckStatus, mutate_state, read_state};
use crate::tasks::{TaskType, schedule_now};
use candid::{CandidType, Deserialize, Nat, Principal};
use canlog::log;
use ic_btc_checker::CheckTransactionResponse;
use ic_btc_interface::{GetUtxosError, OutPoint, Utxo};
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use num_traits::ToPrimitive;
use serde::Serialize;
#[cfg(feature = "tla")]
use std::collections::BTreeMap;

// Max number of times of calling check_transaction with cycle payment, to avoid spending too
// many cycles.
const MAX_CHECK_TRANSACTION_RETRY: usize = 10;

use super::get_btc_address::init_ecdsa_public_key;

use crate::{
    CanisterRuntime, Timestamp,
    guard::{GuardError, balance_update_guard},
    management::{CallError, CallSource, get_utxos},
    metrics::observe_update_call_latency,
    state,
    tx::{DisplayAmount, DisplayOutpoint},
};
#[cfg(feature = "tla")]
use crate::tla::{
    account_to_tla, btc_address_to_tla, utxo_set_to_tla, utxo_to_tla, UPDATE_BALANCE_DESC,
    dummy_utxo
};
#[cfg(feature = "tla")]
use crate::{
    tla::TLA_INSTRUMENTATION_STATE, tla::TLA_TRACES_LKEY, tla::TLA_TRACES_MUTEX,
    tla_log_locals, tla_log_request, tla_log_response, tla_snapshotter,
};
#[cfg(feature = "tla")]
use tla_instrumentation::{Destination, InstrumentationState, TlaValue, ToTla};
#[cfg(feature = "tla")]
use tla_instrumentation_proc_macros::tla_update_method;

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
            error_message: format!("failed to get UTXOs from the Bitcoin canister: {e}"),
        }
    }
}

impl From<TransferError> for UpdateBalanceError {
    fn from(e: TransferError) -> Self {
        Self::GenericError {
            error_code: ErrorCode::ConfigurationError as u64,
            error_message: format!("failed to mint tokens on the ledger: {e:?}"),
        }
    }
}

impl From<CallError> for UpdateBalanceError {
    fn from(e: CallError) -> Self {
        Self::TemporarilyUnavailable(e.to_string())
    }
}

/// Notifies the ckBTC minter to update the balance of the user subaccount.
#[cfg_attr(
    feature = "tla",
    tla_update_method(UPDATE_BALANCE_DESC.clone(), tla_snapshotter!())
)]
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

    let caller_account = Account {
        owner: args.owner.unwrap_or(caller),
        subaccount: args.subaccount,
    };
    let _guard = balance_update_guard(caller_account)?;

   let address = state::read_state(|s| runtime.derive_user_address(s, &caller_account));

    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    #[cfg(feature = "tla")]
    {
        tla_log_locals! {
            caller_account: account_to_tla(&caller_account),
            btc_address: btc_address_to_tla(&address),
            utxo: dummy_utxo(),
            utxos: std::collections::BTreeSet::<u32>::new()
        };
        tla_log_request!(
            "Update_Balance_Receive_Utxos",
            Destination::new("btc_canister"),
            "GetUtxos",
            btc_address_to_tla(&address)
        );
    }

    let utxos = get_utxos(
        btc_network,
        &address,
        min_confirmations,
        CallSource::Client,
        runtime,
    )
    .await.map_err(|e| {
        #[cfg(feature = "tla")]
        tla_log_response!(
            Destination::new("btc_canister"),
            TlaValue::Variant {
                tag: "Error".to_string(),
                value: Box::new(TlaValue::Constant("UNIT".to_string())),
            }
        );
        e
    })?
    .utxos;

    #[cfg(feature = "tla")]
    {
        tla_log_response!(
            Destination::new("btc_canister"),
            TlaValue::Variant {
                tag: "GetUtxosOk".to_string(),
                value: Box::new(utxo_set_to_tla(&utxos, &address)),
            }
        );
    }

    let now = Timestamp::from(runtime.time());
    let (processable_utxos, suspended_utxos) =
        state::read_state(|s| s.processable_utxos_for_account(utxos, &caller_account, &now));

    // Remove pending finalized transactions for the affected account.
    state::mutate_state(|s| s.finalized_utxos.remove(&caller_account));

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

        observe_update_call_latency(0, start_time, runtime.time());

        return Err(UpdateBalanceError::NoNewUtxos {
            current_confirmations,
            required_confirmations: min_confirmations,
            pending_utxos: Some(pending_utxos),
            suspended_utxos: Some(suspended_utxos),
        });
    }

    let token_name = match btc_network {
        crate::Network::Mainnet => "ckBTC",
        _ => "ckTESTBTC",
    };

    let check_fee = read_state(|s| s.check_fee);
    let mut utxo_statuses: Vec<UtxoStatus> = vec![];
    #[cfg(feature="tla")]
    let mut utxos_shadow: Vec<Utxo> = processable_utxos.iter().cloned().collect();
    for utxo in processable_utxos {
        if utxo.value <= check_fee {
            mutate_state(|s| {
                state::audit::ignore_utxo(s, utxo.clone(), caller_account, now, runtime)
            });
            log!(
                Priority::Debug,
                "Ignored UTXO {} for account {caller_account} because UTXO value {} is lower than the check fee {}",
                DisplayOutpoint(&utxo.outpoint),
                DisplayAmount(utxo.value),
                DisplayAmount(check_fee),
            );
            utxo_statuses.push(UtxoStatus::ValueTooSmall(utxo));
            continue;
        }
        let status = check_utxo(&utxo, &args, runtime).await?;
        match status {
            // Skip utxos that are already checked but has unknown mint status
            UtxoCheckStatus::CleanButMintUnknown => {
                #[cfg(feature="tla")]
                {
                    utxos_shadow.retain(|u| u != &utxo);
                }
                continue
            },
            UtxoCheckStatus::Clean => {
                mutate_state(|s| {
                    state::audit::mark_utxo_checked(s, utxo.clone(), caller_account, runtime)
                });
            }
            UtxoCheckStatus::Tainted => {
                mutate_state(|s| {
                    state::audit::quarantine_utxo(s, utxo.clone(), caller_account, now, runtime)
                });
                utxo_statuses.push(UtxoStatus::Tainted(utxo.clone()));
                continue;
            }
        };

        let amount = utxo.value - check_fee;
        let memo = MintMemo::Convert {
            txid: Some(utxo.outpoint.txid.as_ref()),
            vout: Some(utxo.outpoint.vout),
            kyt_fee: Some(check_fee),
        };

        // After the call to `mint_ckbtc` returns, in a very unlikely situation the
        // execution may panic/trap without persisting state changes and then we will
        // have no idea whether the mint actually succeeded or not. If this happens
        // the use of the guard below will help set the utxo to `CleanButMintUnknown`
        // status so that it will not be minted again. Utxos with this status will
        // require manual intervention.
        let guard = scopeguard::guard((utxo.clone(), caller_account), |(utxo, account)| {
            mutate_state(|s| {
                state::audit::mark_utxo_checked_mint_unknown(s, utxo, account, runtime)
            });
        });

        #[cfg(feature = "tla")]
        {
            utxos_shadow.retain(|u| u != &utxo);
            tla_log_locals! {
                utxo: utxo_to_tla(&utxo, &address),
                utxos: utxo_set_to_tla(&utxos_shadow, &address),
                caller_account: account_to_tla(&caller_account)
            };
            tla_log_request!(
                "Update_Balance_Mark_Minted",
                Destination::new("ledger"),
                "Mint",
                TlaValue::Record(BTreeMap::from([
                    ("to".to_string(), account_to_tla(&caller_account)),
                    ("amount".to_string(), amount.to_tla_value()),
                ]))
            );
        }

        match runtime
            .mint_ckbtc(amount, caller_account, crate::memo::encode(&memo).into())
            .await
        {
            Ok(block_index) => {
                log!(
                    Priority::Debug,
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
                #[cfg(feature = "tla")]
                tla_log_response!(
                    Destination::new("ledger"),
                    TlaValue::Variant {
                        tag: "OK".to_string(),
                        value: Box::new(TlaValue::Constant("UNIT".to_string())),
                    }
                );
            }
            Err(err) => {
                log!(
                    Priority::Info,
                    "Failed to mint ckBTC for UTXO {}: {:?}",
                    DisplayOutpoint(&utxo.outpoint),
                    err
                );
                utxo_statuses.push(UtxoStatus::Checked(utxo));
                #[cfg(feature = "tla")]
                tla_log_response!(
                    Destination::new("ledger"),
                    TlaValue::Variant {
                        tag: "Err".to_string(),
                        value: Box::new(TlaValue::Constant("UNIT".to_string())),
                    }
                );
            }
        }
        // Defuse the guard. Note that In case of a panic (either before or after this point)
        // the defuse will not be effective (due to state rollback), and the guard that was
        // setup before the `mint_ckbtc` async call will be invoked.
        scopeguard::ScopeGuard::into_inner(guard);
    }

    schedule_now(TaskType::ProcessLogic(false), runtime);

    observe_update_call_latency(utxo_statuses.len(), start_time, runtime.time());

    Ok(utxo_statuses)
}

async fn check_utxo<R: CanisterRuntime>(
    utxo: &Utxo,
    args: &UpdateBalanceArgs,
    runtime: &R,
) -> Result<UtxoCheckStatus, UpdateBalanceError> {
    use ic_btc_checker::{CHECK_TRANSACTION_CYCLES_REQUIRED, CheckTransactionStatus};

    let btc_checker_principal = read_state(|s| s.btc_checker_principal.map(Principal::from));

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
                    "Failed to call Bitcoin checker canister: {call_err}"
                ))
            })? {
            CheckTransactionResponse::Failed(addresses) => {
                log!(
                    Priority::Info,
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
                    Priority::Debug,
                    "The Bitcoin checker canister requires more cycles, Remaining tries: {}",
                    MAX_CHECK_TRANSACTION_RETRY - i - 1
                );
                continue;
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Retriable(status)) => {
                log!(
                    Priority::Debug,
                    "The Bitcoin checker canister is temporarily unavailable: {:?}",
                    status
                );
                return Err(UpdateBalanceError::TemporarilyUnavailable(format!(
                    "The Bitcoin checker canister is temporarily unavailable: {status:?}"
                )));
            }
            CheckTransactionResponse::Unknown(CheckTransactionStatus::Error(error)) => {
                log!(Priority::Debug, "Bitcoin checker error: {:?}", error);
                return Err(UpdateBalanceError::GenericError {
                    error_code: ErrorCode::KytError as u64,
                    error_message: format!("Bitcoin checker error: {error:?}"),
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
pub async fn mint(amount: u64, to: Account, memo: Memo) -> Result<u64, UpdateBalanceError> {
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
                "cannot mint ckbtc: {msg} (reject_code = {code})"
            ))
        })??;
    Ok(block_index.0.to_u64().expect("nat does not fit into u64"))
}
