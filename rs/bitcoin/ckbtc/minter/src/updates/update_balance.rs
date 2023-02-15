use crate::logs::P1;
use crate::tasks::{schedule_now, TaskType};
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_types::{GetUtxosError, GetUtxosResponse};
use ic_canister_log::log;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account, Subaccount,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use serde::Serialize;

use super::get_btc_address::init_ecdsa_public_key;

use crate::{
    guard::{balance_update_guard, GuardError},
    management::{get_utxos, CallError},
    state,
    updates::get_btc_address,
};

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateBalanceArgs {
    pub owner: Option<Principal>,
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateBalanceResult {
    pub amount: u64,
    pub block_index: u64,
}
enum ErrorCode {
    ConfigurationError = 1,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq, Eq)]
pub enum UpdateBalanceError {
    TemporarilyUnavailable(String),
    AlreadyProcessing,
    NoNewUtxos {
        /// If there are new UTXOs that do not have enough
        /// confirmations yet, this field will contain the number of
        /// confirmations as observed by the minter.
        current_confirmations: Option<u32>,
        required_confirmations: u32,
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
) -> Result<UpdateBalanceResult, UpdateBalanceError> {
    let caller = ic_cdk::caller();
    if args.owner.unwrap_or(caller) == ic_cdk::id() {
        ic_cdk::trap("cannot update minter's balance");
    }

    state::read_state(|s| s.mode.is_deposit_available_for(&caller))
        .map_err(UpdateBalanceError::TemporarilyUnavailable)?;

    init_ecdsa_public_key().await;
    let _guard = balance_update_guard(args.owner.unwrap_or(caller))?;

    let caller_account = Account {
        owner: PrincipalId::from(args.owner.unwrap_or(caller)),
        subaccount: args.subaccount,
    };

    let address = state::read_state(|s| {
        get_btc_address::account_to_p2wpkh_address_from_state(s, &caller_account)
    });

    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    log!(P1, "Fetching utxos for address {}", address);

    let utxos = get_utxos(btc_network, &address, min_confirmations)
        .await?
        .utxos;

    let new_utxos: Vec<_> = state::read_state(|s| {
        let maybe_existing_utxos = s.utxos_state_addresses.get(&caller_account);
        let maybe_finalized_utxos = s.finalized_utxos.get(&caller_account.owner);
        utxos
            .into_iter()
            .filter(|u| {
                !maybe_existing_utxos
                    .map(|utxos| utxos.contains(u))
                    .unwrap_or(false)
                    && !maybe_finalized_utxos
                        .map(|utxos| utxos.contains(u))
                        .unwrap_or(false)
            })
            .collect()
    });

    // Remove pending finalized transactions for the affected principal.
    state::mutate_state(|s| s.finalized_utxos.remove(&caller_account.owner));

    let satoshis_to_mint = new_utxos.iter().map(|u| u.value).sum::<u64>();

    if satoshis_to_mint == 0 {
        // We bail out early if there are no UTXOs to avoid creating a new entry
        // in the UTXOs map.  If we allowed empty entries, malicious callers
        // could exhaust the canister memory.

        // We get the entire list of UTXOs again with a zero
        // confirmation limit so that we can indicate the approximate
        // wait time to the caller.
        let GetUtxosResponse {
            tip_height, utxos, ..
        } = get_utxos(btc_network, &address, /*min_confirmations=*/ 0).await?;

        let current_confirmations = utxos
            .iter()
            .filter_map(|u| {
                (tip_height < u.height.saturating_add(min_confirmations))
                    .then_some(tip_height - u.height)
            })
            .max();

        return Err(UpdateBalanceError::NoNewUtxos {
            current_confirmations,
            required_confirmations: min_confirmations,
        });
    }

    match btc_network {
        ic_ic00_types::BitcoinNetwork::Mainnet => log!(
            P1,
            "minting {} ckBTC for {} new UTXOs",
            crate::tx::DisplayAmount(satoshis_to_mint),
            new_utxos.len()
        ),
        _ => log!(
            P1,
            "minting {} ckTESTBTC for {} new UTXOs",
            crate::tx::DisplayAmount(satoshis_to_mint),
            new_utxos.len()
        ),
    }

    let mint_txid = mint(satoshis_to_mint, caller_account.clone()).await?;

    state::mutate_state(|s| state::audit::add_utxos(s, Some(mint_txid), caller_account, new_utxos));

    schedule_now(TaskType::ProcessLogic);

    Ok(UpdateBalanceResult {
        amount: satoshis_to_mint,
        block_index: mint_txid,
    })
}

/// Mint an amount of ckBTC to an Account
async fn mint(amount: u64, to: Account) -> Result<u64, UpdateBalanceError> {
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
            memo: None,
            amount: Nat::from(amount),
        })
        .await
        .map_err(|e| UpdateBalanceError::TemporarilyUnavailable(e.1))??;
    Ok(block_index)
}
