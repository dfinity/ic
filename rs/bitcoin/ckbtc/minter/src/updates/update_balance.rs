use candid::{CandidType, Deserialize, Nat};
use ic_base_types::PrincipalId;
use ic_btc_types::GetUtxosError;
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

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpdateBalanceArgs {
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpdateBalanceResult {
    pub amount: u64,
    pub block_index: u64,
}
enum ErrorCode {
    ConfigurationError = 1,
}

#[derive(CandidType, Clone, Debug, Deserialize, PartialEq)]
pub enum UpdateBalanceError {
    TemporarilyUnavailable(String),
    AlreadyProcessing,
    NoNewUtxos,
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
    init_ecdsa_public_key().await;
    let _guard = balance_update_guard(caller)?;

    let caller_account = Account {
        owner: PrincipalId::from(caller),
        subaccount: args.subaccount,
    };

    let address = state::read_state(|s| {
        get_btc_address::account_to_p2wpkh_address_from_state(s, &caller_account)
    });

    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    ic_cdk::print(format!("Fetching utxos for address {}", address));

    let utxos = get_utxos(btc_network, &address, min_confirmations).await?;

    let new_utxos = state::read_state(|s| match s.utxos_state_addresses.get(&caller_account) {
        Some(known_utxos) => utxos
            .into_iter()
            .filter(|u| !known_utxos.contains(u))
            .collect(),
        None => utxos,
    });

    let satoshis_to_mint = new_utxos.iter().map(|u| u.value).sum::<u64>();

    if satoshis_to_mint == 0 {
        // We bail out early if there are no UTXOs to avoid creating a new entry
        // in the UTXOs map.  If we allowed empty entries, malicious callers
        // could exhaust the canister memory.
        return Err(UpdateBalanceError::NoNewUtxos);
    }

    ic_cdk::print(format!(
        "minting {} wrapped BTC for {} new UTXOs",
        satoshis_to_mint,
        new_utxos.len()
    ));

    let block_index: u64 = mint(satoshis_to_mint, caller_account.clone()).await?;

    state::mutate_state(|s| s.add_utxos(caller_account, new_utxos));

    Ok(UpdateBalanceResult {
        amount: satoshis_to_mint,
        block_index,
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
