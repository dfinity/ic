use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_types::{
    Address, GetUtxosError, GetUtxosRequest, GetUtxosResponse, Network, NetworkInRequest, Utxo,
    UtxosFilterInRequest,
};
use ic_cdk::api::call::call_with_payment;
use ic_icrc1::{
    endpoints::{TransferArg, TransferError},
    Account, Subaccount,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use serde::Serialize;

use super::get_btc_address::init_ecdsa_public_key;

use crate::{
    guard::{balance_update_guard, GuardError},
    state,
    updates::get_btc_address::{self, GetBtcAddressArgs},
};

const GET_UTXOS_COST_CYCLES: u64 = 100_000_000;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpdateBalanceArgs {
    pub subaccount: Subaccount,
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
    TooManyConcurrentRequests,
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
            GuardError::TooManyConcurrentRequests => Self::TooManyConcurrentRequests,
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

/// Notifies the ckBTC minter to update the balance of the user subaccount.
pub async fn update_balance(
    args: UpdateBalanceArgs,
) -> Result<UpdateBalanceResult, UpdateBalanceError> {
    let caller = ic_cdk::caller();
    init_ecdsa_public_key().await;
    let _guard = balance_update_guard(caller)?;
    let address = get_btc_address::get_btc_address(GetBtcAddressArgs {
        subaccount: Some(args.subaccount),
    })
    .await;

    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    println!("Fetching utxos");
    let utxos = get_utxos(btc_network, &address, min_confirmations).await?;

    if utxos.is_empty() {
        // We bail out early if there are no UTXOs to avoid creating a new entry
        // in the UTXOs map.  If we allowed empty entries, malicious callers
        // could exhaust the canister memory.
        return Err(UpdateBalanceError::NoNewUtxos);
    }

    let satoshis_to_mint = state::mutate_state(|s| {
        let known_utxos = s.utxos_state_addresses.entry(address).or_default();
        let mut satoshis_to_mint = 0;
        for utxo in utxos {
            if !known_utxos.contains(&utxo) {
                satoshis_to_mint += utxo.value;
                known_utxos.insert(utxo);
            }
        }
        satoshis_to_mint
    });

    if satoshis_to_mint == 0 {
        return Err(UpdateBalanceError::NoNewUtxos);
    }

    // Mint ckBTC amount equals to the transferred BTC (minting == transfer to burn).
    let to_caller = Account {
        owner: PrincipalId::from(caller),
        subaccount: Some(args.subaccount),
    };

    let block_index: u64 = mint(satoshis_to_mint, to_caller).await?;

    Ok(UpdateBalanceResult {
        amount: satoshis_to_mint,
        block_index,
    })
}

/// Fetches the full list of UTXOs for the specified address.
async fn get_utxos(
    network: Network,
    address: &Address,
    min_confirmations: u32,
) -> Result<Vec<Utxo>, UpdateBalanceError> {
    // Calls "bitcoin_get_utxos" method with the specified argument on the
    // management canister.
    async fn bitcoin_get_utxos(
        req: GetUtxosRequest,
    ) -> Result<GetUtxosResponse, UpdateBalanceError> {
        let utxos_res: Result<(GetUtxosResponse,), _> = call_with_payment(
            Principal::management_canister(),
            "bitcoin_get_utxos",
            (req,),
            GET_UTXOS_COST_CYCLES,
        )
        .await;
        match utxos_res {
            Ok(utxos) => Ok(utxos.0),
            Err(e) => Err(UpdateBalanceError::TemporarilyUnavailable(e.1)),
        }
    }

    let mut response = bitcoin_get_utxos(GetUtxosRequest {
        address: address.to_string(),
        network: NetworkInRequest::from(network),
        filter: Some(UtxosFilterInRequest::MinConfirmations(min_confirmations)),
    })
    .await?;

    let mut utxos = std::mem::take(&mut response.utxos);

    // Continue fetching until there are no more pages.
    while let Some(page) = response.next_page {
        response = bitcoin_get_utxos(GetUtxosRequest {
            address: address.to_string(),
            network: NetworkInRequest::from(network),
            filter: Some(UtxosFilterInRequest::Page(page)),
        })
        .await?;

        utxos.append(&mut response.utxos);
    }

    Ok(utxos)
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
