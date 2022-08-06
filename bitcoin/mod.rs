//! The IC Bitcoin API.

use crate::api::call::{call_with_payment128, CallResult};
use candid::Principal;

mod types;
pub use types::*;

// The fees for the various bitcoin endpoints.
// TODO: where is the public doc of these parameters?
const GET_BALANCE_CYCLES: u128 = 100_000_000;
const GET_UTXOS_CYCLES: u128 = 100_000_000;
const GET_CURRENT_FEE_PERCENTILES_CYCLES: u128 = 100_000_000;
const SEND_TRANSACTION_BASE_CYCLES: u128 = 5_000_000_000;
const SEND_TRANSACTION_PER_BYTE_CYCLES: u128 = 20_000_000;

/// See [IC method `bitcoin_get_balance`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_balance)
pub async fn bitcoin_get_balance(arg: GetBalanceRequest) -> CallResult<(Satoshi,)> {
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_balance",
        (arg,),
        GET_BALANCE_CYCLES,
    )
    .await
}

/// See [IC method `bitcoin_get_utxos`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_utxos)
pub async fn bitcoin_get_utxos(arg: GetUtxosRequest) -> CallResult<(GetUtxosResponse,)> {
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_utxos",
        (arg,),
        GET_UTXOS_CYCLES,
    )
    .await
}

/// See [IC method `bitcoin_send_transaction`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_send_transaction)
pub async fn bitcoin_send_transaction(arg: SendTransactionRequest) -> CallResult<()> {
    let cycles = SEND_TRANSACTION_BASE_CYCLES
        + (arg.transaction.len() as u128) * SEND_TRANSACTION_PER_BYTE_CYCLES;
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_send_transaction",
        (arg,),
        cycles,
    )
    .await
}

/// See [IC method `bitcoin_get_current_fee_percentiles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_current_fee_percentiles)
pub async fn bitcoin_get_current_fee_percentiles(
    arg: GetCurrentFeePercentilesRequest,
) -> CallResult<(Vec<MillisatoshiPerByte>,)> {
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_current_fee_percentiles",
        (arg,),
        GET_CURRENT_FEE_PERCENTILES_CYCLES,
    )
    .await
}
