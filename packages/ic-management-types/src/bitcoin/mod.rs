//! The IC Bitcoin API.
//!
//! Check [Bitcoin integration](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api) for more details.

use crate::api::call::{call_with_payment128, CallResult};
use candid::Principal;

mod types;
pub use types::*;

const GET_UTXO_MAINNET: u128 = 10_000_000_000;
const GET_UTXO_TESTNET: u128 = 4_000_000_000;

const GET_CURRENT_FEE_PERCENTILES_MAINNET: u128 = 100_000_000;
const GET_CURRENT_FEE_PERCENTILES_TESTNET: u128 = 40_000_000;

const GET_BALANCE_MAINNET: u128 = 100_000_000;
const GET_BALANCE_TESTNET: u128 = 40_000_000;

const SEND_TRANSACTION_SUBMISSION_MAINNET: u128 = 5_000_000_000;
const SEND_TRANSACTION_SUBMISSION_TESTNET: u128 = 2_000_000_000;

const SEND_TRANSACTION_PAYLOAD_MAINNET: u128 = 20_000_000;
const SEND_TRANSACTION_PAYLOAD_TESTNET: u128 = 8_000_000;

const GET_BLOCK_HEADERS_MAINNET: u128 = 4_000_000_000;
const GET_BLOCK_HEADERS_TESTNET: u128 = 4_000_000_000;

/// See [IC method `bitcoin_get_balance`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_balance).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [API fees & Pricing](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api-fees--pricing) for more details.
pub async fn bitcoin_get_balance(arg: GetBalanceRequest) -> CallResult<(Satoshi,)> {
    let cycles = match arg.network {
        BitcoinNetwork::Mainnet => GET_BALANCE_MAINNET,
        BitcoinNetwork::Testnet => GET_BALANCE_TESTNET,
        BitcoinNetwork::Regtest => 0,
    };
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_balance",
        (arg,),
        cycles,
    )
    .await
}

/// See [IC method `bitcoin_get_utxos`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_utxos).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [API fees & Pricing](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api-fees--pricing) for more details.
pub async fn bitcoin_get_utxos(arg: GetUtxosRequest) -> CallResult<(GetUtxosResponse,)> {
    let cycles = match arg.network {
        BitcoinNetwork::Mainnet => GET_UTXO_MAINNET,
        BitcoinNetwork::Testnet => GET_UTXO_TESTNET,
        BitcoinNetwork::Regtest => 0,
    };
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_utxos",
        (arg,),
        cycles,
    )
    .await
}

fn send_transaction_fee(arg: &SendTransactionRequest) -> u128 {
    let (submission, payload) = match arg.network {
        BitcoinNetwork::Mainnet => (
            SEND_TRANSACTION_SUBMISSION_MAINNET,
            SEND_TRANSACTION_PAYLOAD_MAINNET,
        ),
        BitcoinNetwork::Testnet => (
            SEND_TRANSACTION_SUBMISSION_TESTNET,
            SEND_TRANSACTION_PAYLOAD_TESTNET,
        ),
        BitcoinNetwork::Regtest => (0, 0),
    };
    submission + payload * arg.transaction.len() as u128
}

/// See [IC method `bitcoin_send_transaction`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_send_transaction).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [API fees & Pricing](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api-fees--pricing) for more details.
pub async fn bitcoin_send_transaction(arg: SendTransactionRequest) -> CallResult<()> {
    let cycles = send_transaction_fee(&arg);
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_send_transaction",
        (arg,),
        cycles,
    )
    .await
}

/// See [IC method `bitcoin_get_current_fee_percentiles`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-bitcoin_get_current_fee_percentiles).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [API fees & Pricing](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api-fees--pricing) for more details.
pub async fn bitcoin_get_current_fee_percentiles(
    arg: GetCurrentFeePercentilesRequest,
) -> CallResult<(Vec<MillisatoshiPerByte>,)> {
    let cycles = match arg.network {
        BitcoinNetwork::Mainnet => GET_CURRENT_FEE_PERCENTILES_MAINNET,
        BitcoinNetwork::Testnet => GET_CURRENT_FEE_PERCENTILES_TESTNET,
        BitcoinNetwork::Regtest => 0,
    };
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_current_fee_percentiles",
        (arg,),
        cycles,
    )
    .await
}

/// See [IC method `bitcoin_get_block_headers`](https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-bitcoin_get_block_headers).
///
/// This call requires cycles payment.
/// This method handles the cycles cost under the hood.
/// Check [API fees & Pricing](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/bitcoin-how-it-works/#api-fees--pricing) for more details.
pub async fn bitcoin_get_block_headers(
    arg: GetBlockHeadersRequest,
) -> CallResult<(GetBlockHeadersResponse,)> {
    let cycles = match arg.network {
        BitcoinNetwork::Mainnet => GET_BLOCK_HEADERS_MAINNET,
        BitcoinNetwork::Testnet => GET_BLOCK_HEADERS_TESTNET,
        BitcoinNetwork::Regtest => 0,
    };
    call_with_payment128(
        Principal::management_canister(),
        "bitcoin_get_block_headers",
        (arg,),
        cycles,
    )
    .await
}
