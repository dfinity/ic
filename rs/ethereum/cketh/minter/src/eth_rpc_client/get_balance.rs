//! Reading a native ETH balance through the EVM RPC canister.
//!
//! The EVM RPC canister exposes no `eth_getBalance` endpoint and `evm_rpc_client` offers no
//! balance getter, so the balance is read with the canister's generic `multi_request`: it forwards
//! an arbitrary JSON-RPC payload to every provider, deserializes each response's `result` field
//! into a string, and agrees on one under the configured consensus strategy — a threshold of the
//! providers, which is the only agreement this module accepts.
//!
//! Because the canister deserializes `result`, what arrives here is the quantity itself rather than
//! any surrounding JSON, so it is decoded exactly: quotes or padding would be the provider's own
//! and are rejected rather than trimmed away.
//!
//! The first consumer is the sweeper address' ETH balance, which *is* the prepaid-sweep-gas
//! counter (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without
//! touching the ckETH backing"): sweeping may only spend ETH that has already been covered by a
//! ckETH burn, and the sweeper's on-chain balance is what makes that reconcilable.

use crate::eth_rpc_client::{
    MIN_ATTACHED_CYCLES, MultiCallError, NoReduction, ToReducedWithStrategy, rpc_client,
};
use crate::numeric::Wei;
use crate::state::read_state;
use evm_rpc_types::BlockTag;
use ic_ethereum_types::Address;
use serde_json::json;

#[cfg(test)]
mod tests;

/// Why an `eth_getBalance` result could not be read as an amount of wei.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DecodeBalanceError {
    /// The result is not a `0x`-prefixed hex quantity.
    NotAQuantity(String),
    /// The result is a hex quantity but does not fit into 32 bytes.
    TooLarge(String),
}

/// Why reading a balance failed. Not `Clone`, matching [`MultiCallError`].
#[derive(Eq, PartialEq, Debug)]
pub enum GetBalanceError {
    /// The call itself failed, or the providers did not agree.
    Rpc(MultiCallError<String>),
    /// The providers agreed on a result that is not a valid quantity, which means either a
    /// broken provider or a bug on our side — never a balance of zero.
    Decode(DecodeBalanceError),
}

/// The native ETH balance of `address` at `block`.
///
/// Fails rather than defaulting to zero on any error: a zero balance and "we could not read the
/// balance" must not be confused, since the caller uses this to decide whether spending is
/// already covered by a burn.
pub async fn eth_get_balance(address: &Address, block: BlockTag) -> Result<Wei, GetBalanceError> {
    let payload = eth_get_balance_request(address, &block);
    let result = read_state(rpc_client)
        .multi_request(payload)
        .with_cycles(MIN_ATTACHED_CYCLES)
        .try_send()
        .await
        // No client-side reduction: the answer is whatever the EVM RPC canister's own consensus
        // strategy agreed on, and an inconsistent result stays an error.
        //
        // Deliberately *not* `StrictMajorityByKey`, despite the name. That strategy returns the
        // largest ballot whenever it beats the runner-up, so a 2/1/1 split across four providers
        // wins on two votes — and it only ever runs on results the canister has already declared
        // inconsistent, i.e. precisely when the configured threshold was not met. Picking a winner
        // there would quietly settle for fewer providers than the threshold demands, on the number
        // that decides whether ckETH gets burned.
        .reduce_with_strategy(NoReduction)
        .map_err(GetBalanceError::Rpc)?;
    decode_balance(&result).map_err(GetBalanceError::Decode)
}

/// The JSON-RPC payload asking for `address`' balance at `block`.
///
/// The address is rendered in lowercase rather than EIP-55 form: the checksum carries no meaning
/// over JSON-RPC (addresses are compared case-insensitively) and a single canonical rendering
/// keeps the request byte-identical across providers.
pub fn eth_get_balance_request(address: &Address, block: &BlockTag) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [format!("0x{}", hex::encode(address.as_ref())), block_tag_param(block)],
    })
}

/// Reads an `eth_getBalance` result — a hex quantity such as `0x1bc16d674ec80000` — as wei.
pub fn decode_balance(result: &str) -> Result<Wei, DecodeBalanceError> {
    // Decoded exactly as received. `multi_request` yields the JSON string's *contents* — the EVM
    // RPC canister deserializes the `result` field into a `String` — so a provider speaking the
    // protocol gives a bare quantity: no envelope, no quotes, no surrounding whitespace. Repairing
    // anything else would defeat the point of the check, since the value most easily manufactured
    // that way is zero, and zero reads as "the sweeper is empty" and buys a burn that was never
    // needed.
    let Some(digits) = result.strip_prefix("0x") else {
        return Err(DecodeBalanceError::NotAQuantity(result.to_string()));
    };
    // A JSON-RPC quantity is minimal-length hex: at least one digit, no leading zero unless the
    // value *is* zero. Checking the digits here rather than inferring them from a parse failure
    // also keeps `Wei::from_str_hex`'s tolerance for a leading `+` out of reach.
    if digits.is_empty()
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(DecodeBalanceError::NotAQuantity(result.to_string()));
    }
    // The digits are known good, so the only rejection left is a value too wide for 32 bytes.
    Wei::from_str_hex(result).map_err(|_| DecodeBalanceError::TooLarge(result.to_string()))
}

/// Renders a block tag the way the JSON-RPC `eth_getBalance` parameter expects it: a named tag,
/// or a minimal-length hex quantity for an explicit block number.
fn block_tag_param(block: &BlockTag) -> String {
    match block {
        BlockTag::Latest => "latest".to_string(),
        BlockTag::Finalized => "finalized".to_string(),
        BlockTag::Safe => "safe".to_string(),
        BlockTag::Earliest => "earliest".to_string(),
        BlockTag::Pending => "pending".to_string(),
        BlockTag::Number(number) => {
            // A JSON-RPC quantity is minimal-length hex, so strip leading zeros — but never all
            // of them: block zero is `0x0`, not `0x`.
            let digits = hex::encode(number.clone().into_be_bytes());
            let trimmed = digits.trim_start_matches('0');
            format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
        }
    }
}
