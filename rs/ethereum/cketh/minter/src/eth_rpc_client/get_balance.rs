//! Reading a native ETH balance through the EVM RPC canister.
//!
//! The EVM RPC canister exposes no `eth_getBalance` endpoint and `evm_rpc_client` offers no
//! balance getter, so the balance is read with the canister's generic `multi_request`: it
//! forwards an arbitrary JSON-RPC payload to every provider, parses each response's `result`
//! field, and reduces those under the configured consensus strategy. Because the reduction
//! happens on the parsed `result` — not on the raw response body — differences in how
//! providers format the surrounding JSON envelope are irrelevant; only the hex quantity is
//! compared.
//!
//! The first consumer is the sweeper address' ETH balance, which *is* the prepaid-sweep-gas
//! counter (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without
//! touching the ckETH backing"): sweeping may only spend ETH that has already been covered by a
//! ckETH burn, and the sweeper's on-chain balance is what makes that reconcilable.

use crate::eth_rpc_client::{
    MIN_ATTACHED_CYCLES, MultiCallError, StrictMajorityByKey, ToReducedWithStrategy, rpc_client,
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
        // A balance is compared for exact equality across providers: at a finalized block every
        // honest provider must return the same quantity, so anything else is a disagreement
        // worth surfacing rather than papering over by picking one answer.
        .reduce_with_strategy(StrictMajorityByKey::new(|balance: &String| balance.clone()))
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
    // `multi_request` hands back the JSON string's *contents*, but tolerate a quoted form too so
    // a caller passing a raw JSON value through does not silently fail.
    let quantity = result.trim().trim_matches('"');
    if !quantity.starts_with("0x") || quantity.len() <= 2 {
        return Err(DecodeBalanceError::NotAQuantity(result.to_string()));
    }
    Wei::from_str_hex(quantity).map_err(|_| {
        // `from_str_hex` rejects both non-hex digits and values wider than 32 bytes, and the
        // check above established only the `0x` prefix — so tell the two apart here.
        if quantity[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            DecodeBalanceError::TooLarge(result.to_string())
        } else {
            DecodeBalanceError::NotAQuantity(result.to_string())
        }
    })
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
