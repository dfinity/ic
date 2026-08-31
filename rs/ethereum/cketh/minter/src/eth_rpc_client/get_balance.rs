//! Reading a native ETH balance through the EVM RPC canister.
//!
//! The EVM RPC canister exposes no `eth_getBalance` endpoint and `evm_rpc_client` offers no balance
//! getter, so the balance is read with the canister's generic `multi_request`: it forwards an
//! arbitrary JSON-RPC payload to every provider and deserializes each response's `result` field into
//! a string. Each provider's string is decoded into wei here; how much agreement between providers
//! is enough is the caller's reduction strategy to choose.
//!
//! The first consumer is the sweeper address' ETH balance, which *is* the prepaid-sweep-gas
//! counter (`rs/ethereum/cketh/docs/deposit_from_cex.md`, "Fund the transaction fees without
//! touching the ckETH backing"): sweeping may only spend ETH that has already been covered by a
//! ckETH burn, and the sweeper's on-chain balance is what makes that reconcilable.

use crate::eth_rpc_client::{MIN_ATTACHED_CYCLES, rpc_client};
use crate::numeric::{BlockNumber, Wei};
use crate::state::read_state;
use evm_rpc_types::{BlockTag, MultiRpcResult, RpcError, RpcResult, ValidationError};
use ic_canister_runtime::IcError;
use ic_ethereum_types::Address;
use serde_json::json;

#[cfg(test)]
mod tests;

/// The native ETH balance of `address` at `block`, as each provider reported it.
///
/// A result that cannot be read as a quantity is that provider's error, never a balance of zero:
/// the caller uses this to decide whether spending is already covered by a burn, so confusing "we
/// could not read the balance" with "no gas left" would burn ckETH for gas already in place.
pub async fn eth_get_balance(
    address: &Address,
    block: BlockTag,
) -> Result<MultiRpcResult<Wei>, IcError> {
    let payload = eth_get_balance_request(address, &block);
    read_state(rpc_client)
        .multi_request(payload)
        .with_cycles(MIN_ATTACHED_CYCLES)
        .try_send()
        .await
        .map(|balances| balances.and_then(|balance| decode_balance(&balance)))
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
///
/// Decoded as received. `multi_request` yields the JSON string's *contents* — the EVM RPC canister
/// deserializes the `result` field into a `String` — so a provider speaking the protocol gives a
/// bare quantity: no envelope, no quotes, no surrounding whitespace, none of which are repaired
/// here. What is tolerated is a quantity that is merely rendered unusually, such as one carrying
/// leading zeros, since that still says what the balance is.
fn decode_balance(result: &str) -> RpcResult<Wei> {
    Wei::from_str_hex(result).map_err(|e| {
        RpcError::ValidationError(ValidationError::Custom(format!(
            "invalid eth_getBalance result {result:?}: {e}"
        )))
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
        // `LowerHex` is already minimal-length, and renders block zero as `0`. The `0x` is written
        // out because the delegating impl on `CheckedAmountOf` drops the alternate flag, so `{:#x}`
        // would not prefix it.
        BlockTag::Number(number) => format!("0x{:x}", BlockNumber::from(number.clone())),
    }
}
