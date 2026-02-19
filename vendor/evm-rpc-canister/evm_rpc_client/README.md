[![Internet Computer portal](https://img.shields.io/badge/InternetComputer-grey?logo=internet%20computer&style=for-the-badge)](https://internetcomputer.org)
[![DFinity Forum](https://img.shields.io/badge/help-post%20on%20forum.dfinity.org-blue?style=for-the-badge)](https://forum.dfinity.org/t/sol-rpc-canister/41896)
[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?logo=apache&style=for-the-badge)](LICENSE)

# Crate `evm_rpc_client`

Library to interact with the [EVM RPC canister](https://github.com/dfinity/evm-rpc-canister/) from a canister running on the Internet Computer. 
The `alloy` feature flag allows using [Alloy](https://alloy.rs/) types in requests and responses.

See the Rust [documentation](https://docs.rs/evm_rpc_client) for more details.

## Example
Fetching the latest transaction count for a given address using the `eth_getTransactionCount` JSON-RPC method.

```rust
use alloy_primitives::{Adress, U256};
use alloy_rpc_types::BlockNumberOrTag;
use evm_rpc_client::EvmRpcClient;
use evm_rpc_types::RpcResult;

fn get_latest_transaction_count (address: Address) -> RpcResult<U256> {
    let client = EvmRpcClient::builder_for_ic()
        .with_alloy()
        .build();

    client
        .get_transaction_count((address, BlockNumberOrTag::Latest))
        .send()
        .await
        .expect_consistent()
}
```