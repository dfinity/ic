# ICRC-3 Test Ledger

This is a simplified ICRC-3 ledger canister for testing purposes. It allows users to store and retrieve ICRC-3
compatible blocks.

## Features

- **add_block**: An update endpoint that accepts an `ICRC3Value` (representing an ICRC-3 block) and stores it with an
  auto-incrementing block ID
- **icrc3_get_blocks**: A query endpoint compatible with the ICRC-3 standard that returns stored blocks

## Interface

The canister exposes the following endpoints:

### Update Methods

- `add_block(block: ICRC3Value) -> AddBlockResult`
    - Stores a new block and returns its assigned ID
    - Returns `Ok(block_id)` on success or `Err(message)` on failure
    - Does not perform any validation on the block content, e.g., it does not check if the block is a valid ICRC-3
      block, if it contains valid transactions, or a valid parent block hash.

### Query Methods

- `icrc3_get_blocks(requests: Vec<GetBlocksArgs>) -> GetBlocksResult`
    - Retrieves blocks according to ICRC-3 standard
    - Supports querying multiple ranges of blocks in a single call
    - Compatible with existing ICRC-3 tooling

## Building

Build the canister using Bazel:

```bash
bazel build //rs/ledger_suite/icrc1/test_utils/icrc3_test_ledger:icrc3_test_ledger_canister.wasm.gz
```

## Testing

Run the tests:

```bash
bazel test //rs/ledger_suite/icrc1/test_utils/icrc3_test_ledger:icrc3_test_ledger_canister_test
bazel test //rs/ledger_suite/icrc1/test_utils/icrc3_test_ledger:icrc3_test_ledger_integration_test
```

## Storage

The canister uses in-memory storage (heap) for simplicity. Data will not persist across canister upgrades. For a
production use case, you would want to implement stable storage.

## Type Definitions

- `ICRC3Value`: The ICRC-3 value type from `icrc_ledger_types::icrc::generic_value::ICRC3Value`
- `AddBlockResult`: `Result<Nat, String>` where `Nat` is the block ID
- `GetBlocksArgs` and `GetBlocksResult`: Standard ICRC-3 types for block retrieval
