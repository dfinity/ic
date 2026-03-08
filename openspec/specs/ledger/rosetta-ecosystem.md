# Rosetta API Ecosystem

**Crates:** `rosetta-core`, `ic-icp-rosetta-client`, `ic-icp-rosetta-runner`, `ic-icrc-rosetta-client`, `ic-icrc-rosetta-runner`, `ic-ledger-canister-blocks-synchronizer`

**Source:** `rs/rosetta-api/`

## Overview

The Rosetta API ecosystem implements the [Coinbase Rosetta specification](https://www.rosetta-api.org/) for the Internet Computer, enabling standardized blockchain interaction for both ICP (native token) and ICRC-1/ICRC-2 (token standard) ledgers. The ecosystem comprises:

- **rosetta-core**: Shared Rosetta data types (blocks, transactions, operations, identifiers, requests, responses) implementing the Rosetta specification.
- **ic-icp-rosetta-client**: HTTP client library for interacting with the ICP Rosetta server, supporting all Data API and Construction API endpoints plus ICP-specific neuron management operations.
- **ic-icp-rosetta-runner**: Test harness for launching the ICP Rosetta server as a subprocess.
- **ic-icrc-rosetta-client**: HTTP client library for interacting with the ICRC Rosetta server, supporting ICRC-1 transfers, ICRC-2 approvals, and transfer-from operations.
- **ic-icrc-rosetta-runner**: Test harness for launching the ICRC Rosetta server as a subprocess with configurable options.
- **ic-ledger-canister-blocks-synchronizer**: Downloads and verifies ICP ledger blocks, storing them locally in SQLite for the Rosetta server to query.

---

## Requirements

### Requirement: Rosetta Core Data Model

The core library defines the canonical Rosetta data types for the IC ecosystem.

#### Scenario: Block representation
- **WHEN** a block is constructed
- **THEN** it contains a `block_identifier` (index + hash), `parent_block_identifier`, `timestamp` (milliseconds since Unix epoch), and a vector of `Transaction` objects
- **AND** blocks are inalterable: once returned for a specific `BlockIdentifier`, the same contents must always be returned

#### Scenario: Transaction representation
- **WHEN** a transaction is constructed
- **THEN** it contains a `transaction_identifier` (hash) and a vector of `Operation` objects
- **AND** optional metadata may include related cross-shard transaction identifiers

#### Scenario: Operation representation
- **WHEN** an operation is constructed
- **THEN** it has an `operation_identifier` (sequential index), a `type_` string, optional `account`, optional `amount`, and optional `status`
- **AND** `related_operations` indexes must reference operations with lower indexes (DAG structure)

#### Scenario: Amount and Currency
- **WHEN** an amount is specified
- **THEN** it contains a `value` (arbitrary-precision signed integer as string in atomic units) and a `Currency` (symbol + decimals)
- **AND** for ICP, the symbol is "ICP" with 8 decimals; for ICRC tokens, symbol and decimals are configurable

#### Scenario: Public key and signature types
- **WHEN** cryptographic operations are performed
- **THEN** `edwards25519` (Ed25519) and `secp256k1` (ECDSA) curve types are supported
- **AND** public keys can be DER-encoded and converted to IC principals
- **AND** signatures map to `Ed25519` and `Ecdsa` signature types respectively

---

### Requirement: Network API (Data API)

The Rosetta server exposes standard network discovery and status endpoints.

#### Scenario: Network list
- **WHEN** a client calls `/network/list`
- **THEN** the response contains `NetworkIdentifier` entries for each supported network (blockchain + network name)

#### Scenario: Network status
- **WHEN** a client calls `/network/status` with a `NetworkIdentifier`
- **THEN** the response includes `current_block_identifier`, `current_block_timestamp`, `genesis_block_identifier`, optional `oldest_block_identifier`, optional `sync_status`, and `peers`

#### Scenario: Network options
- **WHEN** a client calls `/network/options`
- **THEN** the response includes the Rosetta `Version`, and `Allow` object listing supported `operation_statuses`, `operation_types`, `errors`, `historical_balance_lookup` capability, `call_methods`, and `balance_exemptions`

---

### Requirement: Block API (Data API)

Clients can fetch blocks and transactions.

#### Scenario: Fetch block by index or hash
- **WHEN** a client calls `/block` with a `PartialBlockIdentifier` (index and/or hash)
- **THEN** the response contains the matching `Block` with all transactions
- **AND** if neither index nor hash is specified, the current (latest) block is returned

#### Scenario: Fetch block transaction
- **WHEN** a client calls `/block/transaction` with block and transaction identifiers
- **THEN** the specific transaction within that block is returned

#### Scenario: Search transactions
- **WHEN** a client calls `/search/transactions` with optional filters (transaction hash, account, max_block, offset, limit)
- **THEN** matching `BlockTransaction` entries are returned sorted from most recent to oldest
- **AND** `total_count` and optional `next_offset` support pagination

---

### Requirement: Account API (Data API)

Clients can query account balances.

#### Scenario: Account balance at specific block
- **WHEN** a client calls `/account/balance` with an `AccountIdentifier` and optional `PartialBlockIdentifier`
- **THEN** the response contains the `block_identifier` at which the balance was computed and the `balances` array
- **AND** if `block_identifier` is specified, a historical balance lookup is performed

#### Scenario: Aggregated account balance (ICRC)
- **WHEN** a client calls `/account/balance` with metadata `aggregate_all_subaccounts: true`
- **THEN** the response contains the sum of balances across all subaccounts for the given principal

---

### Requirement: Construction API

The Rosetta server supports offline transaction construction following the standard flow: preprocess, metadata, payloads, combine, submit.

#### Scenario: Derive account from public key
- **WHEN** a client calls `/construction/derive` with a `PublicKey`
- **THEN** the response contains the derived `AccountIdentifier` for the IC principal corresponding to that public key

#### Scenario: Preprocess operations
- **WHEN** a client calls `/construction/preprocess` with a list of operations
- **THEN** the response contains `options` to pass to `/construction/metadata` and optional `required_public_keys`

#### Scenario: Fetch construction metadata
- **WHEN** a client calls `/construction/metadata` with options from preprocess
- **THEN** the response contains transaction metadata and `suggested_fee`

#### Scenario: Generate unsigned transaction and signing payloads
- **WHEN** a client calls `/construction/payloads` with operations, optional metadata (memo, created_at_time), and public keys
- **THEN** the response contains an `unsigned_transaction` (CBOR+hex encoded) and `payloads` (hex-encoded bytes to sign)

#### Scenario: Parse unsigned or signed transaction
- **WHEN** a client calls `/construction/parse` with a transaction blob and `signed` flag
- **THEN** the response contains the extracted `operations` and optional `account_identifier_signers`

#### Scenario: Combine signatures with unsigned transaction
- **WHEN** a client calls `/construction/combine` with the unsigned transaction and signatures
- **THEN** the response contains the `signed_transaction` (CBOR+hex encoded) ready for submission

#### Scenario: Submit signed transaction
- **WHEN** a client calls `/construction/submit` with a signed transaction
- **THEN** the transaction is submitted to the IC
- **AND** the response contains the `transaction_identifier`

#### Scenario: Compute transaction hash
- **WHEN** a client calls `/construction/hash` with a signed transaction
- **THEN** the response contains the computed `transaction_identifier`

---

### Requirement: ICP Rosetta Client

The ICP Rosetta client provides programmatic access to all Rosetta endpoints plus ICP-specific neuron management.

#### Scenario: Transfer ICP tokens
- **WHEN** a client calls `transfer` with sender key, receiver account, amount, and optional fee/memo
- **THEN** the client constructs TRANSFER operations (debit from sender, credit to receiver) and submits via the Construction API flow

#### Scenario: Neuron management operations
- **WHEN** a client calls neuron management methods (stake, start/stop dissolving, set dissolve timestamp, spawn, merge maturity, disburse, follow, register vote, add/remove hotkey, change auto-stake maturity)
- **THEN** the client constructs the appropriate operation types with ICP-specific metadata (neuron index, dissolve delay, etc.)
- **AND** submits via the standard Construction API flow (preprocess -> metadata -> payloads -> sign -> combine -> submit)

#### Scenario: Query neuron info
- **WHEN** a client calls `get_neuron_info` via the `/call` endpoint
- **THEN** the response contains neuron state information (dissolve delay, maturity, etc.)

#### Scenario: Query pending proposals
- **WHEN** a client calls `get_pending_proposals` via the `/call` endpoint
- **THEN** the response contains the list of currently pending governance proposals

#### Scenario: Wait for transaction confirmation
- **WHEN** a client submits a transaction via `make_submit_and_wait_for_transaction`
- **THEN** the client polls `/search/transactions` until the transaction appears or a configurable timeout (default 300 seconds) is reached
- **AND** if the timeout expires, an error is returned

---

### Requirement: ICP Rosetta Runner

The runner launches the ICP Rosetta server binary as a subprocess for testing.

#### Scenario: Start Rosetta server
- **WHEN** `start_rosetta` is called with a binary path, state directory, and `RosettaOptions`
- **THEN** the Rosetta binary is spawned with arguments for `--ic-url`, `--port-file`, `--store-type`, and optional `--canister-id`, `--offline`, `--store-location`
- **AND** the runner waits for the port file to be written and the `/network/list` endpoint to respond successfully
- **AND** the runner returns a `RosettaContext` with the assigned port

#### Scenario: Store type selection
- **WHEN** `RosettaOptions` is built with `with_persistent_storage`
- **THEN** `store_type` is set to "sqlite" (persistent)
- **AND** without that option, `store_type` defaults to "sqlite-in-memory"

#### Scenario: Kill and restart Rosetta process
- **WHEN** `kill_rosetta_process` is called on a `RosettaContext`
- **THEN** the running Rosetta process is killed
- **AND** the state directory is preserved for restarting with existing block data

---

### Requirement: ICRC Rosetta Client

The ICRC Rosetta client supports ICRC-1 transfers, ICRC-2 approvals, and transfer-from operations.

#### Scenario: ICRC-1 transfer
- **WHEN** a client calls `make_submit_and_wait_for_transaction` with TRANSFER operations
- **THEN** two operations are constructed: a debit (negative amount) from the sender and a credit (positive amount) to the receiver
- **AND** the transaction is signed, combined, submitted, and confirmed via search

#### Scenario: ICRC-2 approve
- **WHEN** a client calls `build_approve_operations` with an allowance, spender, optional expected_allowance, and optional expires_at
- **THEN** two operations are constructed: an APPROVE operation (with `ApproveMetadata` including allowance/expected_allowance/expires_at) and a SPENDER operation
- **AND** the currency for the allowance amount is fetched from the `/construction/metadata` endpoint's suggested_fee

#### Scenario: ICRC-2 transfer_from
- **WHEN** a client calls `build_transfer_from_operations` with a spender keypair, from_account, to_account, and amount
- **THEN** three operations are constructed: a debit TRANSFER from `from_account`, a credit TRANSFER to `to_account`, and a SPENDER operation identifying the authorized spender

#### Scenario: Transaction signing and verification
- **WHEN** `sign_transaction` is called with a keypair and payloads
- **THEN** each payload is signed with the keypair
- **AND** the signature is verified locally before being returned (Ed25519 or Secp256k1)
- **AND** if verification fails, an error is returned

#### Scenario: Health and readiness checks
- **WHEN** `health()` or `ready()` is called
- **THEN** the client queries `/health` or `/ready` endpoints respectively

#### Scenario: Aggregated balance query
- **WHEN** `account_balance_aggregated` is called
- **THEN** the request to `/account/balance` includes `aggregate_all_subaccounts: true` in metadata
- **AND** the response contains the sum of balances across all subaccounts for the principal

---

### Requirement: ICRC Rosetta Runner

The runner launches the ICRC Rosetta server binary as a subprocess for testing.

#### Scenario: Start ICRC Rosetta server
- **WHEN** `start_rosetta` is called with a binary path and `RosettaOptions`
- **THEN** the binary is spawned with `--ledger-id`, `--network-type`, `--store-type`, `--port-file`, and optional `--network-url`, `--offline`, `--icrc1-symbol`, `--icrc1-decimals`, `--exit-on-sync`, `--log-file`
- **AND** the runner waits up to 60 seconds for the port file to appear
- **AND** returns a `RosettaContext` with the assigned port

#### Scenario: Multi-token mode
- **WHEN** `RosettaOptions` includes `multi_tokens` configuration
- **THEN** the runner passes `--multi-tokens` and optionally `--multi-tokens-store-dir` instead of `--ledger-id`

#### Scenario: CLI-based transaction execution
- **WHEN** `make_transaction_with_rosetta_client_binary` is called with a rosetta-client binary path and `RosettaClientArgs`
- **THEN** the rosetta-client binary is executed as a subprocess with arguments for operation type, accounts, amounts, allowances, memo, created_at_time, and a PEM file for the sender keypair

#### Scenario: Default ICRC options
- **WHEN** `RosettaOptions::default()` is used
- **THEN** `store_type` is "in-memory", `network_type` is "testnet", `offline` is `true`, symbol is "XTST", decimals is 8

---

### Requirement: Ledger Canister Blocks Synchronizer

The synchronizer downloads, verifies, and stores ICP ledger blocks for the Rosetta server.

#### Scenario: Initialize synchronizer with persistent storage
- **WHEN** `LedgerBlocksSynchronizer::new` is called with a store location path
- **THEN** a SQLite database is created or loaded at the specified path
- **AND** existing blocks are loaded and the sync state is reported via logs

#### Scenario: Initialize synchronizer with in-memory storage
- **WHEN** `LedgerBlocksSynchronizer::new` is called without a store location
- **THEN** an in-memory block store is created
- **AND** blocks must be re-synced from the ledger on each restart

#### Scenario: Verify store consistency on startup
- **WHEN** the synchronizer starts with existing blocks in storage
- **THEN** it verifies that the stored blocks are consistent with the ledger canister
- **AND** if verification info is provided, the tip of chain certificate is validated

#### Scenario: Sync blocks from ledger canister
- **WHEN** the synchronizer runs its sync loop
- **THEN** it queries the ledger canister for blocks in batches (up to 500,000 per batch for database writes)
- **AND** blocks are verified against their parent hash to maintain chain integrity
- **AND** block certification is verified when `VerificationInfo` is provided
- **AND** progress is reported via an `indicatif` progress bar for large syncs (>1000 blocks)

#### Scenario: Retry on query failure
- **WHEN** a block query to the ledger canister fails
- **THEN** the synchronizer retries up to 5 times (MAX_RETRY)
- **AND** tip-of-chain queries retry up to 5 times with 500ms delay between attempts

#### Scenario: Block pruning
- **WHEN** `store_max_blocks` is configured and the block count exceeds the limit
- **THEN** blocks are pruned in batches of 100,000 (PRUNE_DELAY) to avoid frequent small deletions
- **AND** the oldest blocks are removed first

#### Scenario: Canister access and agent setup
- **WHEN** the synchronizer connects to the IC
- **THEN** it creates an `Agent` with anonymous identity, configurable timeout, and optional root key
- **AND** the agent uses timestamp-based nonces for request deduplication
- **AND** query signature verification is disabled for the exchanges testnet

#### Scenario: Block storage in SQLite
- **WHEN** blocks are stored in the SQLite database
- **THEN** each block record includes: `block_hash`, `encoded_block`, `parent_hash`, `block_idx`, `verified` flag, `timestamp`, `tx_hash`, `operation_type`, `from_account`, `to_account`, `spender_account`, `amount`, `allowance`, `expected_allowance`, `fee`, `created_at_time`, `expires_at`, `memo`, and `icrc1_memo`
- **AND** the operation types stored are: Burn, Mint, Transfer, Approve, and TransferFrom

#### Scenario: Timestamp conversion
- **WHEN** timestamps are stored or retrieved
- **THEN** they are converted between IC nanoseconds-since-epoch and ISO 8601 (RFC 3339) format
- **AND** the conversion is lossless (roundtrip preserves the original value)

#### Scenario: Synced height metric
- **WHEN** blocks are synced
- **THEN** the `synced_height` metric is updated with the latest block index
- **AND** the metric uses the "ICP" token type and the ICP ledger canister ID
