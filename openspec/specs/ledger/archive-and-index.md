# Archive and Index Canisters

**Crates**: `ic-ledger-suite-orchestrator`

The ledger suite includes archive canisters for long-term block storage and index canisters for efficient account-based transaction lookup. Both ICP and ICRC-1 ledgers have their own archive and index canister implementations.

## Requirements

### Requirement: Archive Canister - Block Storage

Archive canisters store blocks that have been moved from the ledger to save space.

#### Scenario: Append blocks to archive
- **WHEN** the ledger sends blocks to an archive canister via `append_blocks`
- **THEN** the archive canister stores the encoded blocks
- **AND** the block indices are tracked as an inclusive range [from, to]

#### Scenario: Archive capacity
- **WHEN** `remaining_capacity` is queried on an archive canister
- **THEN** the remaining byte capacity (up to `node_max_memory_size_bytes`, default 1 GiB) is returned

#### Scenario: Archive becomes full
- **WHEN** an archive canister's remaining capacity is less than the next block's size
- **THEN** a new archive canister is created
- **AND** subsequent blocks are sent to the new archive

### Requirement: Archive Canister - Creation

The ledger creates archive canisters on demand.

#### Scenario: First archive creation
- **WHEN** no archive canister exists and archiving is triggered
- **THEN** a new canister is created with the archive wasm
- **AND** the configured amount of cycles is attached (default: 10 trillion)
- **AND** the ledger canister ID is passed as the archive's parent
- **AND** the specified controllers are set on the new canister

#### Scenario: Insufficient cycles for archive creation
- **WHEN** the ledger does not have enough liquid cycles
- **THEN** archive creation fails with an error message
- **AND** the archiving failure metric is incremented

#### Scenario: Minimum cycles validation
- **WHEN** archive creation is attempted on an application subnet
- **THEN** the system validates that:
  - `cycles_for_archive_creation` >= 3x the canister creation cost (or at least 4.5 trillion)
  - The ledger retains at least 10 trillion liquid cycles after creation

#### Scenario: System subnet handling
- **WHEN** the ledger runs on a system subnet (canister creation cost = 0)
- **THEN** archive creation proceeds without the minimum cycles checks

### Requirement: Archive Canister - Configuration

Archive behavior is configured via `ArchiveOptions`.

#### Scenario: Archive options
- **WHEN** the ledger is initialized with archive options
- **THEN** the following are configured:
  - `trigger_threshold` - number of unarchived blocks that triggers archiving
  - `num_blocks_to_archive` - number of blocks to archive per trigger
  - `node_max_memory_size_bytes` - maximum memory per archive node (default: 1 GiB)
  - `max_message_size_bytes` - maximum inter-canister message size (default: 2 MiB)
  - `controller_id` - primary controller of archive canisters
  - `more_controller_ids` - additional controllers
  - `cycles_for_archive_creation` - cycles to send for archive creation
  - `max_transactions_per_response` - max transactions returned by get_transactions

### Requirement: Archive Canister - Block Chunking

Blocks are sent to archives in chunks respecting message size limits.

#### Scenario: Chunk splitting
- **WHEN** blocks are sent to an archive
- **THEN** they are split into chunks that fit within the minimum of:
  - The archive's `max_message_size_bytes`
  - The ledger's max message size
- **AND** each chunk is sent via a separate `append_blocks` call

#### Scenario: Maximum blocks per archive operation
- **WHEN** archiving is triggered
- **THEN** at most 18,000 blocks (MAX_BLOCKS_TO_ARCHIVE) are processed per operation
- **AND** blocks are taken from the oldest unarchived blocks

### Requirement: Archive Canister - Concurrent Archiving Prevention

Only one archiving operation can run at a time.

#### Scenario: Archiving guard
- **WHEN** archiving is in progress
- **AND** another archiving operation is attempted
- **THEN** the second operation returns immediately without action

#### Scenario: Guard cleanup
- **WHEN** the archiving guard is dropped (archiving completes or fails)
- **THEN** the `archiving_in_progress` flag is reset to false

### Requirement: Archive Canister - Partial Failure Handling

Archiving can partially succeed if communication with the archive fails mid-stream.

#### Scenario: Partial archive success
- **WHEN** some chunks are successfully sent but a subsequent chunk fails
- **THEN** the successfully archived blocks are removed from the ledger
- **AND** the failure is logged with the number of sent vs. total blocks
- **AND** the archiving failure metric is incremented

### Requirement: ICP Index Canister

The ICP index canister provides efficient transaction lookup by `AccountIdentifier`.

#### Scenario: Initialize ICP index
- **WHEN** the ICP index canister is initialized with `InitArg { ledger_id }`
- **THEN** it begins synchronizing blocks from the specified ICP ledger

#### Scenario: Query transactions by account
- **WHEN** `get_account_identifier_transactions` is called with:
  - `account_identifier` - the account to query
  - `start` - optional starting transaction ID for pagination
  - `max_results` - maximum number of results
- **THEN** transactions involving the account are returned in reverse chronological order
- **AND** each result includes the block index and the settled transaction details

#### Scenario: Transaction response format
- **WHEN** transactions are returned from the ICP index
- **THEN** each `SettledTransaction` includes:
  - `operation` (Transfer, Mint, Burn, Approve)
  - `memo` (u64)
  - `created_at_time` (optional)
  - `icrc1_memo` (optional, bytes)
  - `timestamp` (block timestamp)

#### Scenario: Query index status
- **WHEN** `status` is called on the ICP index
- **THEN** `num_blocks_synced` is returned

#### Scenario: Get blocks from index
- **WHEN** `get_blocks` is called with a range
- **THEN** the encoded blocks within the range are returned
- **AND** `chain_length` indicates the total number of indexed blocks

### Requirement: ICRC-1 Index Canister (index-ng)

The ICRC-1 index canister provides account-based transaction lookup for ICRC-1 ledgers.

#### Scenario: Initialize ICRC-1 index
- **WHEN** the ICRC-1 index canister is initialized with `InitArg { ledger_id }`
- **THEN** it begins synchronizing blocks from the specified ICRC-1 ledger
- **AND** optionally configures `retrieve_blocks_from_ledger_interval_seconds`

#### Scenario: Query transactions by account
- **WHEN** `get_account_transactions` is called with:
  - `account` - the ICRC-1 account to query
  - `start` - optional starting block index for pagination
  - `max_results` - maximum number of results (Nat)
- **THEN** transactions involving the account are returned
- **AND** each result includes the block index and the ICRC-3 `Transaction`
- **AND** the current balance for the account is included

#### Scenario: Transaction with ID response
- **WHEN** account transactions are returned
- **THEN** each `TransactionWithId` includes:
  - `id` (BlockIndex)
  - `transaction` (ICRC-3 Transaction with kind, mint/burn/transfer/approve details)

#### Scenario: Oldest transaction ID
- **WHEN** account transactions are returned
- **THEN** the response includes `oldest_tx_id` for the account
- **AND** this can be used to determine if all transactions have been fetched

#### Scenario: List subaccounts
- **WHEN** `list_subaccounts` is called with:
  - `owner` - the principal
  - `start` - optional subaccount for pagination
- **THEN** the subaccounts associated with the owner are returned

#### Scenario: Get blocks from ICRC-1 index
- **WHEN** `get_blocks` is called with a range
- **THEN** GenericBlock values are returned
- **AND** the maximum is DEFAULT_MAX_BLOCKS_PER_RESPONSE (2000)

#### Scenario: Fee collector ranges
- **WHEN** `fee_collector_ranges` is queried
- **THEN** the fee collector accounts and their active block ranges are returned

#### Scenario: ICRC-1 index status
- **WHEN** `status` is called
- **THEN** the number of synced blocks is returned

#### Scenario: Block retrieval method
- **WHEN** the index determines which method to use for fetching blocks
- **THEN** it may use either:
  - `get_blocks` - the pre-ICRC-3 endpoint
  - `icrc3_get_blocks` - the ICRC-3 compatible endpoint
- **AND** the method is determined based on ledger capabilities

### Requirement: Index Canister - Upgrade

Both index canisters support upgrades.

#### Scenario: Upgrade ICRC-1 index
- **WHEN** the ICRC-1 index is upgraded with `UpgradeArg`
- **THEN** the `ledger_id` can optionally be changed
- **AND** the `retrieve_blocks_from_ledger_interval_seconds` can be updated

#### Scenario: Upgrade ICP index
- **WHEN** the ICP index is upgraded with `UpgradeArg`
- **THEN** the `ledger_id` can optionally be changed
- **AND** synchronization continues from where it left off

### Requirement: Blockchain Data Integrity

The blockchain maintains hash chain integrity.

#### Scenario: Parent hash validation
- **WHEN** a new block is added to the blockchain
- **AND** its parent hash does not match the last block's hash
- **THEN** the block is rejected with an error

#### Scenario: Timestamp monotonicity
- **WHEN** a new block is added
- **AND** its timestamp is older than the previous block's timestamp
- **THEN** the block is rejected with an error

#### Scenario: Local block range
- **WHEN** the local block range is queried
- **THEN** it returns `[num_archived_blocks, num_archived_blocks + num_unarchived_blocks)`
- **AND** this represents the blocks currently stored in the ledger canister

### Requirement: Block Location Resolution

The ledger resolves block locations across local storage and archives.

#### Scenario: Block in local range
- **WHEN** a block at height H is requested
- **AND** H is within the local block range
- **THEN** the block is served from local storage

#### Scenario: Block in archive
- **WHEN** a block at height H is requested
- **AND** H is within an archived range
- **THEN** the request is redirected to the appropriate archive canister

#### Scenario: Non-overlapping ranges
- **WHEN** block locations are computed for a range
- **THEN** local and archived ranges do not overlap
- **AND** archive ranges are returned oldest first
