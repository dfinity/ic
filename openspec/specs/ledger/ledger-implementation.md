# Ledger Implementation Specification

This specification covers the ledger implementation crates in the IC repository. These crates collectively implement the ICP ledger, the ICRC-1/2/3 standard-compliant ledger, archiving infrastructure, indexing canisters, and token type abstractions. The system is organized as a layered architecture: core types and traits at the bottom (`ic-ledger-core`), generic canister logic in the middle (`ic-ledger-canister-core`), and concrete canister implementations at the top (ICP and ICRC-1 variants).

**Crates covered:**

| Crate | Path |
|---|---|
| `ic-ledger-core` | `rs/ledger_suite/common/ledger_core/` |
| `ic-ledger-canister-core` | `rs/ledger_suite/common/ledger_canister_core/` |
| `ic-icp-archive` | `rs/ledger_suite/icp/archive/` |
| `ic-icp-index` | `rs/ledger_suite/icp/index/` |
| `ic-icrc1-ledger` | `rs/ledger_suite/icrc1/ledger/` |
| `ic-icrc1-archive` | `rs/ledger_suite/icrc1/archive/` |
| `ic-icrc1-index-ng` | `rs/ledger_suite/icrc1/index-ng/` |
| `ic-icrc1-tokens-u64` | `rs/ledger_suite/icrc1/tokens_u64/` |
| `ic-icrc1-tokens-u256` | `rs/ledger_suite/icrc1/tokens_u256/` |
| `ic-ledger-suite-state-machine-tests` | `rs/ledger_suite/tests/sm-tests/` |
| `ledger-suite-orchestrator` | `rs/ethereum/ledger-suite-orchestrator/` |

---

## Requirements

### Requirement: Token Type Abstraction (`ic-ledger-core` -- `tokens` module)

The `TokensType` trait defines the interface all token amount types must satisfy. Implementations must support checked arithmetic, ordering, serialization, and conversion to/from Candid `Nat`. The built-in `Tokens` struct represents ICP amounts as `u64` e8s (10^-8 ICP units).

#### Scenario: Tokens construction with whole units and fractional e8s
- **WHEN** `Tokens::new(tokens, e8s)` is called with valid arguments where `e8s < 100_000_000`
- **THEN** a `Tokens` value is returned where `get_tokens()` equals `tokens` and `get_remainder_e8s()` equals `e8s`
- **AND** `get_e8s()` equals `tokens * 100_000_000 + e8s`

#### Scenario: Tokens construction rejects excessive fractional e8s
- **WHEN** `Tokens::new(tokens, e8s)` is called with `e8s >= 100_000_000`
- **THEN** an error is returned

#### Scenario: Tokens construction rejects overflow
- **WHEN** `Tokens::new(tokens, e8s)` is called with values that would overflow `u64`
- **THEN** an error is returned

#### Scenario: Checked addition returns None on overflow
- **WHEN** `CheckedAdd::checked_add` is called on two `Tokens` values whose sum exceeds `u64::MAX`
- **THEN** `None` is returned
- **AND** no panic occurs

#### Scenario: Checked subtraction returns None on underflow
- **WHEN** `CheckedSub::checked_sub` is called where the subtrahend exceeds the minuend
- **THEN** `None` is returned
- **AND** no panic occurs

#### Scenario: Zero identity
- **WHEN** `Tokens::zero()` is called
- **THEN** the returned value has `e8s == 0`
- **AND** `is_zero()` returns `true`

#### Scenario: TokensType trait completeness
- **WHEN** any type implements `TokensType`
- **THEN** it must also implement `Bounded`, `CheckedAdd`, `CheckedSub`, `Zero`, `Clone`, `Debug`, `Into<Nat>`, `TryFrom<Nat>`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Serialize`, `DeserializeOwned`, and `Hash`

#### Scenario: Tokens Nat round-trip conversion
- **WHEN** a `Tokens` value is converted to `Nat` via `Into<Nat>` and back via `TryFrom<Nat>`
- **THEN** the resulting value equals the original

#### Scenario: Tokens stable storage round-trip
- **WHEN** a `Tokens` value is serialized via `Storable::to_bytes` (8-byte little-endian)
- **AND** deserialized via `Storable::from_bytes`
- **THEN** the resulting value equals the original
- **AND** the storage size is fixed at 8 bytes

---

### Requirement: U64 Token Type (`ic-icrc1-tokens-u64`)

The `U64` type wraps a `u64` to serve as the standard ICRC-1 token amount type for tokens that fit within 64 bits. It declares `TYPE = "U64"` for archive token type verification.

#### Scenario: U64 implements the TokensType trait
- **WHEN** `U64` is used as a token amount
- **THEN** it satisfies all `TokensType` bounds including `Bounded`, `CheckedAdd`, `CheckedSub`, `Zero`, `Serialize`, `Deserialize`, and conversions to/from `Nat`

#### Scenario: U64 deserializes from both plain integers and legacy e8s maps
- **WHEN** a `U64` value is deserialized from a CBOR/JSON integer
- **THEN** it produces the correct `U64` value
- **AND** **WHEN** a `U64` value is deserialized from a `{ e8s: u64 }` map (legacy ICP format)
- **THEN** it produces the equivalent `U64` value from the e8s field

#### Scenario: U64 Nat conversion rejects values exceeding u64
- **WHEN** `U64::try_from(nat)` is called with a `Nat` value larger than `u64::MAX`
- **THEN** an error string is returned

#### Scenario: U64 stable storage round-trip
- **WHEN** a `U64` is serialized via `Storable::to_bytes` and deserialized via `Storable::from_bytes`
- **THEN** the resulting value equals the original

#### Scenario: U64 string parsing
- **WHEN** `U64::from_str(s)` is called with a valid numeric string
- **THEN** the correct `U64` value is returned
- **AND** **WHEN** called with an invalid string
- **THEN** an error is returned

---

### Requirement: U256 Token Type (`ic-icrc1-tokens-u256`)

The `U256` type wraps a 256-bit unsigned integer (from the `ethnum` crate) to support tokens with large supply ranges, such as Ethereum-bridged ERC-20 tokens. It declares `TYPE = "U256"` for archive token type verification.

#### Scenario: U256 implements the TokensType trait
- **WHEN** `U256` is used as a token amount
- **THEN** it satisfies all `TokensType` bounds including `Bounded`, `CheckedAdd`, `CheckedSub`, `Zero`, `Serialize`, `Deserialize`, and conversions to/from `Nat`

#### Scenario: U256 serializes small values as plain u64
- **WHEN** a `U256` value that fits in `u64` is serialized to CBOR
- **THEN** it is encoded as a plain `u64` integer (not tagged)

#### Scenario: U256 serializes large values with CBOR bignum tag
- **WHEN** a `U256` value exceeding `u64::MAX` is serialized to CBOR
- **THEN** it is encoded with CBOR tag 2 (positive bignum) in big-endian byte representation

#### Scenario: U256 deserializes from u64, u128, and tagged bignum
- **WHEN** a `U256` is deserialized from a CBOR integer (u64 or u128)
- **THEN** the correct `U256` value is produced
- **AND** **WHEN** deserialized from a CBOR tag-2 bignum
- **THEN** the correct `U256` value is produced

#### Scenario: U256 Nat conversion rejects values exceeding 256 bits
- **WHEN** `U256::try_from(nat)` is called with a `Nat` value requiring more than 32 bytes
- **THEN** an error string is returned

#### Scenario: U256 stable storage uses fixed 32-byte big-endian encoding
- **WHEN** a `U256` is serialized via `Storable::to_bytes`
- **THEN** it produces exactly 32 bytes in big-endian order
- **AND** round-tripping through `from_bytes` recovers the original value

#### Scenario: U256 conversion from u64 and u128
- **WHEN** `U256::from(n)` is called with a `u64` or `u128` value
- **THEN** the resulting `U256` holds the same numeric value
- **AND** `try_as_u64()` returns `Some(n)` if the value fits in `u64`, or `None` otherwise

---

### Requirement: TimeStamp Type (`ic-ledger-core` -- `timestamp` module)

The `TimeStamp` struct represents a point in time as nanoseconds since the Unix epoch. It supports arithmetic with `Duration` and conversion to/from `SystemTime`.

#### Scenario: TimeStamp creation from nanoseconds
- **WHEN** `TimeStamp::from_nanos_since_unix_epoch(nanos)` is called
- **THEN** `as_nanos_since_unix_epoch()` returns the same `nanos` value

#### Scenario: TimeStamp creation from seconds and nanoseconds
- **WHEN** `TimeStamp::new(secs, nanos)` is called with `nanos < 1_000_000_000`
- **THEN** `as_nanos_since_unix_epoch()` returns `secs * 1_000_000_000 + nanos`
- **AND** if `nanos >= 1_000_000_000`, the function panics

#### Scenario: TimeStamp addition with Duration uses saturating arithmetic
- **WHEN** a `TimeStamp` is added to a `Duration` that would overflow `u64`
- **THEN** the result saturates at `u64::MAX` nanoseconds rather than panicking

#### Scenario: TimeStamp subtraction with Duration uses saturating arithmetic
- **WHEN** a `Duration` larger than the timestamp's nanos is subtracted from a `TimeStamp`
- **THEN** the result saturates at 0 nanoseconds rather than panicking

#### Scenario: TimeStamp SystemTime round-trip
- **WHEN** a `SystemTime` is converted to a `TimeStamp` and back
- **THEN** the resulting `SystemTime` equals the original

#### Scenario: TimeStamp stable storage round-trip
- **WHEN** a `TimeStamp` is stored via `Storable::to_bytes` (8-byte little-endian)
- **AND** restored via `Storable::from_bytes`
- **THEN** the resulting `TimeStamp` equals the original

---

### Requirement: Balance Management (`ic-ledger-core` -- `balances` module)

The `Balances` struct tracks account balances and the total token pool. It supports transfer, mint, burn, credit, and debit operations with checked arithmetic. The `BalancesStore` trait abstracts the underlying storage (heap `BTreeMap` or stable structures).

#### Scenario: Default balances initialization
- **WHEN** `Balances::default()` is called
- **THEN** the `token_pool` is initialized to `Tokens::max_value()`
- **AND** the store is empty
- **AND** `total_supply()` returns zero

#### Scenario: Transfer between two accounts
- **WHEN** `Balances::transfer(from, to, amount, fee, fee_collector)` is called with sufficient balance in the `from` account
- **THEN** the `from` account is debited by `amount + fee`
- **AND** the `to` account is credited by `amount`
- **AND** if a `fee_collector` is provided, the fee is credited to the fee collector
- **AND** if no `fee_collector` is provided, the fee is returned to the token pool

#### Scenario: Transfer with insufficient funds
- **WHEN** `Balances::transfer` is called and the `from` account balance is less than `amount + fee`
- **THEN** `BalanceError::InsufficientFunds` is returned with the current balance
- **AND** no balances are modified

#### Scenario: Mint operation
- **WHEN** `Balances::mint(to, amount)` is called
- **THEN** the `to` account is credited by `amount`
- **AND** the token pool is reduced by `amount`
- **AND** if the token pool would underflow, the function panics ("total token supply exceeded")

#### Scenario: Burn operation
- **WHEN** `Balances::burn(from, amount)` is called with sufficient balance
- **THEN** the `from` account is debited by `amount`
- **AND** the token pool is increased by `amount`

#### Scenario: Zero-balance accounts are removed from storage
- **WHEN** an account's balance reaches zero after a debit operation
- **THEN** the account entry is removed from the `BalancesStore`
- **AND** this prevents unbounded growth of the accounts map

#### Scenario: Total supply calculation
- **WHEN** `Balances::total_supply()` is called
- **THEN** it returns `Tokens::max_value() - token_pool`
- **AND** this represents all tokens currently held by accounts

#### Scenario: Account balance query for missing accounts
- **WHEN** `Balances::account_balance(account)` is called for a nonexistent account
- **THEN** `Tokens::zero()` is returned

---

### Requirement: Approval and Allowance Management (`ic-ledger-core` -- `approvals` module)

The `AllowanceTable` manages spending allowances for (account, spender) pairs, supporting the ICRC-2 approve/transfer_from model. Allowances can have optional expiration timestamps. The `AllowancesData` trait abstracts the underlying storage.

#### Scenario: Setting an allowance for a new pair
- **WHEN** `AllowanceTable::approve(account, spender, amount, expires_at, now, expected_allowance)` is called with a new (account, spender) pair
- **THEN** the allowance is set to `amount` with the given `expires_at` and `arrived_at = now`
- **AND** if `expires_at` is provided, it is added to the expiration queue

#### Scenario: Updating an existing allowance
- **WHEN** `approve` is called for an existing (account, spender) pair
- **THEN** the old allowance is replaced with the new `amount` and `expires_at`
- **AND** the old expiration entry is removed and the new one is inserted if changed

#### Scenario: Self-approval is rejected
- **WHEN** `approve` is called where `account == spender`
- **THEN** `ApproveError::SelfApproval` is returned

#### Scenario: Expired approval is rejected
- **WHEN** `approve` is called with `expires_at <= now`
- **THEN** `ApproveError::ExpiredApproval` is returned with the current time

#### Scenario: Expected allowance check fails
- **WHEN** `approve` is called with `expected_allowance` set and the current allowance does not match
- **THEN** `ApproveError::AllowanceChanged` is returned with the `current_allowance`

#### Scenario: Expected allowance check succeeds for new pair with zero expected
- **WHEN** `approve` is called for a new pair with `expected_allowance = Some(zero)`
- **THEN** the approval proceeds normally

#### Scenario: Setting allowance to zero removes the entry
- **WHEN** `approve` is called with `amount` equal to zero for an existing allowance
- **THEN** the allowance entry is removed from the table
- **AND** any associated expiration is removed from the expiration queue

#### Scenario: Setting allowance to zero for a new pair is a no-op
- **WHEN** `approve` is called with `amount` equal to zero for a nonexistent pair
- **THEN** no entry is created and zero is returned

#### Scenario: Querying an allowance
- **WHEN** `AllowanceTable::allowance(account, spender, now)` is called
- **THEN** the current allowance for the pair is returned if it exists and is not expired
- **AND** if no allowance exists or it is expired, a default (zero) allowance is returned

#### Scenario: Using an allowance (transfer_from)
- **WHEN** `AllowanceTable::use_allowance(account, spender, amount, now)` is called with sufficient non-expired allowance
- **THEN** the allowance is reduced by `amount`
- **AND** the remaining allowance is returned

#### Scenario: Using an allowance with insufficient amount
- **WHEN** `use_allowance` is called with `amount` exceeding the current allowance
- **THEN** `InsufficientAllowance` is returned with the current allowance amount

#### Scenario: Using an expired allowance
- **WHEN** `use_allowance` is called and the allowance's `expires_at` is at or before `now`
- **THEN** `InsufficientAllowance` with zero amount is returned

#### Scenario: Using the full allowance removes the entry
- **WHEN** `use_allowance` reduces the allowance to exactly zero
- **THEN** the allowance entry is removed from the table
- **AND** any associated expiration is removed

#### Scenario: Pruning expired allowances
- **WHEN** `AllowanceTable::prune(now, limit)` is called
- **THEN** up to `limit` allowances whose `expires_at <= now` are removed from the table
- **AND** the count of pruned entries is returned
- **AND** pruning stops early if the next expiration is in the future

#### Scenario: Expiration queue invariant
- **WHEN** any operation on the `AllowanceTable` completes
- **THEN** the number of entries in the expiration queue is less than or equal to the number of allowances (debug assertion)

---

### Requirement: Block Types and Blockchain Chain (`ic-ledger-core` -- `block` module, `ic-ledger-canister-core` -- `blockchain` module)

The `BlockType` trait defines how blocks are constructed, encoded, decoded, and hashed. The `EncodedBlock` struct is a byte-buffer wrapper for serialized blocks. The `Blockchain` struct in `ic-ledger-canister-core` maintains a chain of blocks with hash linking and coordinates with archive storage.

#### Scenario: Block construction preserves parent hash and timestamp
- **WHEN** `BlockType::from_transaction(parent_hash, tx, timestamp, fee, fee_collector)` is called
- **THEN** the resulting block's `parent_hash()` equals the provided `parent_hash`
- **AND** the block's `timestamp()` equals the provided `timestamp`

#### Scenario: Block encode/decode round-trip
- **WHEN** a block is encoded via `BlockType::encode` and decoded via `BlockType::decode`
- **THEN** the decoded block equals the original

#### Scenario: Block hash is computed from encoded representation
- **WHEN** `BlockType::block_hash(encoded)` is called
- **THEN** it returns a `HashOf<EncodedBlock>` computed from the bytes of the encoded block
- **AND** the hash is deterministic for the same encoded bytes

#### Scenario: First block in chain has no parent hash
- **WHEN** the first block is added to an empty blockchain
- **THEN** `parent_hash()` on that block returns `None`
- **AND** `blockchain.last_hash` must also be `None` before adding the first block

#### Scenario: Adding a block to the blockchain
- **WHEN** `Blockchain::add_block(block)` is called
- **THEN** the block's parent hash must match `blockchain.last_hash`
- **AND** the block's timestamp must be >= `blockchain.last_timestamp`
- **AND** the encoded block is stored in the block data container
- **AND** `last_hash` is updated to the hash of the encoded block
- **AND** `last_timestamp` is updated to the block's timestamp
- **AND** the returned index equals `chain_length - 1`

#### Scenario: Adding a block with mismatched parent hash
- **WHEN** `add_block` is called with a block whose `parent_hash()` differs from `last_hash`
- **THEN** an error is returned ("Cannot apply block because its parent hash doesn't match")

#### Scenario: Adding a block with an older timestamp
- **WHEN** `add_block` is called with a block whose `timestamp()` is strictly less than `last_timestamp`
- **THEN** an error is returned ("Cannot apply block because its timestamp is older than the previous tip")

#### Scenario: Chain length accounting
- **WHEN** `chain_length()` is called
- **THEN** it returns `num_archived_blocks + num_unarchived_blocks`
- **AND** this accounts for both locally stored and archived blocks

#### Scenario: Local block range
- **WHEN** `local_block_range()` is called
- **THEN** it returns the range `num_archived_blocks..num_archived_blocks + num_unarchived_blocks`

#### Scenario: Blocks selected for archiving by threshold
- **WHEN** `get_blocks_for_archiving(trigger_threshold, num_blocks_to_archive)` is called
- **AND** `num_unarchived_blocks >= trigger_threshold`
- **THEN** up to `num_blocks_to_archive` oldest unarchived blocks are returned
- **AND** if `num_unarchived_blocks < trigger_threshold`, an empty collection is returned

#### Scenario: Archived blocks removed from local storage
- **WHEN** `remove_archived_blocks(len)` is called
- **THEN** the oldest `len` blocks are removed from local block storage
- **AND** `num_archived_blocks` increases by `len`
- **AND** if `len` exceeds the number of local blocks, the function panics

#### Scenario: BlockDataContainer abstracts stable storage
- **WHEN** blocks are stored via a `BlockDataContainer` implementation
- **THEN** `with_blocks` and `with_blocks_mut` provide access to a `StableBTreeMap<u64, Vec<u8>>`
- **AND** block indices are global (accounting for archived blocks)

---

### Requirement: Transaction Application (`ic-ledger-canister-core` -- `ledger` module)

The `apply_transaction` function is the core entry point for processing a new transaction. It handles deduplication, throttling, approval pruning, balance updates, and block creation.

#### Scenario: Successful transaction application
- **WHEN** `apply_transaction(ledger, transaction, now, effective_fee)` is called with a valid transaction
- **THEN** the transaction is applied to the ledger's balances and/or approvals
- **AND** a new block is appended to the blockchain
- **AND** the block index and block hash are returned as `(BlockIndex, HashOf<EncodedBlock>)`

#### Scenario: Transaction deduplication via created_at_time
- **WHEN** a transaction with `created_at_time` set is submitted
- **AND** a transaction with the same hash already exists in the deduplication window
- **THEN** `TransferError::TxDuplicate { duplicate_of }` is returned with the original block index

#### Scenario: Transaction without created_at_time skips deduplication
- **WHEN** a transaction with `created_at_time` of `None` is submitted
- **THEN** deduplication checks are skipped entirely
- **AND** the transaction is not recorded in the deduplication index

#### Scenario: Transaction too old for deduplication window
- **WHEN** a transaction with `created_at_time` is submitted
- **AND** `created_at_time + transaction_window < now`
- **THEN** `TransferError::TxTooOld` is returned with the `allowed_window_nanos`

#### Scenario: Transaction created in the future
- **WHEN** a transaction with `created_at_time` is submitted
- **AND** `created_at_time > now + PERMITTED_DRIFT`
- **THEN** `TransferError::TxCreatedInFuture` is returned with the current `ledger_time`

#### Scenario: Transaction throttling under load
- **WHEN** the number of transactions in the current window exceeds half of `max_transactions_in_window`
- **AND** the per-second rate limit is exceeded
- **AND** no old transactions were purged in this call
- **THEN** `TransferError::TxThrottled` is returned

#### Scenario: Throttling allows transactions when old ones are purged
- **WHEN** `purge_old_transactions` removes at least one transaction
- **THEN** the throttle check is bypassed for the current transaction

#### Scenario: Insufficient funds
- **WHEN** a transfer or burn transaction is applied and the source account has insufficient balance
- **THEN** `TransferError::InsufficientFunds` is returned with the current balance

#### Scenario: Insufficient allowance for transfer_from
- **WHEN** a transfer_from transaction is applied and the spender's allowance is insufficient
- **THEN** `TransferError::InsufficientAllowance` is returned with the current allowance

#### Scenario: Expired approval on transaction
- **WHEN** a transaction references an expired approval
- **THEN** `TransferError::ExpiredApproval { ledger_time }` is returned

#### Scenario: Allowance changed during transaction
- **WHEN** a transaction's expected allowance does not match the current allowance
- **THEN** `TransferError::AllowanceChanged { current_allowance }` is returned

#### Scenario: Self-approval via transaction
- **WHEN** a transaction attempts self-approval
- **THEN** `TransferError::SelfApproval` is returned

#### Scenario: Fee on burn or mint
- **WHEN** a transaction attempts to charge a fee on a burn or mint
- **THEN** `TransferError::BadFee { expected_fee: zero }` is returned

#### Scenario: Fee collector block index initialization
- **WHEN** a transaction is successfully applied
- **AND** a fee collector is configured but has no `block_index` yet
- **THEN** the fee collector's `block_index` is set to the height of the new block

#### Scenario: Old transaction purging
- **WHEN** `purge_old_transactions(ledger, now)` is called
- **THEN** transactions older than `now - transaction_window - PERMITTED_DRIFT` are removed from both `transactions_by_hash` and `transactions_by_height`
- **AND** at most `max_transactions_to_purge` transactions are removed per call
- **AND** `on_purged_transaction` is called for each purged transaction with its block height

#### Scenario: Approval pruning during transaction application
- **WHEN** `apply_transaction` is called
- **THEN** up to `APPROVE_PRUNE_LIMIT` (100) expired approvals are pruned before processing the transaction

---

### Requirement: Block Archiving (`ic-ledger-canister-core` -- `archive` module)

The archiving system moves older blocks from the ledger canister to separate archive canisters to prevent the ledger from running out of memory. This involves threshold-based triggering, archive node creation, chunked block transfer, and block range tracking.

#### Scenario: Archive configuration defaults
- **WHEN** an `Archive` is created from `ArchiveOptions`
- **THEN** `node_max_memory_size_bytes` defaults to 1 GiB if not specified
- **AND** `max_message_size_bytes` defaults to 2 MiB if not specified
- **AND** `cycles_for_archive_creation` defaults to `DEFAULT_CYCLES_FOR_ARCHIVE_CREATION` (10 trillion) if not specified

#### Scenario: Archiving trigger threshold
- **WHEN** the number of unarchived blocks exceeds `trigger_threshold`
- **THEN** up to `num_blocks_to_archive` blocks (capped by `MAX_BLOCKS_TO_ARCHIVE` = 18,000) are selected for archiving

#### Scenario: Archiving is skipped below threshold
- **WHEN** the number of unarchived blocks is below `trigger_threshold`
- **THEN** no blocks are selected for archiving and the process returns immediately

#### Scenario: Archive canister creation
- **WHEN** no archive node exists or the last archive node is full (remaining capacity less than the first block's size)
- **THEN** a new archive canister is created via the IC management canister with the configured cycles
- **AND** the archive Wasm is installed on the new canister
- **AND** the controller is set to the configured controller principals (including `more_controller_ids` if provided)
- **AND** the new node is added to the archive's `nodes` list

#### Scenario: Reusing existing archive node
- **WHEN** the last archive node has sufficient remaining capacity
- **THEN** blocks are appended to the existing node without creating a new one

#### Scenario: Chunked block transfer respects message size limits
- **WHEN** blocks are sent to an archive node
- **THEN** they are chunked to respect the minimum of `archive.max_message_size_bytes` and the `max_ledger_msg_size_bytes` parameter
- **AND** each chunk is sent via `append_blocks` inter-canister call
- **AND** block index ranges in `nodes_block_ranges` are updated after each successful chunk

#### Scenario: Archive mutual exclusion via ArchivingGuard
- **WHEN** an archiving operation is already in progress (the `archiving_in_progress` flag is true)
- **THEN** a concurrent archiving attempt returns immediately with `ArchivingGuardError::AlreadyArchiving`
- **AND** when the guard is dropped, `archiving_in_progress` is reset to false

#### Scenario: Archiving guard requires archive existence
- **WHEN** an `ArchivingGuard` is created but no archive is configured
- **THEN** `ArchivingGuardError::NoArchive` is returned

#### Scenario: Partial archiving failure
- **WHEN** sending blocks to an archive fails after some blocks were successfully sent
- **THEN** only the successfully archived blocks are removed from the ledger
- **AND** the archiving failure metric is incremented
- **AND** the remaining blocks stay in the ledger for a future archiving attempt

#### Scenario: Archive creation cycle checks on application subnets
- **WHEN** archive creation is attempted on an application subnet (non-zero canister creation cost)
- **THEN** the system verifies that `cycles_for_archive_creation` is at least the minimum of `MIN_CYCLES_FOR_ARCHIVE_CREATION` (4.5 trillion) or 3x the canister creation cost
- **AND** the system verifies the ledger retains at least `MIN_LEDGER_LIQUID_CYCLES_AFTER_ARCHIVE_CREATION` (10 trillion) liquid cycles after creation
- **AND** an error is returned if either check fails

#### Scenario: Archive creation on system subnets
- **WHEN** archive creation is attempted on a system subnet (zero canister creation cost)
- **AND** `cycles_for_archive_creation` exceeds the ledger's liquid cycle balance
- **THEN** an error is returned suggesting setting `cycles_for_archive_creation` to 0

#### Scenario: Block location lookup via binary search
- **WHEN** `find_block_in_archive(ledger, block_height)` is called
- **THEN** a binary search over archive node block ranges locates the correct archive canister
- **AND** the `CanisterId` of that archive is returned, or `None` if the height is not in any archive

#### Scenario: Block locations across ledger and archives
- **WHEN** `block_locations(ledger, start, length)` is called
- **THEN** it returns `BlockLocations` with `local_blocks` (range of blocks in the ledger) and `archived_blocks` (list of `(CanisterId, Range<u64>)`)
- **AND** local and archived block ranges do not overlap (debug-asserted)
- **AND** archived blocks are returned in order from oldest to newest archive

#### Scenario: Archive index listing
- **WHEN** `Archive::index()` is called
- **THEN** it returns a vector of `((from, to), CanisterId)` tuples
- **AND** ranges are inclusive (`from` and `to` are both valid block indices)
- **AND** `Archive::nodes()` returns the list of archive canister IDs

---

### Requirement: Runtime Abstraction (`ic-ledger-canister-core` -- `runtime` module)

The `Runtime` trait abstracts canister runtime operations to allow the ledger logic to be tested and reused across different execution environments.

#### Scenario: Runtime trait interface
- **WHEN** a type implements `Runtime`
- **THEN** it provides `id()` returning the canister's `CanisterId`
- **AND** `print(msg)` for debug output
- **AND** `call(id, method, cycles, args)` for inter-canister calls with arbitrary Candid-encoded arguments and return types

#### Scenario: CdkRuntime implementation
- **WHEN** `CdkRuntime` is used as the runtime
- **THEN** `id()` returns the canister's own principal via `ic_cdk::api::id()`
- **AND** `call()` delegates to `ic_cdk::api::call::call_with_payment`
- **AND** `print()` delegates to `ic_cdk::api::print`

---

### Requirement: ICP Archive Canister (`ic-icp-archive`)

The ICP archive canister stores encoded blocks for the ICP ledger in stable memory. It provides an upgrade argument to adjust memory size.

#### Scenario: Archive upgrade argument
- **WHEN** the ICP archive canister is upgraded with an `ArchiveUpgradeArgument`
- **THEN** the `max_memory_size_bytes` can be optionally updated

---

### Requirement: ICRC-1 Archive Canister (`ic-icrc1-archive`)

The ICRC-1 archive canister stores ICRC-1 encoded blocks in a stable memory log structure. It is initialized by the ledger canister and accepts blocks only from its creating ledger.

#### Scenario: Archive initialization
- **WHEN** the archive canister's `init` function is called with `(ledger_id, block_index_offset, max_memory_size_bytes, max_transactions_per_response)`
- **THEN** `max_memory_size_bytes` defaults to `DEFAULT_MEMORY_LIMIT` (3 GiB) and is capped at that value
- **AND** `max_transactions_per_response` defaults to 2,000
- **AND** the `token_type` is recorded from the wasm binary (U64 or U256)
- **AND** stable memory is partitioned: pages 0..1 for config, pages 1..`NUM_WASM_PAGES` (4 GiB / 64 KiB) for blocks

#### Scenario: Appending blocks with caller verification
- **WHEN** `append_blocks(blocks)` is called
- **THEN** the caller must be the `ledger_id` configured at initialization
- **AND** if the caller is not the ledger, the call traps with "only {ledger_id} can append blocks to this archive"
- **AND** blocks are appended to the stable log if sufficient capacity exists

#### Scenario: Appending blocks exceeding capacity
- **WHEN** `append_blocks` is called and the new blocks would exceed `max_memory_size_bytes`
- **THEN** the call traps with "no space left"

#### Scenario: Remaining capacity query
- **WHEN** `remaining_capacity()` is called
- **THEN** it returns `max_memory_size_bytes - current_log_size_bytes`

#### Scenario: Get transaction by index
- **WHEN** `get_transaction(index)` is called with an index within the archive's range
- **THEN** the block at `index - block_index_offset` is decoded and returned as a `Transaction`
- **AND** if the index is below `block_index_offset`, `None` is returned

#### Scenario: Get transactions range
- **WHEN** `get_transactions(request)` is called
- **THEN** blocks are decoded and returned, capped at `max_transactions_per_response`

#### Scenario: Get blocks range (generic ICRC-1 format)
- **WHEN** `get_blocks(request)` is called
- **THEN** encoded blocks are decoded to generic block format using `encoded_block_to_generic_block` and returned as a `BlockRange`

#### Scenario: ICRC-3 get_blocks with multiple ranges
- **WHEN** `icrc3_get_blocks(requests)` is called with multiple range requests
- **THEN** blocks across all ranges are returned with their global block IDs
- **AND** a global maximum of 100 blocks per response (`MAX_BLOCKS_PER_RESPONSE`) is enforced
- **AND** `log_length` in the response reflects the local log length (not global chain length)

#### Scenario: ICRC-3 supported block types
- **WHEN** `icrc3_supported_block_types()` is called
- **THEN** it returns `1burn`, `1mint`, `1xfer`, `2approve`, `2xfer`, and the ICRC-107 (`107:fee_col`) block type
- **AND** each type includes a URL to the relevant standard

#### Scenario: ICRC-3 get_archives from archive returns empty
- **WHEN** `icrc3_get_archives` is called on the archive canister
- **THEN** it returns an empty list (archives do not know about other archives)

#### Scenario: ICRC-3 tip certificate from archive returns None
- **WHEN** `icrc3_get_tip_certificate` is called on the archive canister
- **THEN** `None` is returned (only the ledger certifies the tip)

#### Scenario: Token type verification on upgrade
- **WHEN** the archive canister is upgraded
- **THEN** the stored `token_type` is verified against the Wasm's `token_type` (U64 or U256)
- **AND** if they differ, the upgrade panics with "Incompatible token type"
- **AND** if the stored `token_type` is `UNDEFINED` (pre-existing archive), it is set to the Wasm's type

#### Scenario: Post-upgrade memory size validation
- **WHEN** the archive canister completes `post_upgrade`
- **THEN** the current log size is verified to not exceed `max_memory_size_bytes`

#### Scenario: Metrics endpoint
- **WHEN** an HTTP request to `/metrics` is received
- **THEN** Prometheus-format metrics are returned including `archive_stable_memory_pages`, `stable_memory_bytes`, `heap_memory_bytes`, `archive_cycle_balance`, and `archive_stored_blocks`
- **AND** requests to other paths return 404

---

### Requirement: ICRC-1 Ledger Canister (`ic-icrc1-ledger`)

The ICRC-1 ledger canister is the primary ledger implementation supporting ICRC-1 (fungible token), ICRC-2 (approve/transfer_from), ICRC-3 (block log), ICRC-21 (consent messages), ICRC-103 (allowance listing), and ICRC-106 (tracked accounts). It stores balances, allowances, and blocks in stable structures.

#### Scenario: Ledger initialization from InitArgs
- **WHEN** the ledger is initialized with `LedgerArgument::Init(init_args)`
- **THEN** `minting_account`, `fee_collector_account`, `transfer_fee`, `token_name`, `token_symbol`, `decimals`, `metadata`, `archive_options`, `max_memo_length`, `feature_flags`, and `index_principal` are configured
- **AND** `initial_balances` are credited to the specified accounts
- **AND** the certified data root hash is set

#### Scenario: Ledger rejects Init argument on upgrade
- **WHEN** `post_upgrade` receives `LedgerArgument::Init(_)`
- **THEN** the canister panics

#### Scenario: Ledger rejects Upgrade argument on init
- **WHEN** `init` receives `LedgerArgument::Upgrade(_)`
- **THEN** the canister panics

#### Scenario: Ledger versioning
- **WHEN** the ledger state is serialized
- **THEN** it includes a `ledger_version` field (currently version 3)
- **AND** version 0 = heap state, version 1 = stable allowances, version 2 = stable balances, version 3 = stable blocks
- **AND** upgrading from scratch stable memory (no memory manager magic bytes) is rejected with an explicit error message pointing to required intermediate upgrades

#### Scenario: Token type safety on upgrade
- **WHEN** the ledger is upgraded
- **AND** the stored `token_type` does not match the wasm's `token_type`
- **THEN** the upgrade panics
- **AND** the first balance is read to verify encoding compatibility

#### Scenario: Transfer (ICRC-1)
- **WHEN** a transfer is submitted via the `icrc1_transfer` endpoint
- **THEN** the transfer is validated (fee, memo length, deduplication, balance)
- **AND** if the sender is the minting account, a mint transaction is created
- **AND** if the recipient is the minting account, a burn transaction is created
- **AND** otherwise, a regular transfer transaction is created with fee deduction
- **AND** a block is appended and the block index is returned as `Nat`
- **AND** certified data is updated and archiving is triggered

#### Scenario: Transfer fee validation
- **WHEN** a transfer specifies a `fee` that does not match the ledger's `transfer_fee`
- **THEN** `TransferError::BadFee` is returned with the expected fee

#### Scenario: Memo length validation
- **WHEN** a transfer includes a memo exceeding `max_memo_length` (default 32 bytes)
- **THEN** the transfer is rejected with a generic error

#### Scenario: Burn amount minimum check
- **WHEN** a burn (transfer to minting account) is submitted with an amount less than the `transfer_fee`
- **THEN** `TransferError::BadBurn` is returned with the minimum burn amount

#### Scenario: Approve (ICRC-2)
- **WHEN** an approval is submitted via the `icrc2_approve` endpoint
- **THEN** the spender's allowance for the caller's account is set to the specified amount
- **AND** a `2approve` block is appended to the blockchain
- **AND** the approval fee is deducted from the caller's account

#### Scenario: ICRC-2 feature flag
- **WHEN** `feature_flags.icrc2` is `false`
- **THEN** ICRC-2 endpoints are disabled or return appropriate errors

#### Scenario: Transfer from (ICRC-2)
- **WHEN** `icrc2_transfer_from` is called by a spender
- **THEN** the allowance is checked and reduced by the transfer amount plus fee
- **AND** the transfer is executed from the specified account to the recipient
- **AND** a `2xfer` block is appended to the blockchain

#### Scenario: Allowance query (ICRC-2)
- **WHEN** `icrc2_allowance(AllowanceArgs)` is called
- **THEN** the current allowance for the (account, spender) pair is returned
- **AND** expired allowances return zero

#### Scenario: ICRC-3 block log queries
- **WHEN** `icrc3_get_blocks(requests)` is called
- **THEN** blocks matching the requested ranges are returned from both local storage and archive references
- **AND** archived ranges include callback functions pointing to the correct archive canisters

#### Scenario: ICRC-3 tip certificate
- **WHEN** `icrc3_get_tip_certificate()` is called
- **THEN** a data certificate is returned proving the hash of the last block in the chain

#### Scenario: ICRC-3 archives listing
- **WHEN** `icrc3_get_archives(args)` is called
- **THEN** the list of archive canisters with their block ranges is returned

#### Scenario: Metadata query
- **WHEN** `icrc1_metadata()` is called
- **THEN** standard metadata entries are returned: `icrc1:name`, `icrc1:symbol`, `icrc1:decimals`, `icrc1:fee`
- **AND** any custom metadata entries from `InitArgs.metadata` are included

#### Scenario: Supported standards
- **WHEN** `icrc1_supported_standards()` is called
- **THEN** it returns at minimum `ICRC-1` and `ICRC-3`
- **AND** if `feature_flags.icrc2` is true, `ICRC-2` is also included

#### Scenario: Pre-upgrade and post-upgrade state persistence
- **WHEN** the ledger canister is upgraded
- **THEN** the ledger state is serialized to stable memory in `pre_upgrade` using CBOR via the `UPGRADES_MEMORY` with an 8 MiB buffer
- **AND** deserialized in `post_upgrade`
- **AND** the certified data root hash is re-set after upgrade

#### Scenario: U256 token support via feature flag
- **WHEN** the ledger is compiled with the `u256-tokens` feature
- **THEN** the `Tokens` type alias resolves to `ic_icrc1_tokens_u256::U256` instead of `ic_icrc1_tokens_u64::U64`
- **AND** all arithmetic, serialization, and storage use 256-bit token amounts

#### Scenario: Stable structures memory layout
- **WHEN** the ledger is operating
- **THEN** it uses five distinct stable memory regions managed by `MemoryManager`:
  - MemoryId 0: upgrades (state serialization)
  - MemoryId 1: allowances `StableBTreeMap<AccountSpender, StorableAllowance>`
  - MemoryId 2: allowance expirations `StableBTreeMap<Expiration, ()>`
  - MemoryId 3: balances `StableBTreeMap<Account, Tokens>`
  - MemoryId 4: blocks `StableBTreeMap<u64, Vec<u8>>`

#### Scenario: ICRC-103 list allowances
- **WHEN** `icrc103_get_allowances(args)` is called
- **THEN** up to `MAX_TAKE_ALLOWANCES` (500) allowances are returned
- **AND** each allowance includes the spender, amount, and optional expiration

#### Scenario: Archiving is triggered after transaction processing
- **WHEN** a transaction is applied and the block count exceeds the archive trigger threshold
- **THEN** blocks are asynchronously archived to archive canisters
- **AND** the maximum message size for archiving calls is `MAX_MESSAGE_SIZE` (1 MiB)

#### Scenario: Configuration constants
- **WHEN** the ICRC-1 ledger is deployed
- **THEN** `TRANSACTION_WINDOW` is 24 hours
- **AND** `MAX_TRANSACTIONS_PER_REQUEST` is 2,000
- **AND** `MAX_TRANSACTIONS_IN_WINDOW` is 3,000,000
- **AND** `MAX_TRANSACTIONS_TO_PURGE` is 100,000
- **AND** `DEFAULT_MAX_MEMO_LENGTH` is 32 bytes

#### Scenario: Upgrade argument applies configuration changes
- **WHEN** `UpgradeArgs` is provided during upgrade
- **THEN** optional fields `metadata`, `token_name`, `token_symbol`, `transfer_fee`, `change_fee_collector`, `max_memo_length`, `feature_flags`, `change_archive_options`, and `index_principal` can be updated
- **AND** `ChangeArchiveOptions` can modify trigger_threshold, num_blocks_to_archive, node_max_memory_size_bytes, max_message_size_bytes, controller_id, cycles_for_archive_creation, and max_transactions_per_response

#### Scenario: ICRC-21 consent messages
- **WHEN** `icrc21_canister_call_consent_message` is called for an ICRC-1 or ICRC-2 endpoint
- **THEN** a human-readable consent message is returned describing the proposed action

---

### Requirement: ICP Index Canister (`ic-icp-index`)

The ICP index canister periodically syncs blocks from the ICP ledger and builds per-account indexes to support efficient balance and transaction history queries. It uses `AccountIdentifier` (the ICP-specific account format).

#### Scenario: Initialization with ledger ID
- **WHEN** the index canister is initialized with `InitArg { ledger_id, retrieve_blocks_from_ledger_interval_seconds }`
- **THEN** it begins periodically fetching blocks from the specified ledger canister

#### Scenario: Upgrade with optional ledger ID change
- **WHEN** the index canister is upgraded with `UpgradeArg`
- **THEN** the `ledger_id` and `retrieve_blocks_from_ledger_interval_seconds` can be optionally updated

#### Scenario: Account transaction history query
- **WHEN** `get_account_identifier_transactions(args)` is called with an `AccountIdentifier`
- **THEN** up to `max_results` transactions involving that account are returned
- **AND** the response includes the account's current `balance` (as u64), `transactions` list, and `oldest_tx_id`

#### Scenario: Pagination via start parameter
- **WHEN** `get_account_identifier_transactions` is called with `start` set to a block index
- **THEN** results begin from the next most recent transaction after `start` (exclusive)

#### Scenario: SettledTransaction format
- **WHEN** transactions are returned from the ICP index
- **THEN** each `SettledTransaction` includes `operation` (Transfer, Mint, Burn, Approve), `memo`, optional `created_at_time`, optional `icrc1_memo`, and `timestamp`

#### Scenario: Sync status query
- **WHEN** `status()` is called
- **THEN** it returns the `num_blocks_synced` indicating how many blocks have been indexed

---

### Requirement: ICRC-1 Index-ng Canister (`ic-icrc1-index-ng`)

The new-generation ICRC-1 index canister syncs blocks from an ICRC-1 ledger (using either `get_blocks` or `icrc3_get_blocks`) and indexes them per-account. It uses the ICRC-1 `Account` format.

#### Scenario: Initialization
- **WHEN** the index-ng canister is initialized with `InitArg { ledger_id, retrieve_blocks_from_ledger_interval_seconds }`
- **THEN** it begins periodic block retrieval from the specified ledger

#### Scenario: Account transactions query
- **WHEN** `get_account_transactions(args)` is called with an `Account`
- **THEN** transactions involving the account are returned with their block IDs
- **AND** the response includes the account's current `balance` (as `Nat`) and `oldest_tx_id`

#### Scenario: Maximum blocks per response
- **WHEN** `get_blocks(request)` is called on the index-ng canister
- **THEN** up to `DEFAULT_MAX_BLOCKS_PER_RESPONSE` (2000) blocks are returned

#### Scenario: List subaccounts
- **WHEN** `list_subaccounts(ListSubaccountsArgs { owner, start })` is called
- **THEN** subaccounts associated with the given owner principal are returned in natural order
- **AND** if `start` is provided, results begin after that subaccount (exclusive)

#### Scenario: Fee collector ranges
- **WHEN** `fee_collector_ranges()` is called
- **THEN** it returns the fee collector account(s) with the block ranges where they were active as `Vec<(Account, Vec<(BlockIndex, BlockIndex)>)>`

#### Scenario: GetBlocksMethod selection
- **WHEN** the index-ng canister communicates with the ledger
- **THEN** it can use either `GetBlocks` (pre-ICRC-3 legacy endpoint) or `ICRC3GetBlocks` depending on the ledger's supported standards

#### Scenario: Sync status
- **WHEN** `status()` is called
- **THEN** it returns the `num_blocks_synced`

#### Scenario: U256 token support
- **WHEN** the index-ng canister is compiled with the `u256-tokens` feature
- **THEN** it uses `U256` token amounts matching the ledger's token type

#### Scenario: ICRC-3 can be disabled via feature flag
- **WHEN** the index-ng canister is compiled with the `icrc3_disabled` feature
- **THEN** ICRC-3 endpoints are not exposed

#### Scenario: Get blocks can be disabled via feature flag
- **WHEN** the index-ng canister is compiled with the `get_blocks_disabled` feature
- **THEN** the `get_blocks` endpoint is not exposed

#### Scenario: Adaptive timer backoff on blocks found
- **WHEN** the index builds and receives blocks from the ledger (i.e., `num_indexed > 0`)
- **THEN** the polling wait time is halved (`last_wait_time / 2`)
- **AND** the result is clamped to the configured minimum (`min_retrieve_blocks_from_ledger_interval`)
- **AND** the next `build_index` timer is scheduled with the new wait time

#### Scenario: Adaptive timer backoff on no blocks found
- **WHEN** the index builds and receives zero blocks from the ledger (i.e., `num_indexed == 0`)
- **THEN** the polling wait time is doubled (`last_wait_time * 2`, using saturating multiplication)
- **AND** the result is clamped to the configured maximum (`max_retrieve_blocks_from_ledger_interval`)
- **AND** the next `build_index` timer is scheduled with the new wait time

#### Scenario: Default adaptive timer bounds
- **GIVEN** no explicit timer interval configuration is provided at init or upgrade
- **THEN** the minimum retrieve interval defaults to 1 second (`MIN_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL = 1s`)
- **AND** the maximum retrieve interval defaults to 10 seconds (`MAX_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL = 10s`)
- **AND** `last_wait_time` is initialized to the effective minimum interval

#### Scenario: Timer configuration with new min/max parameters
- **WHEN** the index-ng canister is initialized or upgraded with `min_retrieve_blocks_from_ledger_interval_seconds` and/or `max_retrieve_blocks_from_ledger_interval_seconds`
- **THEN** those values override the defaults for the adaptive timer bounds
- **AND** the effective minimum must be at least 1 second (traps otherwise)
- **AND** the effective minimum must not exceed the effective maximum (traps otherwise)

#### Scenario: Timer configuration with deprecated legacy parameter
- **WHEN** the index-ng canister is initialized or upgraded with `retrieve_blocks_from_ledger_interval_seconds` set (and neither `min_retrieve_blocks_from_ledger_interval_seconds` nor `max_retrieve_blocks_from_ledger_interval_seconds` is set)
- **THEN** both the minimum and maximum intervals are set to the value of the deprecated parameter (disabling adaptive backoff; fixed interval)
- **AND** the same validation rules apply (minimum >= 1 second, min <= max)

#### Scenario: Timer configuration rejects mixing legacy and new parameters
- **WHEN** the index-ng canister is initialized or upgraded with `retrieve_blocks_from_ledger_interval_seconds` set **and** either `min_retrieve_blocks_from_ledger_interval_seconds` or `max_retrieve_blocks_from_ledger_interval_seconds` is also set
- **THEN** the canister traps with an error indicating the legacy field cannot be combined with the new fields

#### Scenario: Timer state is clamped on upgrade
- **WHEN** the index-ng canister is upgraded and the persisted `last_wait_time` falls outside the new `[min, max]` interval range
- **THEN** the `last_wait_time` is clamped to fit within the new bounds before the next timer is scheduled

#### Scenario: ICRC-107 fee collector tracking via FeeCollector blocks
- **WHEN** the index processes a block whose operation is `Operation::FeeCollector { fee_collector, .. }`
- **THEN** it stores the fee collector account in `state.fee_collector_107` (as `Some(fee_collector)`)
- **AND** subsequent blocks that credit fees use this `fee_collector_107` value as the fee recipient
- **AND** `fee_collector_107` takes precedence over the legacy per-block `fee_collector` / `fee_collector_block_index` fields when determining where to credit fees

#### Scenario: Fee collector resolution priority
- **WHEN** `get_fee_collector()` is called to determine the current fee collector
- **THEN** if `fee_collector_107` has been set (via an ICRC-107 FeeCollector block), its value is used (which may be `Some(account)` or `None` to indicate no fee collector)
- **AND** if `fee_collector_107` has never been set, the legacy method is used: reading the `fee_collector` field from the last indexed block, or following its `fee_collector_block_index` pointer

#### Scenario: GetBlocksMethod detection via ICRC-3 standard support
- **WHEN** the index-ng canister needs to fetch blocks from the ledger and has not yet determined the method
- **THEN** it calls `icrc1_supported_standards` on the ledger canister
- **AND** if the ledger declares support for "ICRC-3", the index uses `ICRC3GetBlocks` (calling `icrc3_get_blocks`)
- **AND** if the ledger does not declare "ICRC-3" support (or the call fails), the index falls back to `GetBlocks` (calling `get_blocks`)

#### Scenario: GetBlocksMethod is cached
- **WHEN** the `GetBlocksMethod` has been determined for a ledger
- **THEN** it is cached in the canister's thread-local state and reused for subsequent `build_index` calls without re-querying the ledger's supported standards

#### Scenario: Non-retriable sync error stops the timer
- **WHEN** a `build_index` cycle encounters a non-retriable error (e.g., block decoding failure)
- **THEN** the indexing timer is stopped and no further `build_index` calls are scheduled
- **AND** the error is logged

#### Scenario: Retriable sync error preserves the timer
- **WHEN** a `build_index` cycle encounters a retriable error (e.g., network failure fetching blocks)
- **THEN** the next `build_index` is scheduled using the current `last_wait_time` (without adjusting it)
- **AND** the error is logged

---

### Requirement: Ledger Suite Orchestrator (`ledger-suite-orchestrator`)

The ledger suite orchestrator (located in `rs/ethereum/ledger-suite-orchestrator/`) manages the lifecycle of ledger suites for Ethereum-bridged tokens. It handles canister creation, installation, upgrades, and monitoring of ICRC-1 ledger, archive, and index canisters.

#### Scenario: Orchestrator manages ledger suite lifecycle
- **WHEN** a new Ethereum-bridged token is registered
- **THEN** the orchestrator creates and initializes a new ICRC-1 ledger, archive, and index-ng canister suite

#### Scenario: Orchestrator performs canister upgrades
- **WHEN** a new Wasm version is available for ledger suite canisters
- **THEN** the orchestrator schedules and performs upgrades for managed canisters

#### Scenario: Orchestrator state management
- **WHEN** the orchestrator stores its state
- **THEN** it uses stable structures to persist the mapping between tokens and their canister suites

#### Scenario: Orchestrator concurrency guard
- **WHEN** an orchestrator operation is in progress
- **THEN** concurrent operations are prevented by a guard mechanism

---

### Requirement: Ledger Suite Integration Tests (`ic-ledger-suite-state-machine-tests`)

The integration test crate validates end-to-end behavior of the ledger suite using state machine tests. It covers transfers, approvals, archiving, metadata, fee collection, metrics, and ICRC standard compliance.

#### Scenario: End-to-end transfer and balance verification
- **WHEN** a transfer is made via the ICRC-1 transfer endpoint in a state machine test
- **THEN** the sender's balance decreases by `amount + fee`
- **AND** the recipient's balance increases by `amount`
- **AND** the total supply remains consistent

#### Scenario: Archiving integration
- **WHEN** enough blocks accumulate to exceed the archive trigger threshold (configurable via `ARCHIVE_TRIGGER_THRESHOLD`)
- **THEN** blocks are archived to archive canisters
- **AND** the archived blocks are queryable from the archive canisters
- **AND** the ledger's local block count decreases

#### Scenario: Approval and transfer_from integration
- **WHEN** an account approves a spender and the spender calls `transfer_from`
- **THEN** the allowance is consumed and the transfer is executed
- **AND** the approval and transfer blocks are recorded in the blockchain

#### Scenario: In-memory ledger state verification
- **WHEN** `verify_ledger_state` is called during integration tests
- **THEN** the in-memory reference ledger state matches the on-canister state
- **AND** balances, allowances, and block hashes are consistent

#### Scenario: Fee collector integration
- **WHEN** a fee collector account is configured
- **THEN** transfer fees are credited to the fee collector instead of the token pool
- **AND** the fee collector's balance reflects the accumulated fees

#### Scenario: ICRC-3 block format verification
- **WHEN** blocks are queried via ICRC-3 endpoints in integration tests
- **THEN** block types include `1burn`, `1mint`, `1xfer`, `2approve`, and `2xfer`
- **AND** the generic block format is consistent between the ledger and archive

#### Scenario: ICRC-21 consent message integration
- **WHEN** `icrc21_canister_call_consent_message` is called for an ICRC-1 or ICRC-2 endpoint in tests
- **THEN** a human-readable consent message is returned describing the proposed action

#### Scenario: Metrics verification
- **WHEN** the `/metrics` HTTP endpoint is queried in state machine tests
- **THEN** Prometheus-format metrics are returned including ledger-specific counters and gauges

#### Scenario: ICRC-106 tracked accounts
- **WHEN** ICRC-106 endpoints are tested
- **THEN** the ledger returns the number of tracked accounts and allows listing them

#### Scenario: ICRC-107 fee collector block type
- **WHEN** a fee collector change occurs
- **THEN** a `107:fee_col` block type is recorded
- **AND** this block type is included in `icrc3_supported_block_types`

#### Scenario: Metadata keys validation
- **WHEN** custom metadata is set during initialization or upgrade
- **THEN** metadata keys are validated against the `MetadataKey` format
- **AND** standard metadata entries (`icrc1:name`, `icrc1:symbol`, `icrc1:decimals`, `icrc1:fee`) cannot be overridden by custom metadata

#### Scenario: Property-based testing with valid_transactions_strategy
- **WHEN** property-based tests run using `proptest`
- **THEN** randomly generated valid transactions are applied to the ledger
- **AND** the in-memory ledger state is verified to match the canister state after each operation
