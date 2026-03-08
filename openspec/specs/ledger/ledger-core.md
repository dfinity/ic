# Ledger Core

**Crates**: `ic-ledger-core`, `ic-ledger-suite-in-memory-ledger`, `ic-ledger-suite-state-machine-helpers`

The ledger core library provides the shared abstractions used by both the ICP and ICRC-1 ledger implementations. It defines the balance management, allowance (approval) system, token types, block types, and the generic ledger canister framework.

## Requirements

### Requirement: Balance Management

The `Balances` struct tracks all account balances and the unallocated token pool.

#### Scenario: Initial state
- **WHEN** a new `Balances` is created
- **THEN** the token pool is set to `Tokens::MAX`
- **AND** no accounts have balances
- **AND** total supply is zero

#### Scenario: Credit an account
- **WHEN** tokens are credited to an account
- **THEN** the account balance increases by the credited amount
- **AND** if the account did not previously exist, it is created

#### Scenario: Debit an account
- **WHEN** tokens are debited from an account
- **AND** the account has sufficient balance
- **THEN** the account balance decreases by the debited amount

#### Scenario: Debit with insufficient funds
- **WHEN** tokens are debited from an account
- **AND** the account balance is less than the debit amount
- **THEN** an `InsufficientFunds { balance }` error is returned

#### Scenario: Debit from non-existent account
- **WHEN** tokens are debited from an account that does not exist
- **THEN** an `InsufficientFunds { balance: zero }` error is returned

#### Scenario: Zero balance removal
- **WHEN** a debit reduces an account balance to exactly zero
- **THEN** the account is removed from the balance store
- **AND** subsequent balance queries return zero

#### Scenario: Transfer between accounts
- **WHEN** `transfer(from, to, amount, fee, fee_collector)` is called
- **THEN** `from` is debited by `amount + fee`
- **AND** `to` is credited by `amount`
- **AND** if `fee_collector` is None, `fee` is added to the token pool
- **AND** if `fee_collector` is Some, `fee` is credited to the fee collector

#### Scenario: Transfer overflow protection
- **WHEN** `amount + fee` would overflow
- **THEN** the transfer fails with `InsufficientFunds` (since no account can hold more than max)

#### Scenario: Mint tokens
- **WHEN** `mint(to, amount)` is called
- **THEN** the token pool decreases by `amount`
- **AND** `to` is credited by `amount`

#### Scenario: Burn tokens
- **WHEN** `burn(from, amount)` is called
- **AND** `from` has sufficient balance
- **THEN** `from` is debited by `amount`
- **AND** the token pool increases by `amount`

#### Scenario: Total supply
- **WHEN** `total_supply()` is called
- **THEN** it returns `Tokens::MAX - token_pool`

### Requirement: BalancesStore Trait

The `BalancesStore` trait abstracts the storage backend for balances, allowing both heap and stable structure implementations.

#### Scenario: BTreeMap implementation
- **WHEN** `BTreeMap<AccountId, Tokens>` is used as the store
- **THEN** `get_balance` returns the value from the map
- **AND** `update` modifies entries, removing them if the new value is zero

#### Scenario: Stable structure implementation
- **WHEN** a stable BTreeMap is used as the store
- **THEN** balances survive canister upgrades
- **AND** the interface behaves identically to the heap implementation

### Requirement: Allowance Table

The `AllowanceTable` manages ICRC-2 style approvals with expiration support.

#### Scenario: Set allowance
- **WHEN** `approve(account, spender, amount, expires_at, now, expected_allowance)` is called
- **AND** the approval is valid
- **THEN** the allowance for (account, spender) is set to `amount`
- **AND** if `expires_at` is specified, it is stored in the expiration queue

#### Scenario: Query allowance
- **WHEN** `allowance(account, spender, now)` is called
- **AND** an active (non-expired) allowance exists
- **THEN** the current allowance amount and expiration are returned

#### Scenario: Query expired allowance
- **WHEN** `allowance(account, spender, now)` is called
- **AND** the allowance has expired (expires_at <= now)
- **THEN** a default allowance (amount = 0) is returned

#### Scenario: Use allowance
- **WHEN** `use_allowance(account, spender, amount, now)` is called
- **AND** the current allowance >= amount
- **THEN** the allowance is reduced by `amount`
- **AND** the remaining allowance is returned

#### Scenario: Use entire allowance
- **WHEN** `use_allowance` reduces the allowance to zero
- **THEN** the allowance entry is removed
- **AND** any associated expiration is removed

#### Scenario: Use allowance with insufficient amount
- **WHEN** `use_allowance` is called with amount > current allowance
- **THEN** `InsufficientAllowance` error is returned with the current allowance

#### Scenario: Use expired allowance
- **WHEN** `use_allowance` is called on an expired allowance
- **THEN** `InsufficientAllowance(0)` is returned

#### Scenario: Self-approval rejected
- **WHEN** `approve` is called where account == spender
- **THEN** `ApproveError::SelfApproval` is returned

#### Scenario: Expired approval rejected
- **WHEN** `approve` is called with `expires_at <= now`
- **THEN** `ApproveError::ExpiredApproval { now }` is returned

#### Scenario: Expected allowance mismatch
- **WHEN** `approve` is called with `expected_allowance` that differs from the current value
- **THEN** `ApproveError::AllowanceChanged { current_allowance }` is returned

#### Scenario: Approve zero on non-existent allowance
- **WHEN** `approve` is called with amount = 0 for a non-existent allowance
- **THEN** the operation succeeds (no-op)
- **AND** no entry is created

#### Scenario: Prune expired allowances
- **WHEN** `prune(now, limit)` is called
- **THEN** up to `limit` expired allowances (expires_at <= now) are removed
- **AND** both the allowance and expiration entries are cleaned up
- **AND** the number of pruned allowances is returned

#### Scenario: Expiration queue ordering
- **WHEN** allowances with different expirations exist
- **THEN** pruning processes them in chronological order (earliest first)

### Requirement: AllowancesData Trait

The `AllowancesData` trait abstracts the allowance storage backend.

#### Scenario: Heap allowances data
- **WHEN** `HeapAllowancesData` is used
- **THEN** allowances are stored in a `BTreeMap<(AccountId, AccountId), Allowance>`
- **AND** expirations are stored in a `BTreeSet<(TimeStamp, (AccountId, AccountId))>`

#### Scenario: Stable allowances data
- **WHEN** stable structure implementations are used
- **THEN** allowances survive canister upgrades
- **AND** the interface behaves identically to the heap implementation

### Requirement: Token Type System

The `TokensType` trait defines the requirements for token values used in the ledger.

#### Scenario: TokensType requirements
- **WHEN** a type implements `TokensType`
- **THEN** it supports: `Bounded`, `CheckedAdd`, `CheckedSub`, `Zero`, `Clone`, `Debug`, `Into<Nat>`, `TryFrom<Nat>`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Serialize`, `DeserializeOwned`, `Hash`

#### Scenario: Checked arithmetic
- **WHEN** `checked_add` or `checked_sub` would overflow or underflow
- **THEN** `None` is returned instead of wrapping

### Requirement: Block Type System

The `BlockType` trait defines the interface for blocks in the chain.

#### Scenario: Block construction
- **WHEN** a block is constructed via `from_transaction`
- **THEN** it contains the parent hash, transaction, timestamp, effective fee, and fee collector

#### Scenario: Block encoding and decoding
- **WHEN** a block is encoded and then decoded
- **THEN** the decoded block equals the original block
- **AND** `decode(encode(B)) == Ok(B)` for all blocks B

#### Scenario: Block hash
- **WHEN** `block_hash` is called on an encoded block
- **THEN** a deterministic hash of the encoded representation is returned

#### Scenario: Parent hash requirement
- **WHEN** a block is part of a chain
- **THEN** it has a parent hash pointing to the previous block
- **AND** only the genesis block (first block) may have no parent hash

#### Scenario: Timestamp ordering
- **WHEN** blocks are added to the chain
- **THEN** timestamps are monotonically non-decreasing

### Requirement: Transaction Application Framework

The `apply_transaction` function orchestrates the full transaction lifecycle.

#### Scenario: Transaction lifecycle
- **WHEN** `apply_transaction` is called
- **THEN** the following steps occur in order:
  1. Old transactions are purged from the deduplication window
  2. Transaction throttling is checked (if no transactions were purged)
  3. Expired allowances are pruned (up to 100)
  4. If `created_at_time` is set, deduplication is performed
  5. The transaction is applied to the balance/allowance state
  6. A new block is created and appended to the blockchain
  7. The transaction hash is recorded for deduplication

#### Scenario: Transaction purging
- **WHEN** old transactions are purged
- **THEN** up to `max_transactions_to_purge` (ICP: 100,000) are removed per call
- **AND** only transactions older than `now - transaction_window - PERMITTED_DRIFT` are purged

### Requirement: LedgerData Trait

The `LedgerData` trait defines the full interface a ledger implementation must provide.

#### Scenario: Ledger configuration
- **WHEN** a ledger implements `LedgerData`
- **THEN** it provides:
  - `transaction_window()` - deduplication time window
  - `max_transactions_in_window()` - throttling limit
  - `max_transactions_to_purge()` - purge batch size
  - `token_name()` and `token_symbol()` - token identity
  - `blockchain()` - the block chain data structure
  - `transactions_by_hash()` - deduplication index
  - `transactions_by_height()` - time-ordered transaction list

### Requirement: Timestamp

The `TimeStamp` type represents nanoseconds since Unix epoch.

#### Scenario: Timestamp creation
- **WHEN** a `TimeStamp` is created from nanoseconds
- **THEN** it stores the value as `u64` nanoseconds since Unix epoch

#### Scenario: Timestamp arithmetic
- **WHEN** a `Duration` is added to a `TimeStamp`
- **THEN** the result is a new `TimeStamp` advanced by that duration
