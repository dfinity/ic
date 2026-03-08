# ICP Ledger

The ICP Ledger is the canister responsible for managing ICP token balances, transfers, minting, and burning on the Internet Computer. It uses `AccountIdentifier` (a 28-byte hash of principal and subaccount) as the account model, encodes blocks in protobuf, and stores state in stable structures.

## Requirements

### Requirement: Token Representation

ICP tokens are represented internally as `Tokens`, a wrapper around a `u64` value denominated in e8s (10^-8 ICP). One ICP equals 100,000,000 e8s.

#### Scenario: Construct tokens from whole and fractional parts
- **WHEN** a caller constructs `Tokens::new(12, 200)`
- **THEN** the resulting value has 12 whole tokens and 200 e8s
- **AND** `get_e8s()` returns `1_200_000_200`
- **AND** `get_tokens()` returns `12`
- **AND** `get_remainder_e8s()` returns `200`

#### Scenario: Reject fractional part exceeding one token
- **WHEN** a caller constructs `Tokens::new(1, 100_000_000)`
- **THEN** construction fails with an error
- **AND** the fractional e8s part must be less than `TOKEN_SUBDIVIDABLE_BY` (100,000,000)

#### Scenario: Maximum token value
- **WHEN** `Tokens::MAX` is queried
- **THEN** it returns `Tokens { e8s: u64::MAX }`
- **AND** this represents roughly 184 billion ICP

### Requirement: Account Identification

ICP uses `AccountIdentifier`, a 28-byte hash derived from a principal and an optional 32-byte subaccount. This differs from the ICRC-1 `Account` type.

#### Scenario: Derive account identifier from principal
- **WHEN** an `AccountIdentifier` is computed from a `PrincipalId` and a `Subaccount`
- **THEN** the result is a SHA-224 hash of a domain separator, the principal bytes, and the subaccount bytes
- **AND** the first 4 bytes are a CRC-32 checksum of the remaining 28 bytes

#### Scenario: Default subaccount
- **WHEN** no subaccount is specified
- **THEN** the default subaccount (all zeros) is used for hashing

### Requirement: Transfer Operation

Transfers move tokens from one account to another, deducting a fee.

#### Scenario: Successful transfer
- **WHEN** account A has balance >= amount + fee
- **AND** a transfer of `amount` from A to B is submitted
- **THEN** A's balance decreases by `amount + fee`
- **AND** B's balance increases by `amount`
- **AND** the fee is returned to the token pool (burned)
- **AND** a new block is appended to the blockchain
- **AND** the block index and block hash are returned

#### Scenario: Transfer with fee collector
- **WHEN** a fee collector is configured
- **AND** a transfer is executed
- **THEN** the fee is credited to the fee collector account instead of being burned

#### Scenario: Insufficient funds
- **WHEN** account A has balance < amount + fee
- **AND** a transfer is attempted
- **THEN** the transfer fails with `InsufficientFunds { balance }`
- **AND** no balances are modified

#### Scenario: Self-transfer
- **WHEN** a transfer is made from account A to the same account A
- **THEN** the transfer succeeds
- **AND** A's balance decreases by only the fee amount

### Requirement: Default Transfer Fee

The ICP ledger has a configurable transfer fee, defaulting to 10,000 e8s (0.0001 ICP).

#### Scenario: Query transfer fee
- **WHEN** a client queries the transfer fee
- **THEN** the configured fee is returned (default: `Tokens::from_e8s(10_000)`)

### Requirement: Minting Operation

Minting creates new tokens from the token pool and credits them to an account.

#### Scenario: Successful mint
- **WHEN** the minting account initiates a mint of `amount` to account B
- **THEN** B's balance increases by `amount`
- **AND** the token pool decreases by `amount`
- **AND** no fee is charged for minting

#### Scenario: Total supply overflow protection
- **WHEN** the total supply would exceed `Tokens::MAX` after minting
- **THEN** the operation panics with "total token supply exceeded"

### Requirement: Burning Operation

Burning removes tokens from an account and returns them to the token pool.

#### Scenario: Successful burn
- **WHEN** account A has balance >= amount
- **AND** a burn of `amount` is submitted
- **THEN** A's balance decreases by `amount`
- **AND** the token pool increases by `amount`
- **AND** no fee is charged for burning

#### Scenario: Burn with insufficient funds
- **WHEN** account A has balance < amount
- **THEN** the burn fails with `InsufficientFunds { balance }`

### Requirement: Approve Operation (ICRC-2 Compatibility)

The ICP ledger supports ICRC-2-style approvals, allowing a spender to transfer tokens on behalf of the owner.

#### Scenario: Successful approval
- **WHEN** account A approves spender S for `allowance` amount
- **THEN** the approval fee is deducted from A's balance (burned)
- **AND** the allowance for (A, S) is set to `allowance`

#### Scenario: Approval with expected allowance check
- **WHEN** an approval specifies `expected_allowance`
- **AND** the current allowance does not match `expected_allowance`
- **THEN** the approval fails with `AllowanceChanged { current_allowance }`

#### Scenario: Approval with expiration
- **WHEN** an approval specifies `expires_at`
- **THEN** the allowance becomes invalid after `expires_at`
- **AND** expired approvals are pruned from storage

#### Scenario: Failed approval refunds fee
- **WHEN** an approval fails (e.g., due to `AllowanceChanged`)
- **THEN** the approval fee is refunded (minted back) to the approver's account

### Requirement: Transfer From (ICRC-2 Compatibility)

Spenders can transfer tokens from an owner's account using a previously set allowance.

#### Scenario: Successful transfer_from
- **WHEN** spender S has allowance >= amount for owner A
- **AND** A has balance >= amount
- **THEN** the transfer succeeds
- **AND** the allowance for (A, S) decreases by the used amount
- **AND** A's balance decreases by the transferred amount

#### Scenario: Insufficient allowance
- **WHEN** spender S has allowance < amount for owner A
- **THEN** the transfer fails with `InsufficientAllowance { allowance }`

### Requirement: Transaction Deduplication

The ledger detects duplicate transactions within a configurable time window.

#### Scenario: Duplicate detection within window
- **WHEN** a transaction with `created_at_time` and identical content is submitted twice
- **AND** both submissions are within the transaction window (default: 24 hours)
- **THEN** the second submission fails with `TxDuplicate { duplicate_of }`

#### Scenario: Transaction too old
- **WHEN** a transaction's `created_at_time` is older than `now - transaction_window`
- **THEN** it is rejected with `TxTooOld { allowed_window_nanos }`

#### Scenario: Transaction created in the future
- **WHEN** a transaction's `created_at_time` is beyond `now + PERMITTED_DRIFT`
- **THEN** it is rejected with `TxCreatedInFuture { ledger_time }`

### Requirement: Transaction Throttling

The ledger throttles transactions to prevent overload.

#### Scenario: Throttle under high load
- **WHEN** the number of transactions in the deduplication window exceeds half of `max_transactions_in_window` (default: 3,000,000)
- **AND** the per-second rate exceeds the allowed maximum
- **THEN** new transactions are rejected with `TxThrottled`

### Requirement: Balance Tracking

Accounts with zero balance are automatically removed from the balance store.

#### Scenario: Zero balance cleanup
- **WHEN** an account's balance reaches exactly zero after a debit
- **THEN** the account is removed from the balance store
- **AND** subsequent balance queries return zero

#### Scenario: Total supply calculation
- **WHEN** total supply is queried
- **THEN** it returns `Tokens::MAX - token_pool`
- **AND** this equals the sum of all account balances

### Requirement: Block Chain Storage

The ICP ledger stores blocks in stable structures (version 3+), with each block containing a transaction, timestamp, and parent hash.

#### Scenario: Block ordering
- **WHEN** a new block is added
- **THEN** its parent hash must match the hash of the previous block
- **AND** its timestamp must be >= the timestamp of the previous block

#### Scenario: Block encoding
- **WHEN** a block is encoded
- **THEN** it is serialized using protobuf format
- **AND** `decode(encode(B)) == Ok(B)` for all blocks B

### Requirement: Archiving

Blocks are moved to archive canisters when the local block count exceeds a threshold.

#### Scenario: Trigger archiving
- **WHEN** the number of unarchived blocks exceeds `trigger_threshold`
- **THEN** up to `num_blocks_to_archive` blocks (max 18,000 per batch) are sent to archive canisters
- **AND** archived blocks are removed from local storage

#### Scenario: Archive canister creation
- **WHEN** no archive canister exists or the last one is full
- **THEN** a new archive canister is created with the configured wasm
- **AND** sufficient cycles are attached for creation and operation

#### Scenario: Block lookup across archives
- **WHEN** a block at height H is requested
- **AND** H falls within an archived range
- **THEN** the correct archive canister is identified via binary search on block ranges

### Requirement: Ledger Initialization

The ledger is initialized with a minting account, initial balances, and configuration parameters.

#### Scenario: Initialize with initial balances
- **WHEN** the ledger is initialized with initial values `{ account -> amount }`
- **THEN** each account is credited via a Mint operation
- **AND** the token symbol defaults to "ICP"
- **AND** the token name defaults to "Internet Computer"

### Requirement: Notification State

The ICP ledger tracks block notification state for integrations.

#### Scenario: Mark block as notified
- **WHEN** a block is marked as notified within the transaction window
- **THEN** the notification state is set
- **AND** attempting to re-notify fails with an error

#### Scenario: Notification too old
- **WHEN** a notification is attempted for a block older than the transaction window
- **THEN** the operation fails with an error message

### Requirement: Stable Storage Versioning

The ICP ledger uses versioned storage, with each version moving more state into stable structures.

#### Scenario: Version 3 storage layout
- **WHEN** the ledger is at version 3
- **THEN** allowances are stored in stable memory (MemoryId 1)
- **AND** allowance expirations are in stable memory (MemoryId 2)
- **AND** balances are in stable memory (MemoryId 3)
- **AND** blocks are in stable memory (MemoryId 4)
