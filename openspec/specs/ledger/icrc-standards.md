# ICRC Token Standards

The ICRC ledger suite implements the ICRC-1, ICRC-2, ICRC-3, and ICRC-21 token standards for fungible tokens on the Internet Computer. The implementation supports both u64 and u256 token types, uses ICRC-1 `Account` (principal + optional 32-byte subaccount), and encodes blocks in CBOR with self-described tag 55799.

## Requirements

### Requirement: ICRC-1 Token Standard - Basic Transfer

ICRC-1 defines the core fungible token interface including transfer, balance query, metadata, and total supply.

#### Scenario: Successful icrc1_transfer
- **WHEN** a caller transfers `amount` from their account to a destination account
- **AND** the caller's balance >= amount + fee
- **THEN** the caller's balance decreases by `amount + fee`
- **AND** the destination balance increases by `amount`
- **AND** a block of type "xfer" is recorded
- **AND** the block index (Nat) is returned

#### Scenario: Transfer with explicit fee
- **WHEN** a transfer specifies `fee` in the `TransferArg`
- **AND** the specified fee does not match the ledger's current fee
- **THEN** the transfer fails with `BadFee { expected_fee }`

#### Scenario: Transfer with memo
- **WHEN** a transfer includes a `memo` (up to 32 bytes)
- **THEN** the memo is stored in the transaction
- **AND** the memo participates in deduplication hashing

#### Scenario: Burn via transfer to minting account
- **WHEN** a transfer is sent to the minting account
- **THEN** the operation is treated as a burn
- **AND** no fee is charged
- **AND** a block of type "burn" is recorded

#### Scenario: Mint from minting account
- **WHEN** the minting account transfers tokens to a regular account
- **THEN** new tokens are minted
- **AND** no fee is charged
- **AND** a block of type "mint" is recorded

#### Scenario: Bad burn amount
- **WHEN** a burn amount is below the minimum burn amount
- **THEN** the transfer fails with `BadBurn { min_burn_amount }`

### Requirement: ICRC-1 Metadata

The ledger exposes token metadata through the `icrc1_metadata` endpoint.

#### Scenario: Query standard metadata
- **WHEN** `icrc1_metadata` is called
- **THEN** the response includes at minimum:
  - `icrc1:symbol` (Text) - the token symbol
  - `icrc1:name` (Text) - the token name
  - `icrc1:decimals` (Nat) - the number of decimal places
  - `icrc1:fee` (Nat) - the current transfer fee

#### Scenario: Custom metadata
- **WHEN** the ledger is initialized with custom metadata entries
- **THEN** those entries are returned alongside standard entries in `icrc1_metadata`

### Requirement: ICRC-1 Total Supply

#### Scenario: Query total supply
- **WHEN** `icrc1_total_supply` is called
- **THEN** it returns `Tokens::MAX - token_pool`
- **AND** this equals the sum of all non-zero account balances

### Requirement: ICRC-1 Minting Account

#### Scenario: Query minting account
- **WHEN** `icrc1_minting_account` is called
- **THEN** the configured minting account is returned
- **AND** transfers from this account are treated as mints
- **AND** transfers to this account are treated as burns

### Requirement: ICRC-1 Supported Standards

#### Scenario: Query supported standards
- **WHEN** `icrc1_supported_standards` is called
- **THEN** the response includes entries for each supported standard with name and URL
- **AND** at minimum includes "ICRC-1"

### Requirement: ICRC-2 Approve

ICRC-2 extends ICRC-1 with an approve/transfer_from model, allowing delegated transfers.

#### Scenario: Successful icrc2_approve
- **WHEN** an owner calls `icrc2_approve` with a spender and amount
- **THEN** the approval fee is deducted from the owner's balance
- **AND** the allowance for (owner, spender) is set to the specified amount
- **AND** a block of type "approve" is recorded
- **AND** the block index is returned

#### Scenario: Self-approval rejected
- **WHEN** an owner attempts to approve themselves as spender
- **THEN** the approval is rejected
- **AND** no fee is charged (for ICRC accounts where self-approval is detectable)

#### Scenario: Approve with expected_allowance
- **WHEN** `icrc2_approve` includes `expected_allowance`
- **AND** the current allowance does not match the expected value
- **THEN** the approval fails with `AllowanceChanged { current_allowance }`
- **AND** the fee is refunded to the owner

#### Scenario: Approve with expiration
- **WHEN** `icrc2_approve` includes `expires_at` (nanoseconds since Unix epoch)
- **AND** `expires_at` is in the future
- **THEN** the allowance is set with the specified expiration
- **AND** the allowance returns zero after expiration

#### Scenario: Approve with past expiration
- **WHEN** `icrc2_approve` includes `expires_at` that is <= current time
- **THEN** the approval fails with `Expired { ledger_time }`

#### Scenario: Approve zero amount removes allowance
- **WHEN** an owner approves an amount of zero for an existing allowance
- **THEN** the existing allowance is removed
- **AND** any associated expiration is removed

### Requirement: ICRC-2 Transfer From

#### Scenario: Successful icrc2_transfer_from
- **WHEN** spender S calls `icrc2_transfer_from` to move tokens from owner A to destination B
- **AND** the allowance for (A, S) >= amount + fee
- **AND** A's balance >= amount + fee
- **THEN** A's balance decreases by `amount + fee`
- **AND** B's balance increases by `amount`
- **AND** the allowance for (A, S) decreases by `amount + fee`
- **AND** a block of type "xfer" with spender field is recorded

#### Scenario: Transfer from with insufficient allowance
- **WHEN** the allowance for (A, S) < amount + fee
- **THEN** the transfer fails with `InsufficientAllowance { allowance }`

#### Scenario: Transfer from with insufficient balance
- **WHEN** the allowance is sufficient but A's balance < amount + fee
- **THEN** the transfer fails with `InsufficientFunds { balance }`

#### Scenario: Transfer from with expired allowance
- **WHEN** the allowance for (A, S) has expired
- **THEN** the allowance is treated as zero
- **AND** the transfer fails with `InsufficientAllowance { allowance: 0 }`

#### Scenario: Allowance cleanup on full use
- **WHEN** a transfer_from uses the entire remaining allowance (reduces to zero)
- **THEN** the allowance entry is removed from storage
- **AND** any associated expiration entry is removed

### Requirement: ICRC-2 Allowance Query

#### Scenario: Query allowance
- **WHEN** `icrc2_allowance` is called with account and spender
- **THEN** the current allowance amount and expiration (if any) are returned
- **AND** expired allowances return amount = 0

### Requirement: ICRC-2 Burn From (Spender Burn)

#### Scenario: Burn via spender
- **WHEN** a spender initiates a burn from an owner's account
- **AND** the allowance >= burn amount
- **AND** the owner's balance >= burn amount
- **THEN** the burn succeeds
- **AND** the allowance decreases by the burn amount
- **AND** no fee is charged for burns

### Requirement: Allowance Pruning

Expired allowances are periodically pruned from storage.

#### Scenario: Automatic pruning
- **WHEN** a new transaction is applied
- **THEN** up to 100 expired allowances are pruned
- **AND** the pruning processes allowances in expiration time order

#### Scenario: Pruning maintains invariants
- **WHEN** allowances are pruned
- **THEN** the number of expirations never exceeds the number of allowances

### Requirement: ICRC-3 Transaction Log

ICRC-3 defines a standard for querying the transaction log with generic block representation.

#### Scenario: Block encoding as CBOR
- **WHEN** a block is encoded
- **THEN** it is serialized as CBOR with self-described tag 55799
- **AND** transactions use compact operation codes: "mint", "burn", "xfer", "approve"

#### Scenario: Generic block conversion
- **WHEN** an encoded block is converted to a `GenericBlock`
- **THEN** the result is a CBOR-to-GenericValue mapping
- **AND** integers map to `Nat64` or `Nat` depending on size
- **AND** byte strings map to `Blob`
- **AND** text strings map to `Text`
- **AND** maps use text keys

#### Scenario: Representation-independent hashing
- **WHEN** a block hash is computed
- **THEN** it uses representation-independent hashing (RI hash)
- **AND** integers are LEB128-encoded before hashing
- **AND** maps are sorted by key hash before concatenation
- **AND** the self-described CBOR tag (55799) is transparent to hashing

#### Scenario: Bignum handling in hashing
- **WHEN** a value exceeds u64 range
- **THEN** it is encoded as a CBOR bignum (tag 2 for positive, tag 3 for negative)
- **AND** the LEB128 encoding of the bignum is used for hashing

#### Scenario: Get blocks via icrc3_get_blocks
- **WHEN** `icrc3_get_blocks` is called with a range
- **THEN** blocks within the range are returned as GenericBlock values
- **AND** archived block ranges reference the appropriate archive canisters

### Requirement: ICRC-3 Archive Information

#### Scenario: Query archives
- **WHEN** `icrc3_get_archives` is called
- **THEN** the list of archive canisters with their block ranges is returned

#### Scenario: Supported block types
- **WHEN** `icrc3_supported_block_types` is called
- **THEN** the supported block types are returned (mint, burn, xfer, approve, etc.)

### Requirement: ICRC-21 Consent Messages

ICRC-21 provides human-readable consent messages for wallet interactions.

#### Scenario: Consent message for transfer
- **WHEN** `icrc21_canister_call_consent_message` is called for an `icrc1_transfer` call
- **THEN** a human-readable consent message is returned
- **AND** it describes the transfer amount, destination, and fee

#### Scenario: Consent message for approve
- **WHEN** `icrc21_canister_call_consent_message` is called for an `icrc2_approve` call
- **THEN** a human-readable consent message is returned
- **AND** it describes the approval amount, spender, and expiration

#### Scenario: Consent message display types
- **WHEN** the consent message request specifies `GenericDisplay`
- **THEN** the response includes structured field display data
- **WHEN** the consent message request specifies `LineDisplay { characters_per_line, lines_per_page }`
- **THEN** the response includes paginated text display

### Requirement: ICRC-103 Allowance Listing

#### Scenario: List allowances for account
- **WHEN** `icrc103_get_allowances` is called with an account
- **THEN** active (non-expired) allowances for that account are returned
- **AND** pagination is supported via the spender field

### Requirement: Fee Collector

The ledger can optionally direct fees to a designated fee collector account instead of burning them.

#### Scenario: Fee collector configuration
- **WHEN** the ledger is initialized or upgraded with a `fee_collector_account`
- **THEN** transfer fees are credited to the fee collector instead of being returned to the token pool

#### Scenario: Fee collector block recording
- **WHEN** the fee collector changes
- **THEN** the fee collector account is recorded in the first block after the change
- **AND** subsequent blocks reference the fee collector by block index

### Requirement: ICRC-1 Block Structure

Each ICRC-1 block contains specific fields encoded in CBOR.

#### Scenario: Block fields
- **WHEN** a block is created
- **THEN** it contains:
  - `phash` - parent hash (optional, absent for genesis block)
  - `tx` - the transaction (flattened, with `op`, `from`, `to`, `amt`, etc.)
  - `fee` - effective fee (only when fee is not specified in transaction)
  - `ts` - timestamp in nanoseconds since Unix epoch
  - `fee_col` - fee collector account (when first set)
  - `fee_col_block` - block index of fee collector setting

#### Scenario: Block parent hash chain
- **WHEN** a new block is appended
- **THEN** its `phash` equals the hash of the previous encoded block
- **AND** the genesis block has no `phash`

### Requirement: Token Type Flexibility

The ICRC-1 implementation is generic over token types.

#### Scenario: U64 token type
- **WHEN** the ledger is compiled without `u256-tokens` feature
- **THEN** tokens use 64-bit unsigned integers
- **AND** the maximum value is `u64::MAX`

#### Scenario: U256 token type
- **WHEN** the ledger is compiled with `u256-tokens` feature
- **THEN** tokens use 256-bit unsigned integers
- **AND** larger token amounts are supported (e.g., for wrapped ETH)

### Requirement: Ledger Upgrade

The ICRC-1 ledger supports upgrades with parameter changes.

#### Scenario: Upgrade with parameter changes
- **WHEN** the ledger is upgraded with `UpgradeArgs`
- **THEN** optional fields (token_name, token_symbol, transfer_fee, metadata) are updated if provided
- **AND** the fee collector can be changed or unset
- **AND** archive options can be modified

#### Scenario: Upgrade preserves state
- **WHEN** the ledger is upgraded
- **THEN** all balances, allowances, and blockchain data are preserved
- **AND** the state is serialized to stable memory during pre_upgrade
- **AND** the state is deserialized from stable memory during post_upgrade
