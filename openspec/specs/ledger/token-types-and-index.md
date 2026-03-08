# Ledger Suite: Token Types and ICP Index

## Overview

This specification covers the token amount types used by the ICRC-1 ledger suite and the ICP index canister. These crates provide the core numeric representations for ledger balances and a block-indexing canister for the ICP ledger.

---

## Crate: `ic-icrc1-tokens-u256`

**Path:** `rs/ledger_suite/icrc1/tokens_u256`

### Purpose

Provides a 256-bit unsigned integer token type (`U256`) for use in ICRC-1 ledger operations where token amounts may exceed 64-bit or 128-bit capacity (e.g., ERC-20-compatible token bridges).

### Public Types

#### `U256`

A newtype wrapper around `ethnum::u256`.

```
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Decode, Encode)]
pub struct U256(u256);
```

**Constants:**
- `U256::ZERO` -- The zero value.
- `U256::ONE` -- The value one.
- `U256::MAX` -- The maximum 256-bit unsigned value (2^256 - 1).
- `U256::TYPE` -- String literal `"U256"` for type identification.

**Constructor / Accessor Methods:**
- `new(n: u256) -> Self` -- Wraps a raw `u256`.
- `to_u256(self) -> u256` -- Unwraps to the inner `u256`.
- `from_words(hi: u128, lo: u128) -> Self` -- Constructs from high and low 128-bit halves.
- `try_as_u64(&self) -> Option<u64>` -- Returns `Some(u64)` if the value fits in 64 bits; `None` otherwise.

### Trait Implementations

| Trait | Behavior |
|---|---|
| `Display` | Delegates to `u256::fmt`. |
| `From<u64>`, `From<u128>` | Widening conversions. |
| `From<U256> for Nat` | Converts to Candid `Nat` via big-endian byte representation. |
| `TryFrom<Nat> for U256` | Fails with error string if the `Nat` exceeds 32 bytes. |
| `Storable` | Fixed-size 32-byte big-endian encoding; `Bound::Bounded { max_size: 32, is_fixed_size: true }`. |
| `Bounded` | `min_value() = ZERO`, `max_value() = MAX`. |
| `CheckedAdd` | Returns `None` on overflow. |
| `CheckedSub` | Returns `None` on underflow. |
| `Zero` | `zero() = ZERO`; `is_zero()` equality check. |
| `Serialize` | Values fitting in u64 serialize as `u64`; larger values serialize as CBOR tag 2 (bignum) with big-endian compressed bytes. |
| `Deserialize` | Accepts u64 literals, u128 literals, and CBOR-tagged bignums. Also handles legacy `{ e8s: u64 }` map format is NOT supported (that is U64-only). |

### CBOR Encoding

Large values (> u64::MAX) are serialized using CBOR tag 2 (RFC 8949 bignum) wrapping the `ethnum::serde::compressed_bytes::be` representation. Values that fit in u64 are serialized as plain u64 for compactness.

---

## Crate: `ic-icrc1-tokens-u64`

**Path:** `rs/ledger_suite/icrc1/tokens_u64`

### Purpose

Provides a 64-bit unsigned integer token type (`U64`) for use in ICRC-1 ledger operations. This is the standard token type for ICP and most ICRC-1 tokens.

### Public Types

#### `U64`

A newtype wrapper around `u64`.

```
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize, Encode, Decode)]
pub struct U64(u64);
```

**Constants:**
- `U64::ZERO` -- The zero value.
- `U64::MAX` -- `u64::MAX`.
- `U64::TYPE` -- String literal `"U64"`.

**Constructor / Accessor Methods:**
- `new(n: u64) -> Self` -- Wraps a raw `u64`.
- `to_u64(self) -> u64` -- Unwraps to the inner `u64`.

### Trait Implementations

| Trait | Behavior |
|---|---|
| `FromStr` | Parses a decimal string to u64. |
| `Display` | Delegates to `u64::fmt`. |
| `From<u64>` | Direct wrapping. |
| `From<U64> for Nat` | Converts to Candid `Nat`. |
| `TryFrom<Nat> for U64` | Fails if `Nat` does not fit in u64. |
| `Storable` | Delegates to `u64::to_bytes` / `u64::from_bytes`; uses `u64`'s `Bound`. |
| `Bounded` | `min_value() = ZERO`, `max_value() = MAX`. |
| `CheckedAdd` | Returns `None` on overflow. |
| `CheckedSub` | Returns `None` on underflow. |
| `Zero` | `zero() = ZERO`; `is_zero()` equality check. |
| `Serialize` | Transparent serialization as u64. |
| `Deserialize` | Accepts both plain u64 values AND legacy `{ e8s: u64 }` map format (via `ic_ledger_core::tokens::Tokens`). |

### Backward Compatibility

The custom `Deserialize` implementation supports the legacy `{ e8s: u64 }` map format used by the original ICP ledger `Tokens` type. This allows seamless migration from the old token format.

---

## Crate: `ic-icp-index`

**Path:** `rs/ledger_suite/icp/index`

### Purpose

An index canister for the ICP ledger that periodically syncs blocks from the ledger and its archives, indexes them by `AccountIdentifier`, tracks balances, and exposes query endpoints for transaction history and balance lookups.

### Architecture

The canister uses stable memory exclusively for persistence via `ic-stable-structures`:

| Memory ID | Structure | Purpose |
|---|---|---|
| 0 | `StableCell<State>` | Scalar canister state (ledger_id, sync interval, flags). |
| 1, 2 | `StableLog<Vec<u8>>` | Append-only log of encoded blocks (index + data segments). |
| 3 | `StableBTreeMap<([u8; 28], Reverse<u64>), ()>` | Account-to-block-index mapping, stored in reverse order for newest-first iteration. |
| 4 | `StableBTreeMap<(AccountIdentifierDataType, [u8; 28]), u64>` | Per-account aggregated data (currently only balance). |

### Canister Lifecycle

#### Init (`IndexArg::Init`)

**Required fields:**
- `ledger_id: Principal` -- The principal of the ICP ledger canister to index.
- `retrieve_blocks_from_ledger_interval_seconds: Option<u64>` -- Optional polling interval (defaults to 1 second).

Initializes stable state and starts a periodic timer for `build_index`.

#### Post-Upgrade (`IndexArg::Upgrade`)

**Optional fields:**
- `ledger_id: Option<Principal>` -- Update the indexed ledger.
- `retrieve_blocks_from_ledger_interval_seconds: Option<u64>` -- Update the polling interval.

Applies configuration changes and restarts the sync timer.

### Block Synchronization (`build_index`)

1. Determines the next expected block index from the stable block log length.
2. Calls `query_encoded_blocks` on the ledger canister.
3. For archived block ranges, fetches from archive canisters using the callback provided by the ledger.
4. Appends each block to the stable log, updates account-to-block-index mappings, and processes balance changes.
5. On error, logs the failure and stops the timer to prevent repeated failures.

**Concurrency guard:** A boolean `is_build_index_running` flag prevents overlapping sync operations.

### Balance Tracking

For each block, the canister processes balance changes based on the operation type:

| Operation | Debit | Credit |
|---|---|---|
| `Burn { from, amount }` | `from -= amount` | -- |
| `Mint { to, amount }` | -- | `to += amount` |
| `Transfer { from, to, amount, fee }` | `from -= (amount + fee)` | `to += amount` |
| `Approve { from, fee }` | `from -= fee` | -- |

Zero balances are removed from the map to save storage.

**Overflow/underflow behavior:** The canister traps (panics) on balance overflow or underflow, treating it as data corruption.

### Query Endpoints

#### `ledger_id() -> Principal`
Returns the principal of the indexed ledger canister.

#### `get_blocks(GetBlocksRequest) -> GetBlocksResponse`
Returns encoded blocks from stable memory for the requested range.

**Response:**
- `chain_length: u64` -- Total number of indexed blocks.
- `blocks: Vec<EncodedBlock>` -- The requested block range.

#### `get_account_identifier_transactions(GetAccountIdentifierTransactionsArgs) -> GetAccountIdentifierTransactionsResult`

**Arguments:**
- `account_identifier: AccountIdentifier` -- The account to query.
- `start: Option<BlockIndex>` -- Pagination cursor (exclusive upper bound); `None` starts from newest.
- `max_results: u64` -- Maximum transactions to return.

**Response (on success):**
- `balance: u64` -- Current account balance.
- `transactions: Vec<SettledTransactionWithId>` -- Transactions in reverse chronological order.
- `oldest_tx_id: Option<BlockIndex>` -- The oldest transaction ID for this account.

#### `get_account_transactions(GetAccountTransactionsArgs) -> GetAccountTransactionsResult`
Same as above but accepts an ICRC-1 `Account` (converted to `AccountIdentifier`).

#### `get_account_identifier_balance(AccountIdentifier) -> u64`
Returns the current balance for the given account identifier.

#### `icrc1_balance_of(Account) -> u64`
Returns the current balance for the given ICRC-1 account (converted to AccountIdentifier).

#### `status() -> Status`
Returns `Status { num_blocks_synced: u64 }`.

#### `http_request(HttpRequest) -> HttpResponse`
- `/metrics` -- Prometheus metrics (stable memory pages, heap memory, cycle balance, block count).
- `/logs` -- JSON-formatted canister logs (P0 and P1 priority levels).

### Public Library Types (`ic_icp_index`)

```
enum IndexArg { Init(InitArg), Upgrade(UpgradeArg) }

struct InitArg {
    ledger_id: Principal,
    retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
}

struct UpgradeArg {
    ledger_id: Option<Principal>,
    retrieve_blocks_from_ledger_interval_seconds: Option<u64>,
}

struct GetBlocksResponse {
    chain_length: u64,
    blocks: Vec<EncodedBlock>,
}

struct GetAccountIdentifierTransactionsArgs {
    account_identifier: AccountIdentifier,
    start: Option<BlockIndex>,
    max_results: u64,
}

struct SettledTransaction {
    operation: Operation,
    memo: Memo,
    created_at_time: Option<TimeStamp>,
    icrc1_memo: Option<ByteBuf>,
    timestamp: Option<TimeStamp>,
}

struct SettledTransactionWithId {
    id: BlockIndex,
    transaction: SettledTransaction,
}

struct GetAccountIdentifierTransactionsResponse {
    balance: u64,
    transactions: Vec<SettledTransactionWithId>,
    oldest_tx_id: Option<BlockIndex>,
}

struct GetAccountIdentifierTransactionsError { message: String }

struct Status { num_blocks_synced: BlockIndex }
```

### Constants

- `DEFAULT_MAX_BLOCKS_PER_RESPONSE` -- Maximum blocks returned per `get_blocks` call (same as `MAX_BLOCKS_PER_REQUEST` from `icp-ledger`).
- `DEFAULT_RETRIEVE_BLOCKS_FROM_LEDGER_INTERVAL` -- 1 second default polling interval.
