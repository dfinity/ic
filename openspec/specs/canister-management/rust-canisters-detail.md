# Canister Management: Rust Canisters Detail

## Overview

This specification covers the foundational Rust canister libraries (`dfn_core`, `dfn_json`, `on_wire`, `stable_reader`, `stable_structures`) and the purpose-built test canisters (`backtrace-canister`, `call-loop-canister`, `call-tree-test`, `ecdsa-canister`, `memory-test`, `messaging-test`, `response-payload-test`, `statesync-test`).

---

## Crate: `on_wire`

**Path:** `rs/rust_canisters/on_wire`

### Purpose

Abstracts over serialization formats for canister communication. Decouples the choice of wire format (bytes, JSON, Candid, protobuf) from the communication method (query, inter-canister call, endpoint handler).

### Core Traits

#### `FromWire`
```
pub trait FromWire: Sized {
    fn from_bytes(wire: Vec<u8>) -> Result<Self, String>;
}
```
Deserializes a value from raw bytes.

#### `IntoWire`
```
pub trait IntoWire {
    fn into_bytes(self) -> Result<Vec<u8>, String>;
}
```
Serializes a value to raw bytes.

#### `NewType`
```
pub trait NewType {
    type Inner;
    fn into_inner(self) -> Self::Inner;
    fn from_inner(_: Self::Inner) -> Self;
}
```
A wrapper trait that allows unwrapping/wrapping serialization format markers.

### Witness Pattern

The `witness` function eliminates type ambiguity in polymorphic endpoint functions:
```
pub fn witness<ReturnType: NewType, Payload: NewType>(
    rt: ReturnType,
    payload: Payload::Inner,
) -> (ReturnType::Inner, Payload)
```

### Built-in Format Types

#### `BytesS`
Raw byte passthrough. `FromWire` and `IntoWire` are identity operations.

```
pub struct BytesS(pub Vec<u8>);
pub fn bytes(a: BytesS, b: Vec<u8>) -> (Vec<u8>, BytesS);
```

#### `FromS<T>`
Uses Rust's `From<Vec<u8>>` and `Into<Vec<u8>>` traits for conversion. Convenient for prototypes but encoding format may change between library versions.

```
pub struct FromS<T>(pub T);
pub fn from<A, B>(a: FromS<A>, b: B) -> (A, FromS<B>);
```

### Blanket Implementations

`Vec<u8>` implements both `IntoWire` and `FromWire` as identity operations.

---

## Crate: `dfn_json`

**Path:** `rs/rust_canisters/dfn_json`

### Purpose

A serialization format adapter for `on_wire` that uses `serde_json` for JSON encoding/decoding.

### Public Types

#### `Json<A>`
```
pub struct Json<A>(pub A);
```

Implements `FromWire` (via `serde_json::from_slice`), `IntoWire` (via `serde_json::to_vec`), and `NewType`.

#### `json` witness function
```
pub fn json<A, B>(a: Json<A>, b: B) -> (A, Json<B>);
```

Used as: `over(dfn_json::json, my_handler)`.

---

## Crate: `dfn_core`

**Path:** `rs/rust_canisters/dfn_core`

### Purpose

Core runtime library for IC canisters written in Rust. Provides raw System API bindings, async call support, endpoint definition helpers, and stable memory access.

### Module Structure

| Module | Purpose |
|---|---|
| `api` | Raw `ic0` System API bindings, `Funds` type, `CanisterId`/`PrincipalId` re-exports, `call`/`call_explicit` for inter-canister calls, `spawn` for futures. |
| `api::futures` | Async runtime: `CallFuture`, `FutureResult`, `TopLevelFuture` for managing IC async call patterns. |
| `api::ic0` | Direct FFI bindings to the `ic0` wasm import module (conditionally compiled for `wasm32`). |
| `endpoint` | Endpoint definition helpers: `over`, `over_async`, `over_init`, `over_may_reject`, and explicit variants. |
| `printer` | Debug printing utilities. |
| `setup` | Canister initialization setup. |
| `stable` | Stable memory read/write operations. |

### Re-exports

```
pub use api::futures::FutureResult;
pub use api::{CanisterId, call, call_explicit};
pub use endpoint::{bytes, from, over, over_async, over_async_explicit,
    over_async_may_reject, over_explicit, over_init, over_may_reject};
pub use on_wire::{BytesS, FromS};
```

### System API Bindings (`api::ic0`)

Complete FFI bindings for the IC System API, including:
- Canister identity: `canister_self_copy/size`
- Message handling: `msg_arg_data_copy/size`, `msg_caller_copy/size`, `msg_reply`, `msg_reply_data_append`, `msg_reject`
- Inter-canister calls: `call_new`, `call_data_append`, `call_on_cleanup`, `call_cycles_add`, `call_cycles_add128`, `call_perform`
- Stable memory: `stable_size/grow/read/write`, `stable64_size/grow/read/write`
- System info: `time`, `performance_counter`, `canister_cycle_balance`, `canister_cycle_balance128`
- Cycles: `msg_cycles_available/128`, `msg_cycles_refunded/128`, `msg_cycles_accept/128`
- Certified data: `certified_data_set`, `data_certificate_present`

### Endpoint Helpers

#### `over<In, Out, F, Witness>(witness, f)`
Creates a synchronous canister endpoint:
1. Reads input bytes via `arg_data()`.
2. Deserializes using the witness format's `FromWire`.
3. Calls `f(input)`.
4. Serializes the result using `IntoWire`.
5. Calls `reply` with the serialized bytes.

Always replies (never rejects). Traps on deserialization/serialization failure.

#### `over_init<In, F>(f)`
For `canister_init` -- deserializes input and calls `f`, with no reply.

#### `over_may_reject<In, Out, F, Witness>(witness, f)`
Like `over`, but `f` returns `Result<Out, String>`. On `Err`, calls `reject` instead of `reply`.

#### `over_async<In, Out, F, Witness>(witness, f)`
Async variant: `f` returns a `Future<Output = Out>`. Spawns the future for execution.

#### `over_explicit<In, Out>(f)`
Explicit encoding variant where `f` receives `In: FromWire` directly (not unwrapped via `NewType`).

### Funds Type

```
pub struct Funds { pub cycles: u64 }
```
Simplified representation of cycle funds for inter-canister calls.

---

## Crate: `stable_reader`

**Path:** `rs/rust_canisters/stable_reader`

### Purpose

A helper for reading length-prefix-encoded data from stable memory and piping it to a writer.

### Public Functions

#### `read(input: &mut impl Read, output: impl Write) -> io::Result<u32>`

Reads a length-prefix-encoded blob:
1. Reads a 4-byte little-endian `u32` prefix (the expected payload length).
2. Creates a `BufReader` over the input limited to `prefix` bytes.
3. Copies data to a `BufWriter` over the output.
4. Verifies the number of bytes read matches the prefix exactly.

**Error cases:**
- `prefix > piped_bytes` -- `UnexpectedEof` error indicating truncated stable memory data.
- `prefix < piped_bytes` -- Internal error (bug) indicating more bytes were read than expected.
- Returns `Ok(prefix)` on success (the number of bytes transferred).

---

## Crate: `stable_structures`

**Path:** `rs/rust_canisters/stable_structures`

### Purpose

A benchmark canister for measuring the performance of `ic-stable-structures` (`StableBTreeMap` and `StableVec`) in a Wasm execution environment. Used for performance regression testing.

### Data Structures

- `STABLE_BTREE_U64: StableBTreeMap<u64, u64, DefaultMemoryImpl>` -- BTree mapping u64 keys to u64 values.
- `STABLE_VEC_U64: StableVec<u64, DefaultMemoryImpl>` -- Vector of u64 values.

Both use `DefaultMemoryImpl` directly (no `MemoryManager`) to avoid measuring memory management overhead.

### Canister API

#### Init
`init(structure: String, count: u32)` -- Pre-populates the specified structure:
- `"btree_u64"` -- Inserts `count` entries `(i, 1)`.
- `"vec_u64"` -- Pushes `count` entries of value `1`.
- `"none"` -- No initialization.

#### BTree Operations

| Endpoint | Mode | Description |
|---|---|---|
| `query_btree_u64_single_read(count)` | query | Reads key `0` repeatedly. |
| `query_btree_u64_sparse_read(count)` | query | Reads `count` evenly-spaced keys. |
| `update_btree_u64_single_write(count)` | update | Writes to key `0` repeatedly. |
| `update_btree_u64_sparse_write(count)` | update | Writes to `count` evenly-spaced keys. |
| `update_btree_u64_insert(count)` | update | Inserts `count` sequential entries. |

#### Vector Operations

| Endpoint | Mode | Description |
|---|---|---|
| `query_vec_u64_single_read(count)` | query | Reads index `0` repeatedly. |
| `query_vec_u64_sparse_read(count)` | query | Reads `count` evenly-spaced indices. |
| `update_vec_u64_single_write(count)` | update | Writes to index `0` repeatedly. |
| `update_vec_u64_sparse_write(count)` | update | Writes to `count` evenly-spaced indices. |
| `update_vec_u64_insert(count)` | update | Appends `count` entries. |

#### Baseline

| Endpoint | Mode | Description |
|---|---|---|
| `update_empty()` | update | No-op update for measuring call overhead. |
| `query_empty()` | query | No-op query for measuring call overhead. |

---

## Test Canisters

### `backtrace-canister`

**Path:** `rs/rust_canisters/backtrace_canister`

**Purpose:** Tests canister backtrace reporting for different failure modes.

**Endpoints (all update):**
Each endpoint creates a non-trivial call chain (outer -> inner -> inner_2) to produce meaningful backtraces.

| Endpoint | Failure Mode |
|---|---|
| `unreachable` | Triggers `wasm32::unreachable()` instruction. |
| `oob` | Reads from out-of-bounds Wasm memory (near `u32::MAX`). |
| `ic0_trap` | Calls `panic!("uh oh")`. |
| `stable_oob` | (Triggers stable memory out-of-bounds access.) |

Uses the `make_call_chain!` macro with `#[inline(never)]` to ensure frames appear in backtraces.

### `call-loop-canister`

**Path:** `rs/rust_canisters/call_loop_canister`

**Purpose:** Tests inter-canister call limits by sending many outgoing calls in parallel.

**Endpoint:**
- `send_calls(megabytes_to_send: u32)` (update) -- Sends `megabytes_to_send` inter-canister calls, each with a 1 MB payload, to distinct (non-existent) canisters. Uses `futures::future::join_all` to await all calls.

### `call-tree-test`

**Path:** `rs/rust_canisters/call_tree_test`

**Purpose:** XNet integration testing canister that executes recursive call trees across canisters.

**Key types:**
- `CallTree { canister_id: String, subtrees: Vec<CallTree> }` -- Recursive call tree structure.
- `Arguments { calltrees: Vec<CallTree>, debug: bool, pages: u32 }` -- Input specifying the call tree, debug mode, and memory pages to touch.
- `Metrics { reject_responses: usize }` -- Tracks rejected responses.

**Memory allocation:** Allocates up to 3,800 MiB of heap memory in vectors of up to 512 MiB each, touching specified pages.

### `ecdsa-canister`

**Path:** `rs/rust_canisters/ecdsa`

**Purpose:** Test canister for ECDSA signing operations via the management canister.

**Endpoint:**
- `get_sig(options: Options)` (update) -- Calls `ic:00::sign_with_ecdsa` with a zero message hash and configurable derivation path and key name (defaults to `"test_key"` with `Secp256k1` curve).

### `memory-test`

**Path:** `rs/rust_canisters/memory_test`

**Purpose:** Tests heap and stable memory operations with configurable patterns.

**Configuration:**
- `MEMORY_SIZE = 1 GiB` heap allocation.
- `STABLE_MEMORY_SIZE = 6 GiB` stable memory.

**Operation struct:**
```
struct Operation {
    repeat: Option<usize>,     // iterations (default 1)
    address: Option<u64>,      // start address (random if omitted)
    size: u64,                 // region size in bytes
    step: Option<usize>,       // interval between accesses (contiguous if omitted)
    value: Option<u8>,         // value to assert/write (random if omitted)
}
```

Uses `dfn_core` for low-level System API access and a seeded PRNG (`rand_pcg::Lcg64Xsh32`) for deterministic random operations.

### `messaging-test`

**Path:** `rs/rust_canisters/messaging_test`

**Purpose:** Tests inter-canister messaging patterns including downstream call chains, payload sizes, cycle transfers, and best-effort calls.

**Key types:**
```
struct Call {
    receiver: Principal,
    call_bytes: u32,           // outgoing payload size
    reply_bytes: u32,          // expected reply payload size
    cycles: u128,              // cycles to attach
    timeout_secs: Option<u32>, // Some = best-effort, None = guaranteed response
    downstream_calls: Vec<Call>,
}
```

The `Call` type is recursive: each call specifies downstream calls that the receiver should make, enabling complex call tree testing.

**Message encoding:**
- `Message` -- Input to the canister containing a list of `Call` entries plus padding bytes.
- Uses Candid `Encode`/`Decode` for inter-canister payload serialization.

### `response-payload-test`

**Path:** `rs/rust_canisters/response_payload_test`

**Purpose:** Tests variable-size response payloads.

**Endpoint:**
- `query(operation: Operation) -> Result<String, String>` -- Returns a string of `response_size_bytes` repeated `'a'` characters.

### `statesync-test`

**Path:** `rs/rust_canisters/statesync_test`

**Purpose:** Support canister for state synchronization integration tests.

**Key types:**
```
enum CanisterCreationStatus {
    Idle,
    InProgress(u64),
    Done(u64),
}
```

Tracks the progress of canister creation operations during state sync testing. The `u64` values represent canister counts or identifiers.
