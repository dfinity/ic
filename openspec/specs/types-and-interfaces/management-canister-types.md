# Types and Interfaces: Management Canister Types

## Overview

This specification covers the `ic-management-canister-types-private` and `ic-exhaustive-derive` crates, which define Candid payload types for the IC management canister (`ic:00`) and a proc-macro for exhaustive test set generation.

---

## Crate: `ic-management-canister-types-private`

**Path:** `rs/types/management_canister_types`

### Purpose

Defines all Candid-encoded request and response types used for communication with the IC management canister (`ic:00`). This is the canonical Rust representation of the management canister API surface.

### Module Structure

| Module | Purpose |
|---|---|
| `lib.rs` | Core types: `Method` enum, `Payload` trait, canister lifecycle types, settings, history, install modes, snapshot types, key management types. |
| `bounded_vec.rs` | `BoundedVec` generic for size-bounded vectors with deserialization enforcement. |
| `data_size.rs` | `DataSize` trait for computing in-memory data sizes of types. |
| `http.rs` | HTTP outcall request/response types, transform functions, pricing versions. |
| `provisional.rs` | Test-only provisional canister creation and top-up types. |

### Constants

- `IC_00: CanisterId` -- The management canister ID (the zero principal).
- `MAX_CONTROLLERS: usize = 10` -- Maximum number of controllers per canister.
- `HASH_LENGTH: usize = 32` -- SHA-256 hash length.
- `MAXIMUM_DERIVATION_PATH_LENGTH: usize = 255` -- BIP32 derivation path limit.
- `DEFAULT_SKIPPING_QUOTA: usize = 10_000` -- Candid decoder skipping quota per recommendation.

### Method Enum

```
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Method { ... }
```

Enumerates all management canister methods. Key categories:

**Canister Lifecycle:**
`CreateCanister`, `InstallCode`, `InstallChunkedCode`, `UninstallCode`, `StartCanister`, `StopCanister`, `DeleteCanister`, `UpdateSettings`, `CanisterStatus`, `CanisterInfo`, `CanisterMetadata`, `DepositCycles`

**Cryptographic Operations:**
`ECDSAPublicKey`, `SignWithECDSA`, `SchnorrPublicKey`, `SignWithSchnorr`, `VetKdPublicKey`, `VetKdDeriveKey`, `RawRand`, `SetupInitialDKG`, `ReshareChainKey`

**Bitcoin Interface:**
`BitcoinGetBalance`, `BitcoinGetUtxos`, `BitcoinGetBlockHeaders`, `BitcoinSendTransaction`, `BitcoinGetCurrentFeePercentiles`, `BitcoinSendTransactionInternal`, `BitcoinGetSuccessors`

**HTTP Outcalls:**
`HttpRequest`, `FlexibleHttpRequest`

**Chunk Store:**
`UploadChunk`, `StoredChunks`, `ClearChunkStore`

**Canister Snapshots:**
`TakeCanisterSnapshot`, `LoadCanisterSnapshot`, `ListCanisterSnapshots`, `DeleteCanisterSnapshot`, `ReadCanisterSnapshotMetadata`, `ReadCanisterSnapshotData`, `UploadCanisterSnapshotMetadata`, `UploadCanisterSnapshotData`

**Subnet Information:**
`NodeMetricsHistory`, `SubnetInfo`, `FetchCanisterLogs`

**Test-Only:**
`ProvisionalCreateCanisterWithCycles`, `ProvisionalTopUpCanister`

**Migration:**
`RenameCanister`

### Payload Trait

```
pub trait Payload<'a>: Sized + CandidType + Deserialize<'a> {
    fn encode(&self) -> Vec<u8>;
    fn decode(blob: &'a [u8]) -> Result<Self, UserError>;
}
```

All IC:00 payload types implement this trait. Encoding uses `candid::Encode!`; decoding uses `candid::Decode!` with a configured `DecoderConfig` that limits the skipping quota to 10,000 and disables full error messages for performance.

Decoding errors are mapped to `UserError` with `ErrorCode::InvalidManagementPayload`.

### Core Types

#### `CanisterIdRecord`
Simple wrapper for canister ID payloads: `{ canister_id: principal }`.

#### Canister History Types

- `CanisterChangeOrigin` -- Variant: `from_user { user_id }` or `from_canister { canister_id, canister_version }`.
- `CanisterCreationRecord` -- `{ controllers: Vec<PrincipalId>, environment_variables_hash: Option<[u8; 32]> }`.
- `CanisterCodeDeploymentRecord` -- `{ mode: CanisterInstallMode, module_hash: [u8; 32] }`.
- `CanisterControllersChangeRecord` -- `{ controllers: Vec<PrincipalId> }`.
- `CanisterLoadSnapshotRecord` -- `{ canister_version, snapshot_id, taken_at_timestamp, source: SnapshotSource, from_canister_id }`.
- `CanisterSettingsChangeRecord` -- `{ controllers: Option<Vec<PrincipalId>>, environment_variables_hash: Option<[u8; 32]> }`.

### BoundedVec

```
pub struct BoundedVec<
    const MAX_ALLOWED_LEN: usize,
    const MAX_ALLOWED_TOTAL_DATA_SIZE: usize,
    const MAX_ALLOWED_ELEMENT_DATA_SIZE: usize,
    T,
>(Vec<T>);
```

**Purpose:** A vector with compile-time bounds on element count, total data size, and per-element data size. The bounds are enforced at deserialization time (not at construction).

**Invariant:** At least one of the three bounds must be set (not `UNBOUNDED = usize::MAX`). Construction panics otherwise.

**Constant:** `pub const UNBOUNDED: usize = usize::MAX` -- Indicates no bound on that dimension.

**Deserialization behavior:**
1. Elements are deserialized one-by-one from a sequence.
2. After each element: check count vs `MAX_ALLOWED_LEN`, element size vs `MAX_ALLOWED_ELEMENT_DATA_SIZE`, cumulative size vs `MAX_ALLOWED_TOTAL_DATA_SIZE`.
3. On violation, returns a descriptive `serde::de::Error`.

**Key usage:** `BoundedHttpHeaders` bounds HTTP headers to 64 elements, 48 KiB total, 16 KiB per element.

### HTTP Outcall Types

#### `CanisterHttpRequestArgs`
The primary HTTP outcall request payload with fields: `url`, `max_response_bytes`, `headers` (as `BoundedHttpHeaders`), `method` (enum: get/head/post/put/delete), `body`, `transform` (optional `TransformContext`), `is_replicated`, `pricing_version`.

#### `TransformArgs`
Input to the transform function: `{ response: CanisterHttpResponsePayload, context: Vec<u8> }`.

#### `TransformContext`
References a canister query function for response transformation: `{ function: TransformFunc, context: Vec<u8> }`.

#### Pricing Constants
- `PRICING_VERSION_LEGACY = 1`
- `PRICING_VERSION_PAY_AS_YOU_GO = 2`
- `DEFAULT_HTTP_OUTCALLS_PRICING_VERSION = 1` (legacy)
- `ALLOWED_HTTP_OUTCALLS_PRICING_VERSIONS = [1]`

### Features

- `fuzzing_code` -- Enables `arbitrary::Arbitrary` derive for fuzzing support.

---

## Crate: `ic-exhaustive-derive`

**Path:** `rs/types/exhaustive_derive`

### Purpose

A proc-macro crate that derives the `ExhaustiveSet` trait for algebraic data types. The trait generates a representative set of values covering all variants and field combinations, primarily used for testing serialization round-trip correctness.

### Derive Macro: `#[derive(ExhaustiveSet)]`

Implements `crate::exhaustive::ExhaustiveSet` for structs and enums, provided all fields implement `ExhaustiveSet`.

### Generated Trait

```
pub trait ExhaustiveSet {
    fn exhaustive_set<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Vec<Self>;
}
```

### Strategy for Structs (Named and Tuple)

Rather than computing the Cartesian product (which causes combinatorial explosion), the macro uses **cyclic interleaving**:

1. Compute the exhaustive set for each field independently.
2. The composite set length equals the maximum individual set length.
3. Each field cycles through its own set using a cyclic iterator.

**Example:** If field `f1` has set `[a, b, c]` and `f2` has set `[x, y]`, the result is:
```
[Struct { f1: a, f2: x }, Struct { f1: b, f2: y }, Struct { f1: c, f2: x }]
```

This ensures every value of every field type appears at least once, with O(max(|field_sets|)) total elements.

### Strategy for Enums

- **Unit variants:** Collected directly into the result vector.
- **Data-carrying variants:** Each variant's fields are expanded using the same cyclic interleaving strategy as structs, then wrapped in the variant constructor. Results from all variants are concatenated.

### Generics Support

The macro adds `ExhaustiveSet` bounds to all generic type parameters automatically.

### Limitations

- **Unions** are not supported (compile-time error).
- **Unit structs** are not supported.
- Types with special invariants requiring constructors should implement the trait manually.
