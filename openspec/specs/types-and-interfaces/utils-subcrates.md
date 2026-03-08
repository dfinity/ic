# Types and Interfaces: Utility Sub-crates

## Overview

This specification covers the utility sub-crates under `rs/utils/` that provide foundational building blocks: assertion macros, caching, formatting, threading, and validation.

---

## Crate: `ic-utils-ensure`

**Path:** `rs/utils/ensure`

### Purpose

Provides `assert`-like macros that return `Result` errors instead of panicking. Designed for use in functions that return `Result<_, String>`.

### Macros

#### `ensure!($cond, $msg, $args...)`

Evaluates `$cond`. If false, returns `Err(format!("Condition {} is false: {}", stringify!($cond), format!($msg, $args...)))`.

**Usage:**
```rust
fn validate(x: u32) -> Result<(), String> {
    ensure!(x > 0, "x must be positive, got {}", x);
    Ok(())
}
```

#### `ensure_eq!($lhs, $rhs, $msg?, $args...?)`

Compares `$lhs != $rhs`. If unequal, returns `Err` with a message including both stringified expressions and their debug-formatted values.

Two forms:
- With message: `ensure_eq!(a, b, "context: {}", info)` -- appends formatted context.
- Without message: `ensure_eq!(a, b)` -- just shows the values.

### Design Notes

- Both macros use `expr_2021` fragment specifier.
- Both macros use early return (`return Err(...)`), so the calling function must return `Result<_, String>`.

---

## Crate: `ic-utils-lru-cache`

**Path:** `rs/utils/lru_cache`

### Purpose

An LRU (Least Recently Used) cache with dual capacity bounds: **memory size** (heap bytes) and **disk size**. Items are evicted when either capacity is exceeded.

### Dependencies

- `ic_heap_bytes::DeterministicHeapBytes` -- Trait for computing deterministic heap byte consumption.
- `ic_types::DiskBytes` -- Trait for computing disk byte consumption.
- `ic_types::NumBytes` -- Type-safe byte count.

### Public Types

#### `LruCache<K, V>`

```
pub struct LruCache<K, V>
where
    K: DeterministicHeapBytes + DiskBytes + Eq + Hash,
    V: DeterministicHeapBytes + DiskBytes,
```

**Internal state:**
- `cache: lru::LruCache<K, V>` -- Underlying unbounded LRU cache.
- `memory_capacity: usize`, `disk_capacity: usize` -- Configured maximum sizes.
- `memory_size: usize`, `disk_size: usize` -- Current tracked sizes.

**Constant:** `MAX_SIZE = usize::MAX / 2` -- Upper bound on individual item size and cache capacity to prevent arithmetic overflow.

### Methods

| Method | Description |
|---|---|
| `new(memory_capacity, disk_capacity)` | Creates a cache with the given capacity limits. Both must be <= `MAX_SIZE`. |
| `unbounded()` | Creates a cache that never auto-evicts (`MAX_SIZE` for both capacities). |
| `get(&mut self, key) -> Option<&V>` | Returns the value if present and marks it as most-recently-used. |
| `push(&mut self, key, value) -> Vec<(K, V)>` | Inserts a key-value pair. Returns all evicted entries (including a replaced duplicate key). Item sizes must be <= `MAX_SIZE`. |
| `pop(&mut self, key) -> Option<V>` | Removes and returns the value for the given key. |
| `pop_lru(&mut self) -> Option<(K, V)>` | Removes and returns the least-recently-used entry. |
| `clear(&mut self)` | Removes all entries, resets sizes to 0. |
| `len() -> usize` | Number of entries. |
| `is_empty() -> bool` | Whether the cache is empty. |

### Eviction Policy

On `push`, after inserting the new item:
1. If the new item replaces an existing key, the old entry's size is subtracted first.
2. While `memory_size > memory_capacity` OR `disk_size > disk_capacity`, the LRU item is popped.
3. All evicted items (both from capacity enforcement and key replacement) are returned.

**Key insight:** Both the key AND value contribute to the size calculations. This means large keys also consume capacity.

### Size Tracking

Sizes are tracked incrementally:
- On insert: `memory_size += key.deterministic_heap_bytes() + value.deterministic_heap_bytes()` (and similarly for disk).
- On remove: sizes are subtracted using `saturating_sub`.

### Invariant Checking

In debug builds (for caches with < 1,000 entries), the cache verifies that tracked sizes match the sum over all entries. This is disabled for larger caches due to performance cost.

### Trait Implementations

- `DeterministicHeapBytes for LruCache` -- Returns `self.memory_size`.
- `DiskBytes for LruCache` -- Returns `self.disk_size`.

---

## Crate: `ic-utils-rustfmt`

**Path:** `rs/utils/rustfmt`

### Purpose

A utility for formatting Rust source files programmatically by invoking the `rustfmt` binary.

### Public Functions

#### `rustfmt(path: impl AsRef<Path>) -> io::Result<()>`

Formats Rust source files at the given path:
- If `path` is a **directory**, recursively formats all `.rs` files within it.
- If `path` is a **file** with `.rs` extension, formats that single file.
- Otherwise, does nothing.

### Implementation Details

- Uses the `RUSTFMT` environment variable if set; otherwise defaults to `"rustfmt"` in PATH.
- Invokes `rustfmt --emit files <path>` which formats files in place.
- Returns `io::Result<()>` for filesystem errors; rustfmt formatting errors are silently ignored (only the process exit code matters).

---

## Crate: `ic-utils-thread`

**Path:** `rs/utils/thread`

### Purpose

Thread management utilities for graceful shutdown and background deallocation.

### Module: Root (`lib.rs`)

#### `JoinOnDrop<T>`

A wrapper around `thread::JoinHandle<T>` that automatically joins the thread when dropped.

```
pub struct JoinOnDrop<T>(Option<thread::JoinHandle<T>>);
```

**Methods:**
- `new(h: JoinHandle<T>) -> Self` -- Wraps a join handle.
- `join(mut self) -> thread::Result<T>` -- Explicitly joins the thread, consuming the wrapper.

**Drop behavior:** Calls `h.join()` and discards the result. This ensures the spawned thread completes before the owning struct is fully destroyed.

**Usage note:** In structs with multiple fields, `JoinOnDrop` should be the **last field** so that communication channels (senders/receivers) are dropped first, allowing the thread to observe channel closure and terminate.

### Module: `deallocator_thread`

#### `DeallocatorThread`

A background thread that deallocates complex objects gradually to avoid latency spikes from large deallocations.

```
pub struct DeallocatorThread {
    deallocation_sender: DeallocationSender,
    _deallocation_handle: JoinOnDrop<()>,
}
```

**Constructor:**
- `new(name: &str, sleep_between_drops: Duration)` -- Spawns a named background thread that receives objects via an unbounded channel, drops each one, then sleeps for the specified duration.

**Methods:**
- `sender() -> &DeallocationSender` -- Returns a cloneable sender reference.
- `send(obj: Box<dyn Any + Send + 'static>)` -- Delegates to the sender.
- `flush_deallocation_channel()` -- Blocks until all queued deallocations complete (for testing).

#### `DeallocationSender`

A cheaply cloneable sender to the deallocator thread.

**Backpressure:** `DEALLOCATION_BACKLOG_THRESHOLD = 500`. When the channel has >= 500 pending items, `send()` drops the object synchronously on the calling thread instead of enqueueing it. This prevents unbounded memory growth if the deallocator cannot keep up.

---

## Crate: `ic-validate-eq`

**Path:** `rs/utils/validate_eq`

### Purpose

Defines the `ValidateEq` trait for comparing a vetted subset of struct fields, reporting a path to the first divergence. Fields that are too expensive to compare in production (e.g., `PageMap`) can be excluded.

### Trait

```
pub trait ValidateEq {
    fn validate_eq(&self, rhs: &Self) -> Result<(), String>;
}
```

Returns `Ok(())` if the validated fields match, or `Err(path_description)` with a human-readable path to the first divergence.

### Blanket Implementations

| Type | Behavior |
|---|---|
| `BTreeMap<K, V>` where `K: PartialEq + Debug, V: ValidateEq` | Checks lengths match, then iterates pairs checking keys with `PartialEq` and values with `validate_eq`. Error includes `key=<debug>.<error>`. |
| `Option<T>` where `T: ValidateEq` | `None/None` = Ok; `Some/Some` = delegate; mixed = Err. |
| `VecDeque<T>` where `T: ValidateEq` | Checks length, then pairwise `validate_eq`. |
| `Arc<T>` where `T: ValidateEq` | Dereferences and delegates. |
| `(A, B)` where `A: ValidateEq, B: ValidateEq` | Validates both components. |

---

## Crate: `ic-validate-eq-derive`

**Path:** `rs/utils/validate_eq_derive`

### Purpose

Proc-macro derive for the `ValidateEq` trait.

### Derive Macro: `#[derive(ValidateEq)]`

Generates a `validate_eq` implementation for named structs. Each field can be annotated with `#[validate_eq(...)]`.

### Field Attributes

| Attribute | Behavior |
|---|---|
| (none, default) | Compares using `PartialEq`. Returns the field name on divergence. Also includes a compile-time check that the field type does NOT implement `ValidateEq` (to catch accidental use of shallow comparison on types that support deep comparison). |
| `#[validate_eq(CompareWithValidateEq)]` | Calls `.validate_eq()` recursively. Returns `field_name.inner_error` path. |
| `#[validate_eq(Ignore)]` | Skips the field entirely. |

### Compile-Time Safety

For fields using the default `PartialEq` comparison, the macro generates a compile-time assertion (using the "ambiguous impl" pattern from `static_assertions`) that ensures the field type does NOT implement `ValidateEq`. This catches bugs where a type has `ValidateEq` but the derive accidentally uses shallow comparison.

### Limitations

- Only supports named structs (not enums, unnamed structs, or unions).
- Supports generics (generic parameters are passed through to the impl).
