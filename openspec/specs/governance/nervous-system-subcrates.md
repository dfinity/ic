# Nervous System Sub-Crates Specification

This document specifies the behavior and contracts of the smaller utility crates in the
`rs/nervous_system/` tree. Each section covers one crate (or closely related pair).

---

## ic-nervous-system-collections-union-multi-map

**Path:** `rs/nervous_system/collections/union_multi_map/`

### Purpose

Provides a lazy union view over multiple multi-maps (maps whose values are collections such as
`Vec`, `BTreeSet`, or `HashSet`). Rather than copying and merging maps upfront, it chains
iterators from the constituent "layers" on each lookup.

### Public API

| Item | Description |
|---|---|
| `UnionMultiMap<'a, Map, Key, Value, ValuesIterator>` | Main struct. Holds `Vec<&'a Map>` of layers. |
| `UnionMultiMap::new(layers: Vec<&'a Map>) -> Self` | Constructor. |
| `UnionMultiMap::get(&self, key: &Key) -> Option<impl Iterator<Item = &'a Value>>` | Returns a flattened iterator over all values associated with `key` across every layer that contains that key. Returns `None` if no layer contains the key. |
| `trait Get<'a, Key, Value, ValuesIterator>` | Abstraction over map lookup. A single method `fn get(&'a self, key: &Key) -> Option<ValuesIterator>`. |

### Supported Combinations

Implementations of `Get` are provided for all combinations of:

- Map types: `BTreeMap`, `HashMap`
- Value collection types: `Vec`, `BTreeSet`, `HashSet`

### Invariants

1. `get` never mutates any layer.
2. If no layer contains `key`, `get` returns `None`.
3. If at least one layer contains `key`, `get` returns `Some(iterator)` that yields all values
   from all layers that contain the key, in layer order.
4. `Key` and `Value` must implement `Debug`.

---

## ic-nervous-system-instruction-stats

**Path:** `rs/nervous_system/instruction_stats/`

### Purpose

Tracks how many WebAssembly instructions are consumed by canister **update** calls. Stores
per-label-set histograms in thread-local state and exposes them as Prometheus-compatible
`candid_call_instructions` histogram metrics.

**Important limitation:** Only works within update methods, not queries, because queries do not
persist heap changes.

### Public API

| Item | Description |
|---|---|
| `UpdateInstructionStatsOnDrop` | RAII guard. On construction, snapshots `call_context_instruction_counter()`. On drop, computes delta and records it in the histogram for the given label set. |
| `UpdateInstructionStatsOnDrop::new(operation_name: &str, additional_labels: BTreeMap<String, String>) -> Self` | Creates a guard. `operation_name` is inserted as a label. |
| `encode_instruction_metrics(out: &mut MetricsEncoder<W>) -> io::Result<()>` | Writes accumulated histogram data as the `candid_call_instructions` metric. |

### Histogram Bins

Bins cover orders of magnitude 10^6 through 10^10, with 9 subdivisions per order, capped at
40 billion instructions. Events exceeding all finite bins fall into the infinity bin.

### Thread-Local State

- `STATS: RefCell<BTreeMap<LabelSet, Histogram>>` -- keyed by the full set of Prometheus labels.

---

## ic-nervous-system-instruction-stats-update-attribute (proc macro)

**Path:** `rs/nervous_system/instruction_stats_update_attribute/`

### Purpose

A procedural macro attribute `#[update]` that wraps `#[ic_cdk::update]` and additionally injects
an `UpdateInstructionStatsOnDrop` guard at the top of the function body, automatically tracking
instruction consumption for every annotated canister update endpoint.

### Usage

```rust
#[ic_nervous_system_instruction_stats_update_attribute::update]
fn my_method(arg: MyArg) -> MyResponse { ... }
```

Expands to the equivalent of:

```rust
#[ic_cdk::update]
fn my_method(arg: MyArg) -> MyResponse {
    let _on_drop = ic_nervous_system_instruction_stats::UpdateInstructionStatsOnDrop::new(
        "canister_method:my_method", std::collections::BTreeMap::new(),
    );
    ...
}
```

### Behavior

1. Forwards all attribute arguments to `ic_cdk::update` (e.g., `hidden = true`).
2. Inserts the instruction-tracking statement as the very first statement.
3. The injected label `operation_name` is `"canister_method:<function_name>"`.

---

## ic-nervous-system-query-instruction-logger (proc macro)

**Path:** `rs/nervous_system/query_instruction_logger/`

### Purpose

A procedural macro attribute `#[query]` that wraps `#[ic_cdk::query]` and logs instruction usage
at the end of query execution via `ic_cdk::println!`.

### Behavior

1. Wraps the original function body in a block that captures its return value.
2. After the body executes, prints: `"{LOG_PREFIX}Instructions used by method {fn_name}: {count}"`
   using `ic_cdk::api::call_context_instruction_counter()`.
3. Returns the captured result.
4. Forwards all attribute arguments to `ic_cdk::query`.

### Differences from instruction-stats

- This targets **query** methods (not update).
- Logs via `ic_cdk::println!` rather than accumulating histograms (queries cannot persist state).
- Requires `crate::LOG_PREFIX` to be defined in the calling crate.

---

## ic-nervous-system-proxied-canister-calls-tracker

**Path:** `rs/nervous_system/proxied_canister_calls_tracker/`

### Purpose

Tracks in-flight inter-canister calls that are made on behalf of another canister (typically NNS
Governance proxying calls through NNS Root). Provides statistics on the age and count of in-flight
calls, keyed by `(method_name, caller, callee)`.

### Public API

| Item | Description |
|---|---|
| `ProxiedCanisterCallsTracker` | Main struct. Holds a clock function, monotonic call ID counter, and a `BTreeMap` of open calls. |
| `ProxiedCanisterCallsTracker::new(clock: fn() -> SystemTime) -> Self` | Constructor. |
| `ProxiedCanisterCallsTracker::start_tracking(ego, caller, callee, method_name, args) -> SingleProxiedCallTracker` | Begins tracking. Returns an RAII guard. When the guard is dropped, the call is removed from tracking. |
| `is_empty() -> bool` | True if no calls are in flight. |
| `len() -> usize` | Number of in-flight calls. |
| `get_method_name_caller_callee_to_in_flight_max_age() -> BTreeMap<(String, PrincipalId, CanisterId), Duration>` | Returns the maximum age per `(method_name, caller, callee)` key. |
| `get_method_name_caller_callee_to_in_flight_count() -> BTreeMap<(String, PrincipalId, CanisterId), u64>` | Returns the count of in-flight calls per key. |
| `SingleProxiedCallTracker` | RAII guard. On drop, removes the tracked call. |

### Internal State

- `next_call_id: ProxiedCallId` -- monotonically incrementing u128 with wrapping.
- `id_to_open_call: BTreeMap<ProxiedCallId, CanisterCallMetadata>` -- metadata includes
  `created_at`, `caller`, `callee`, `method_name`, and `args_metadata` (first/last 64 bytes of
  the argument payload plus length).

### Invariants

1. Each `start_tracking` call increments the call ID and inserts metadata.
2. Each drop of `SingleProxiedCallTracker` removes exactly one entry.
3. Age is computed as `now - created_at`; if `created_at` is in the future, a sentinel duration
   of 9,876,543,210 seconds is used.

---

## ic-nervous-system-long-message

**Path:** `rs/nervous_system/long_message/`

### Purpose

Provides a mechanism to break long-running canister update operations across multiple message
boundaries by making a no-op self-call. This resets the per-message instruction counter while
staying within the same call context.

### Public API

| Item | Description |
|---|---|
| `noop_self_call_if_over_instructions(message_threshold: u64, call_context_threshold: Option<u64>) -> Result<(), OverCallContextError>` | If the current message has exceeded `message_threshold` instructions, makes a no-op self-call to get a fresh message budget. If `call_context_threshold` is set and the call-context counter exceeds it, returns `Err`. |
| `is_message_over_threshold(instructions_threshold: u64) -> bool` | Checks if the current message's instruction counter exceeds the threshold. |
| `OverCallContextError` | Error indicating call context limit was exceeded. Contains the `limit`. |

### Hidden Canister Method

Registers a hidden query endpoint `__long_message_noop` that does nothing. The self-call to this
endpoint is what creates a new message boundary.

### Test Support

In non-wasm32 builds:
- `in_test_temporarily_set_call_context_over_threshold() -> Temporary` -- sets the simulated
  call-context-over-limit flag to true.
- `is_message_over_threshold` alternates true/false on successive calls.

---

## ic-nervous-system-time-helpers

**Path:** `rs/nervous_system/time_helpers/`

### Purpose

Thin wrappers around platform time APIs that work both in canister (wasm32) and native
environments.

### Public API

| Function | Description |
|---|---|
| `now_nanoseconds() -> u64` | Returns current time in nanoseconds since UNIX epoch. Uses `ic_cdk::api::time()` on wasm32, `SystemTime::now()` natively. |
| `now_seconds() -> u64` | Returns current time in seconds since UNIX epoch. |
| `now_system_time() -> SystemTime` | Returns current time as `SystemTime`. |

---

## ic-nervous-system-timers

**Path:** `rs/nervous_system/timers/`

### Purpose

Provides a test-safe abstraction over `ic_cdk_timers`. In wasm32 builds, delegates directly to
`ic_cdk_timers`. In non-wasm32 builds (tests), provides a simulated timer infrastructure with
explicit time control.

### Public API (both environments)

| Function | Description |
|---|---|
| `set_timer(delay, future) -> TimerId` | Schedules a one-shot timer. |
| `set_timer_interval(interval, async_fn) -> TimerId` | Schedules a recurring timer. |
| `clear_timer(id)` | Cancels a timer. |

### Test-Only API (non-wasm32)

| Function | Description |
|---|---|
| `test::set_time_for_timers(duration_since_epoch)` | Sets the simulated clock. |
| `test::get_time_for_timers() -> Duration` | Reads the simulated clock. |
| `test::advance_time_for_timers(duration)` | Advances the simulated clock. |
| `test::run_pending_timers()` | Executes all timers whose scheduled time has passed. One-shot timers are removed after execution; recurring timers are rescheduled. |
| `test::run_pending_timers_every_interval_for_count(interval, count)` | Advances time by `interval` and runs pending timers, repeated `count` times. |
| `test::has_timer_task(TimerId) -> bool` | Checks if a timer exists. |
| `test::existing_timer_ids() -> Vec<TimerId>` | Lists all registered timer IDs. |

### Internal Test State

- `CURRENT_TIME: RefCell<Duration>` -- simulated clock, initialized to `SystemTime::now()`.
- `TIMER_TASKS: RefCell<SlotMap<TimerId, TimerTask>>` -- registered timers (one-shot or recurring).

---

## ic-nervous-system-timestamp

**Path:** `rs/nervous_system/timestamp/`

### Purpose

Formats UNIX timestamps as human-readable UTC strings. Exists because `chrono` and similar crates
cannot be used in the IC canister build environment.

### Public API

| Function | Description |
|---|---|
| `format_timestamp(timestamp_seconds: u64) -> Option<String>` | Formats as `"YYYY-MM-DD HH:MM:SS UTC"`. Returns `None` for out-of-range values. |
| `format_timestamp_for_humans(timestamp_seconds: u64) -> String` | Like `format_timestamp`, but falls back to `"timestamp {N} seconds"` on failure. |

---

## ic-nervous-system-timer-task

**Path:** `rs/nervous_system/timer_task/`

### Purpose

Trait-based framework for defining canister timer tasks with automatic metrics collection
(instruction counts, execution timestamps, histograms). Supports four task variants across two
dimensions: sync/async and recurring/periodic.

### Task Traits

| Trait | Schedule | Execution | Key Properties |
|---|---|---|---|
| `RecurringSyncTask` | Variable delay (returned from `execute`) | Synchronous | Consumes self, returns `(Duration, Self)`. If panics, stops. |
| `RecurringAsyncTask` | Variable delay | Asynchronous | Same pattern but async. Spawned via `ic_cdk::spawn`. |
| `PeriodicSyncTask` | Fixed interval (`INTERVAL` const) | Synchronous | `Copy` required. Runs even after panic. Does NOT run at t=0. |
| `PeriodicAsyncTask` | Fixed interval | Asynchronous | `Copy` required. Spawned. |

### Common Trait Members

All traits require:
- `const NAME: &'static str` -- used as the metric label.
- `fn execute(self) -> ...` -- the task body.

Recurring traits additionally require:
- `fn initial_delay(&self) -> Duration`

Periodic traits additionally require:
- `const INTERVAL: Duration`

### Scheduling

All traits provide:
- `fn schedule(self, metrics_registry: MetricsRegistryRef)` -- starts the task loop.
- Recurring traits also have `fn schedule_with_delay(self, delay, metrics_registry)`.

### Metrics (TimerTaskMetricsRegistry)

`MetricsRegistry` (re-exported as `TimerTaskMetricsRegistry`) collects:

- **Sync tasks:** instruction histogram, `last_executed` timestamp.
- **Async tasks:** instruction histogram, `outstanding_count`, `last_started`, `last_finished`.

`MetricsRegistry::encode(prefix, encoder)` writes:
- `{prefix}_task_instruction` -- histogram with label `task_name`.
- `{prefix}_sync_task_last_executed` -- gauge.
- `{prefix}_async_task_outstanding_count` -- counter.
- `{prefix}_async_task_last_started` -- gauge.
- `{prefix}_async_task_last_finished` -- gauge.

### Instruction Buckets

29 buckets from 10,000 to `u64::MAX`, using a semi-logarithmic scale (1, 2, 5 pattern per
decade).

---

## ic-nervous-system-string

**Path:** `rs/nervous_system/string/`

### Purpose

Utility for clamping strings and debug representations to a maximum character length, with an
ellipsis in the middle.

### Public API

| Function | Description |
|---|---|
| `clamp_string_len(s: &str, max_len: usize) -> String` | If `s` has more than `max_len` chars, keeps the first and last portions with `...` in the middle. If `max_len <= 3`, simply truncates. |
| `clamp_debug_len(object: &impl Debug, max_len: usize) -> String` | Applies `clamp_string_len` to the `{:#?}` formatted output. |

### Behavior

- `clamp_string_len("abcdef", 5)` returns `"a...f"`.
- `clamp_string_len("abcde", 5)` returns `"abcde"` (fits).
- Tail gets `content_len / 2` characters; head gets the remainder.

---

## ic-nervous-system-temporary

**Path:** `rs/nervous_system/temporary/`

### Purpose

RAII guard for temporarily overriding `thread_local! { static ...: Cell<bool> }` values in tests.
Restores the original value on drop.

### Public API

| Item | Description |
|---|---|
| `Temporary` | `#[must_use]` struct holding a reference to a `&'static LocalKey<Cell<bool>>` and the original value. |
| `Temporary::new(flag, temporary_value) -> Self` | Sets `flag` to `temporary_value` and captures the original. |
| `Drop for Temporary` | Restores the original value. |

### Intended Use

Feature-flag testing without compile-time feature gates:

```rust
thread_local! { static IS_FOO_ENABLED: Cell<bool> = Cell::new(false); }
fn temporarily_enable_foo() -> Temporary { Temporary::new(&IS_FOO_ENABLED, true) }

#[test]
fn test_foo_enabled() {
    let _guard = temporarily_enable_foo();
    // IS_FOO_ENABLED is true here; restored on drop.
}
```

---

## ic-nervous-system-histogram

**Path:** `rs/nervous_system/histogram/`

### Purpose

A Prometheus-compatible histogram that groups events into bins by their associated integer value
and counts occurrences per bin. Designed to plug into `ic_metrics_encoder`.

### Public API

| Item | Description |
|---|---|
| `Histogram::new(bin_inclusive_upper_bounds: Vec<i64>) -> Self` | Creates histogram with specified bin boundaries. |
| `Histogram::add_event(value: i64)` | Records an event. Finds the first bin whose upper bound >= value and increments it. If no finite bin matches, increments the infinity bin. Also adds to `sum`. |
| `Histogram::encode_metrics(labels, out) -> io::Result<LabeledHistogramBuilder>` | Writes histogram data (all finite bins plus an infinity bin) to a `LabeledHistogramBuilder`. |

### Internal State

- `bin_inclusive_upper_bound_to_count: BTreeMap<i64, u64>`
- `infinity_bin_count: u64`
- `sum: i64` (for computing mean)

---

## ic-nervous-system-humanize

**Path:** `rs/nervous_system/humanize/`

### Purpose

Human-readable parsing and formatting for nervous system protocol buffer types: tokens, durations,
percentages, and time-of-day values.

### Parse Functions

| Function | Input Format | Example |
|---|---|---|
| `parse_tokens(s)` | `"123 tokens"`, `"1 token"`, `"100_000 e8s"` | `"1.5 tokens"` -> `Tokens { e8s: 150_000_000 }` |
| `parse_duration(s)` | humantime format: `"1w 2d 3h"` | -> `Duration { seconds: ... }` |
| `parse_percentage(s)` | `"12.5%"` | -> `Percentage { basis_points: 1250 }` |
| `parse_time_of_day(s)` | `"14:30 UTC"` | -> `GlobalTimeOfDay { ... }` |

### Format Functions (Inverses)

| Function | Output Example |
|---|---|
| `format_tokens(tokens)` | `"1.5 tokens"`, `"500_000 e8s"` (for amounts < 0.01 tokens) |
| `format_duration(duration)` | humantime format |
| `format_percentage(percentage)` | `"12.5%"` |
| `format_time_of_day(time_of_day)` | `"14:30 UTC"` |

### Internal Helpers

- `parse_fixed_point_decimal(s, decimal_places) -> u64` -- parses decimal strings with `_`
  separators. The decimal point is shifted right by `decimal_places` digits.
- `group_digits(n: u64) -> String` -- formats with `_` as thousands separator (e.g., `1_234_567`).

---

## ic-nervous-system-initial-supply

**Path:** `rs/nervous_system/initial_supply/`

### Purpose

Computes the initial token supply of an ICRC-1 ledger by scanning mint transactions from the
beginning until a non-mint or a different-timestamp transaction is found.

### Public API

| Item | Description |
|---|---|
| `initial_supply_e8s<R: Runtime>(ledger_canister_id, options) -> Result<u64, String>` | Scans the ledger (and archive canisters if needed) to sum all initial mint amounts. |
| `InitialSupplyOptions` | `max_transactions: u64` (default 100,000), `batch_size: u64` (default 250, clamped to 1..2000). |

### Algorithm

1. Fetch transactions in batches starting from index 0.
2. Record the timestamp of the first transaction (`first_timestamp`).
3. For each transaction:
   - If timestamp differs from `first_timestamp`, stop.
   - If `kind != "mint"`, stop.
   - Add `mint.amount` to running total.
   - If `transaction_count >= max_transactions`, return error.
4. If a batch returns fewer than `batch_size` transactions, all transactions have been scanned.
5. Return the total as `u64`.

### Archive Handling

`ThickLedgerClient` follows redirects to archive canisters. When a ledger response includes
`archived_transactions`, those are fetched from the indicated archive canister and method, then
prepended to the directly-available transactions.

---

## Tools

### ic-nervous-system-tools-neuron-subaccount

**Path:** `rs/nervous_system/tools/neuron-subaccount/`

CLI tool that computes the NNS neuron subaccount and governance account identifier given a
controller principal and memo.

**Usage:** `neuron-subaccount --controller <PRINCIPAL> --memo <u64>`

**Output:** The subaccount (via `compute_neuron_staking_subaccount`) and the full governance
account (account identifier of the governance canister with that subaccount).

---

### release-runscript

**Path:** `rs/nervous_system/tools/release-runscript/`

Interactive CLI tool that guides an operator through the full NNS/SNS canister release process.
Implements an 8-step workflow:

| Step | Name | Action |
|---|---|---|
| 1 | Pick Release Candidate Commit | Finds latest commit with prebuilt artifacts. |
| 2 | Determine Upgrade Targets | Interactively selects NNS and SNS canisters to release. |
| 3 | Run Tests | Reminds operator to verify CI. |
| 4 | Create Proposal Texts | Runs shell scripts to generate proposal markdown. |
| 5 | Submit Proposals | Submits proposals via HSM-based identity. |
| 6 | Create Forum Post | Generates and copies forum post content. |
| 7 | Schedule Vote | Opens calendar event for trusted neuron voting. |
| 8 | Update Changelog | Commits changelog updates and creates a PR via `gh`. |

Each step can be invoked independently via subcommands, allowing resume after interruption.

---

### ic-nervous-system-tools-signed-canister-reply

**Path:** `rs/nervous_system/tools/signed-canister-reply/`

CLI tool for obtaining and verifying cryptographically signed canister replies.

**Subcommands:**

| Subcommand | Description |
|---|---|
| `call-canister --callee <PRINCIPAL> --method <NAME> --arg-path <PATH>` | Calls a canister and outputs the CBOR-encoded signed reply (certificate + callee principal ID) to stdout. |
| `load-from-file --signed-reply-path <PATH>` | Reads a previously saved signed reply, verifies the ICP certificate, and outputs the reply content in hex. |

The signed reply format is a CBOR object `{ callee_principal_id, certificate }` wrapping an ICP
certification `Certificate`. Verification uses the IC agent's `verify` method against the root
key.

---

### ic-nervous-system-submit-motion-proposal

**Path:** `rs/nervous_system/tools/submit-motion-proposal/`

CLI tool that submits an NNS motion proposal using an HSM-based identity.

**Arguments:**
- `--neuron-id <u64>` -- the proposing neuron.
- `--proposal-file <PATH>` -- file with YAML header (`title`, `url`) separated by 80 dashes from
  the summary markdown.
- `--network-url` (default: `https://ic0.app`)

**Requirements:** `DFX_HSM_PIN` environment variable must be set. Uses the `~/.config/dfx/identity/hsm/identity.json` HSM configuration.

---

### sync-with-released-nervous-system-wasms

**Path:** `rs/nervous_system/tools/sync-with-released-nervous-system-wasms/`

CLI tool that synchronizes a local workspace JSON file with the canister WASMs currently deployed
on the ICP mainnet.

**Process:**
1. For each NNS canister, reads `git_commit_id` metadata and `module_hash` from mainnet.
2. For each SNS canister, queries `sns-wasm` for the latest upgrade step and resolves git versions.
3. For external canisters (cycles-ledger, internet-identity, nns-dapp, etc.), crawls GitHub tags
   to find the release whose WASM sha256 matches the deployed module hash.
4. Updates the workspace JSON file with `rev`/`tag` and `sha256` for each canister.

**Usage:** `sync-with-released-nervous-system-wasms <path_to_workspace_file> <path_to_ic_wasm>`

Requires `GITHUB_TOKEN` environment variable.
