# Canister Utility Crates Specification

This specification covers the canister utility libraries under `rs/rust_canisters/` that provide HTTP serving, profiling, and logging capabilities for IC canisters in Rust.

---

## Requirements

### Requirement: Canister HTTP Serving (ic-canister-serve)

The `ic-canister-serve` crate provides functions to serve Prometheus-compatible metrics and structured JSON log output over a canister's `http_request` query endpoint.

#### Scenario: Serve Prometheus metrics via HTTP
- **WHEN** `serve_metrics` is called with a metrics-encoding closure
- **THEN** an `HttpResponse` is returned with status 200
- **AND** the `Content-Type` header is set to `text/plain; version=0.0.4`
- **AND** the `Content-Length` header matches the encoded body length
- **AND** the `Cache-Control` header is set to `no-store`
- **AND** the body contains the Prometheus-encoded metrics with the current timestamp converted from nanoseconds to milliseconds

#### Scenario: Metrics encoding failure
- **WHEN** `serve_metrics` is called and the encoding closure returns an error
- **THEN** an `HttpResponse` is returned with status 500
- **AND** the body contains the error description prefixed with `Failed to encode metrics:`

#### Scenario: Serve logs via HTTP with default parameters
- **WHEN** `serve_logs` is called with an HTTP request that has no query parameters
- **THEN** the severity defaults to `Info`
- **AND** the time filter defaults to `0` (include all entries)
- **AND** the response merges INFO and ERROR log entries ordered by timestamp
- **AND** the response has status 200 with `Content-Type: application/json`

#### Scenario: Serve logs filtered by severity
- **WHEN** `serve_logs` is called with a request containing `?severity=Error`
- **THEN** only ERROR-level log entries are included in the response
- **AND** INFO-level entries are excluded

#### Scenario: Serve logs filtered by time
- **WHEN** `serve_logs` is called with a request containing `?time=T`
- **THEN** log entries with timestamps less than or equal to T are skipped
- **AND** only entries with timestamps strictly greater than T are included

#### Scenario: Log response size limiting
- **WHEN** the combined size of serialized log entries exceeds approximately 1 MiB (`MAX_LOGS_RESPONSE_SIZE = 1 << 20`)
- **THEN** the response is truncated and no further entries are added
- **AND** each entry's approximate size is computed as 1.33x its raw field sizes to account for JSON serialization overhead

#### Scenario: Log entries include severity annotation
- **WHEN** log entries are serialized in the HTTP response
- **THEN** each entry is enhanced with a `severity` field (`Info` or `Error`), a `timestamp`, a `file`, a `line`, and a `message`

#### Scenario: Invalid log request parameters
- **WHEN** `serve_logs` is called with an invalid `severity` or `time` query parameter
- **THEN** an `HttpResponse` is returned with status 400
- **AND** the body contains a JSON object with an `error_description` field listing the invalid parameters

#### Scenario: Merged log ordering
- **WHEN** INFO and ERROR log buffers both contain entries
- **THEN** entries from both buffers are interleaved by timestamp in ascending order using a priority queue

---

### Requirement: Canister Profiler (ic-canister-profiler)

The `ic-canister-profiler` crate provides instruction-counting utilities for measuring the cost of code spans inside IC canisters, using `ic0.performance_counter`.

#### Scenario: Measure synchronous span instructions
- **WHEN** `measure_span` is called with a sink, a span name, and a closure
- **THEN** the closure is executed and its return value is returned
- **AND** the number of instructions consumed is recorded to the sink using `ic0::performance_counter(0)` (on wasm32) or elapsed wall-clock time (on non-wasm32)
- **AND** the measurement is computed as the difference between the counter after and before execution, using saturating subtraction

#### Scenario: Measure asynchronous span instructions
- **WHEN** `measure_span_async` is called with a sink, a span name, and a future
- **THEN** the future is awaited and its output is returned
- **AND** the number of instructions consumed across call-context switches is recorded using `ic0::performance_counter(1)` (on wasm32) or elapsed wall-clock time (on non-wasm32)

#### Scenario: Record measurement to SpanStats
- **WHEN** `ProfilerSink::record` is called on `&mut SpanStats` with a span name and instruction count
- **THEN** the instruction count is placed into the appropriate histogram bucket
- **AND** the `sum` is incremented by the instruction count
- **AND** the `max` is updated if the new count exceeds the current maximum
- **AND** the `num_samples` is incremented by one

#### Scenario: SpanStats histogram buckets
- **WHEN** a measurement is recorded into `SpanStats`
- **THEN** it is placed into the first bucket whose upper bound is greater than or equal to the measurement value
- **AND** there are 29 predefined buckets ranging from 10,000 to `u64::MAX`

#### Scenario: Record profiling metrics to Prometheus
- **WHEN** `SpanStats::record_metrics` is called with a `LabeledHistogramBuilder`
- **THEN** each span is emitted as a labeled histogram with a `span` label containing the span name
- **AND** the histogram includes per-bucket counts and the cumulative sum

#### Scenario: Thread-local SpanStats as ProfilerSink
- **WHEN** a `&'static LocalKey<RefCell<SpanStats>>` is used as a `ProfilerSink`
- **THEN** measurements are recorded thread-locally via `RefCell` borrow
- **AND** no cross-thread synchronization is required

#### Scenario: Span lookup by name
- **WHEN** `SpanStats::get_span` is called with a span name
- **THEN** it returns `Some(&SpanInfo)` if that span has been recorded
- **AND** it returns `None` if no measurement has been recorded for that span

---

### Requirement: Canister Log Library (ic-canister-log)

The `ic-canister-log` crate provides a thread-local circular log buffer with a macro-based API for structured logging inside IC canisters.

#### Scenario: Declare a log buffer with declare_log_buffer! macro
- **WHEN** `declare_log_buffer!(name = LOG, capacity = N)` is invoked
- **THEN** a thread-local `RefCell<LogBuffer>` named `LOG` is created
- **AND** the buffer has a maximum capacity of N entries

#### Scenario: Log a message with the log! macro
- **WHEN** `log!(LOG, "message {}", arg)` is invoked
- **THEN** a `LogEntry` is appended to the LOG buffer
- **AND** the entry contains the current timestamp from `ic0::time()` (on wasm32) or `SystemTime::now()` (on non-wasm32)
- **AND** the entry contains the formatted message string
- **AND** the entry contains the source file path via `std::file!()`
- **AND** the entry contains the source line number via `std::line!()`
- **AND** the entry contains a monotonically increasing counter from `entry_counter::increment()`
- **AND** the message is also printed to stdout via `println!` for local development convenience

#### Scenario: LogBuffer circular eviction
- **WHEN** the number of entries in a `LogBuffer` reaches its `max_capacity`
- **AND** a new entry is appended
- **THEN** the oldest entry (front of the deque) is evicted
- **AND** the new entry is pushed to the back

#### Scenario: LogBuffer iteration order
- **WHEN** `LogBuffer::iter()` is called
- **THEN** entries are returned in insertion order (oldest to newest)

#### Scenario: LogBuffer partition point query
- **WHEN** `LogBuffer::entries_partition_point` is called with a predicate on timestamps
- **THEN** entries are skipped using binary search up to the partition point
- **AND** only entries for which the predicate returns false are yielded
- **AND** the predicate must partition the entries (true for all entries before false entries) for correct behavior

#### Scenario: Global entry counter
- **WHEN** `entry_counter::increment()` is called
- **THEN** a thread-local counter is incremented by one and the new value is returned
- **AND** `entry_counter::get()` returns the current counter value without incrementing
- **AND** `entry_counter::set(value)` allows resetting the counter to an arbitrary value

#### Scenario: GlobalBuffer as Sink
- **WHEN** a `&'static GlobalBuffer` (i.e., `LocalKey<RefCell<LogBuffer>>`) is used as a `Sink`
- **THEN** entries are appended to the thread-local `LogBuffer` via `RefCell` borrow

#### Scenario: Export log entries
- **WHEN** `export(&LOG)` is called on a `GlobalBuffer`
- **THEN** a `Vec<LogEntry>` is returned containing clones of all entries in insertion order

#### Scenario: DevNull sink
- **WHEN** a `DevNull` sink is used
- **THEN** all appended log entries are silently discarded

#### Scenario: LogEntry display format
- **WHEN** a `LogEntry` is formatted using `Display`
- **THEN** the output follows the pattern `[{timestamp}] {file}:{line} {message}`
