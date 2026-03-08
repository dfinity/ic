# Monitoring Details

This specification covers the core monitoring and observability crates of the Internet Computer replica. It defines the expected behavior of structured logging, metrics collection, CPU profiling, distributed tracing, and adapter metrics for external processes. The relevant crates are `ic-logger`, `ic-metrics`, `ic-pprof`, `ic-tracing`, `ic-adapter-metrics-client`, `ic-adapter-metrics-server`, and `ic-adapter-metrics-service`.

---

## Requirements

### Requirement: ReplicaLogger Construction and Configuration (ic-logger)

The IC logger provides structured, context-aware logging for the replica. It is built on `slog` with async output, structured `LogEntry` protobuf records, and rate-limited logging support.

#### Scenario: ReplicaLogger construction from config
- **WHEN** `new_replica_logger_from_config` is called with a `LoggerConfig`
- **THEN** a `LoggerImpl` is created with the configured log destination and format
- **AND** an `AsyncGuard` is returned to keep the async logging thread alive
- **AND** a `ReplicaLogger` is created wrapping a `LogEntryLogger` at the configured log level

#### Scenario: ReplicaLogger construction from slog Logger
- **WHEN** `new_replica_logger` is called with a `slog::Logger` and a `LoggerConfig`
- **THEN** a `LogEntryLogger` is created with the given root logger and the configured log level
- **AND** a `ReplicaLogger` wrapping the `LogEntryLogger` is returned

### Requirement: Log Destination Selection (ic-logger)

The logger supports multiple output destinations based on configuration.

#### Scenario: Log to stdout
- **WHEN** a `LoggerImpl` is created with `LogDestination::Stdout`
- **THEN** the logger writes all output to standard output

#### Scenario: Log to stderr
- **WHEN** a `LoggerImpl` is created with `LogDestination::Stderr`
- **THEN** the logger writes all output to standard error

#### Scenario: Log to file
- **WHEN** a `LoggerImpl` is created with `LogDestination::File(path)`
- **THEN** a file is created at the specified path
- **AND** the logger writes all output to that file
- **AND** if file creation fails, the process panics

### Requirement: Log Format Selection (ic-logger)

The logger supports JSON and full-text output formats.

#### Scenario: JSON log format
- **WHEN** the `LogFormat` is set to `Json`
- **THEN** the logger uses `slog_json::Json` as the drain formatter

#### Scenario: Full-text log format
- **WHEN** the `LogFormat` is set to `TextFull`
- **THEN** the logger uses `slog_term::FullFormat` with UTC timestamps and original key order
- **AND** a `PlainSyncDecorator` is used for uncolored output

### Requirement: Async and Priority-Based Log Routing (ic-logger)

The logger routes log messages based on priority level for reliability.

#### Scenario: High-priority synchronous logging
- **WHEN** a log message at Error or Critical level is emitted
- **THEN** the message is written synchronously via the high_priority_drain
- **AND** the message is guaranteed to be persisted before the logging call returns

#### Scenario: Low-priority asynchronous logging
- **WHEN** a log message below Error level (Warning, Info, Debug, Trace) is emitted
- **THEN** the message is sent to the async drain with a channel size of 10,240
- **AND** the async drain runs in a dedicated thread with a configurable name

#### Scenario: Overflow strategy for async logging
- **WHEN** the async drain channel is full
- **THEN** if `block_on_overflow` is true (system testing), the caller blocks until space is available
- **AND** if `block_on_overflow` is false (production), messages are dropped and the drop is reported
- **AND** the default overflow strategy is `DropAndReport`

### Requirement: Log Level Filtering (ic-logger)

The logger filters messages based on a configured minimum level.

#### Scenario: Level filtering in LogEntryLogger
- **WHEN** a log message is emitted at a given `slog::Level`
- **THEN** the `LogEntryLogger` checks if the message level is at or above the configured threshold via `is_enabled_at`
- **AND** levels map from `ic_config::logger::Level` to `slog::Level`: Critical, Error, Warning, Info, Debug, Trace
- **AND** in debug builds (`cfg(debug_assertions)`), the default level from `slog::Logger` conversion is Trace
- **AND** in release builds, the default level from `slog::Logger` conversion is Info
- **AND** messages below the threshold are silently discarded

### Requirement: Structured Log Entry Emission (ic-logger)

The logger produces structured `LogEntry` protobuf records with contextual metadata.

#### Scenario: Log entry population
- **WHEN** a log message is emitted via the `ReplicaLogger`
- **THEN** a `LogEntry` protobuf is populated with:
  - `level`: the log level as a string (e.g., "INFO", "WARNING")
  - `utc_time`: the current UTC time in RFC 3339 format with millisecond precision
  - `crate_`: the first component of the Rust module path
  - `module`: the last component of the Rust module path
  - `message`: the formatted log message, truncated to `MAX_LOG_MESSAGE_LEN_BYTES` (16 KiB)
  - `line`: the source line number
  - `subnet_id` and `node_id`: from the logger context
- **AND** the formatted output includes a network context prefix: `s:{subnet_id}/n:{node_id}/{crate}/{module} {message}`
- **AND** the `LogEntry` is attached as a structured `slog` key-value pair

#### Scenario: Log message truncation
- **WHEN** a log message exceeds `MAX_LOG_MESSAGE_LEN_BYTES` (16,384 bytes)
- **THEN** the message is ellipsized with 50% of the allowed length from the beginning and the remainder from the end
- **AND** an ellipsis marker is inserted at the truncation point

#### Scenario: Crate name extraction
- **WHEN** `get_crate` is called with a module path
- **THEN** the first component of the `::` delimited path is returned
- **AND** if the path is empty, an empty string is returned

#### Scenario: Module name extraction
- **WHEN** `get_module` is called with a module path
- **THEN** the last component of the `::` delimited path is returned
- **AND** if the path is empty, an empty string is returned

### Requirement: Rate-Limited Logging (ic-logger)

The logger supports throttling repeated log messages from the same source location.

#### Scenario: First log for a source location
- **WHEN** `is_n_seconds` is called for a module_path + line combination for the first time
- **THEN** `true` is returned
- **AND** the current timestamp is recorded in the `last_log` HashMap

#### Scenario: Subsequent log within the rate limit window
- **WHEN** `is_n_seconds` is called again for the same location within N seconds
- **THEN** `false` is returned
- **AND** the log is suppressed

#### Scenario: Subsequent log after the rate limit window expires
- **WHEN** `is_n_seconds` is called after N seconds have elapsed since the last log for this location
- **THEN** `true` is returned
- **AND** the timestamp is updated

#### Scenario: Rate limiting is per-instance
- **WHEN** a LogEntryLogger is cloned
- **THEN** the clone has its own empty `last_log` HashMap
- **AND** rate limiting is independent between the original and the clone

### Requirement: Context-Aware Logging (ic-logger)

The ReplicaLogger supports context enrichment via the ContextLogger wrapper.

#### Scenario: Context logger creation
- **WHEN** a `ReplicaLogger` (which is `ContextLogger<LogEntry, LogEntryLogger>`) is created
- **THEN** it wraps a `LogEntry` context that can be enriched with additional fields
- **AND** `new_logger!` creates a derived logger with additional context fields set
- **AND** macros `info!`, `warn!`, `error!`, `debug!`, `trace!`, `crit!` emit logs with the accumulated context

### Requirement: Test Loggers (ic-logger)

The logger provides test-specific logger implementations.

#### Scenario: No-op logger for testing
- **WHEN** `no_op_logger()` is called
- **THEN** a `ReplicaLogger` is created that discards all log messages
- **AND** it uses `slog::Discard` as the drain with Critical level (suppresses everything)

#### Scenario: Test logger with environment control
- **WHEN** `test_logger(log_level)` is called
- **THEN** if the `RUST_LOG` environment variable is set, its value determines the log level (overriding the parameter)
- **AND** if `LOG_TO_STDERR` is set, output goes to stderr; otherwise to stdout via `TestStdoutWriter`
- **AND** if neither `RUST_LOG` nor `log_level` provides a level, a no-op logger is returned

#### Scenario: Test logger with writer
- **WHEN** `LoggerImpl::new_for_test` is called with a custom writer
- **THEN** a LoggerImpl is created that writes to the provided writer
- **AND** the async thread is named "logger-for-test"

---

### Requirement: MetricsRegistry Construction (ic-metrics)

The IC metrics system provides a wrapper around the Prometheus client library with helpers for metric creation, critical error tracking, adapter metrics collection, and Tokio runtime observability.

#### Scenario: Global metrics registry with process collector
- **WHEN** `MetricsRegistry::global()` is called
- **THEN** the Prometheus default registry is cloned and wrapped
- **AND** an `AdapterMetricsRegistry` is created for scraping external adapter processes
- **AND** on Linux, a `ProcessCollector` is registered that exposes `process_threads` and other OS-level metrics via `/proc`
- **AND** duplicate registration of the ProcessCollector is silently ignored

#### Scenario: Isolated metrics registry for testing
- **WHEN** `MetricsRegistry::new()` is called
- **THEN** a fresh, empty `prometheus::Registry` is created
- **AND** the registry is independent of the global default, ensuring test isolation
- **AND** an `AdapterMetricsRegistry` is attached

### Requirement: Metric Type Creation (ic-metrics)

The MetricsRegistry provides convenience methods for creating all Prometheus metric types.

#### Scenario: Histogram creation with custom buckets
- **WHEN** `metrics_registry.histogram(name, help, buckets)` is called
- **THEN** a `prometheus::Histogram` is created with the specified bucket boundaries
- **AND** the histogram is registered with the underlying Prometheus registry
- **AND** the registered histogram is returned for use

#### Scenario: Histogram vector creation
- **WHEN** `metrics_registry.histogram_vec(name, help, buckets, label_names)` is called
- **THEN** a `prometheus::HistogramVec` is created with the specified labels and bucket boundaries
- **AND** individual histogram instances are accessed via `with_label_values`

#### Scenario: Integer gauge creation
- **WHEN** `metrics_registry.int_gauge(name, help)` is called
- **THEN** a `prometheus::IntGauge` is created and registered
- **AND** the gauge supports `set`, `inc`, `dec` operations for tracking current values

#### Scenario: Integer gauge vector creation
- **WHEN** `metrics_registry.int_gauge_vec(name, help, label_names)` is called
- **THEN** a `prometheus::IntGaugeVec` is created with the specified labels
- **AND** individual gauge instances are accessed via `with_label_values`

#### Scenario: Floating-point gauge creation
- **WHEN** `metrics_registry.gauge(name, help)` is called
- **THEN** a `prometheus::Gauge` is created and registered

#### Scenario: Floating-point gauge vector creation
- **WHEN** `metrics_registry.gauge_vec(name, help, label_names)` is called
- **THEN** a `prometheus::GaugeVec` is created with the specified labels

#### Scenario: Integer counter creation
- **WHEN** `metrics_registry.int_counter(name, help)` is called
- **THEN** a monotonically increasing `prometheus::IntCounter` is created and registered
- **AND** the counter supports `inc` and `inc_by` operations

#### Scenario: Integer counter vector creation
- **WHEN** `metrics_registry.int_counter_vec(name, help, label_names)` is called
- **THEN** a `prometheus::IntCounterVec` is created with the specified labels

### Requirement: Critical Error Counter (ic-metrics)

The MetricsRegistry provides a specialized counter for critical errors that trigger alerts.

#### Scenario: Critical error counter creation
- **WHEN** `metrics_registry.error_counter(error_name)` is called
- **THEN** an `IntCounter` is created with metric name `critical_errors` and a constant label `error={error_name}`
- **AND** each unique error name produces a distinct counter instance
- **AND** any increment triggers monitoring alerts
- **AND** each increment must be paired with an error log message prefixed by the error name

#### Scenario: Duplicate error counter panics
- **WHEN** `error_counter` is called with the same error name twice on the same registry
- **THEN** the second call panics due to duplicate Prometheus registration
- **AND** this enforces uniqueness of error counter names

### Requirement: Generic Collector Registration (ic-metrics)

The MetricsRegistry supports registration of arbitrary Prometheus collectors.

#### Scenario: Register a custom collector
- **WHEN** `metrics_registry.register(collector)` is called with any `prometheus::Collector`
- **THEN** the collector is cloned, boxed, and registered with the underlying Prometheus registry
- **AND** the original collector is returned for direct use

#### Scenario: Access underlying Prometheus registry
- **WHEN** `metrics_registry.prometheus_registry()` is called
- **THEN** a reference to the underlying `prometheus::Registry` is returned
- **AND** this can be used for direct Prometheus operations (e.g., gathering metrics)

### Requirement: Bucket Helper Functions (ic-metrics)

The metrics crate provides helper functions for generating histogram bucket boundaries.

#### Scenario: Decimal buckets on 1-2-5 grid
- **WHEN** `decimal_buckets(min_power, max_power)` is called
- **THEN** buckets are generated as `{1, 2, 5} x 10^n` for n in [min_power, max_power]
- **AND** the returned vector is strictly increasing
- **AND** the count is `3 * (max_power - min_power + 1)`
- **AND** panics if min_power > max_power

#### Scenario: Decimal buckets with zero
- **WHEN** `decimal_buckets_with_zero(min_power, max_power)` is called
- **THEN** the result is the same as `decimal_buckets` with a `0.0` bucket prepended

#### Scenario: Binary buckets as powers of two
- **WHEN** `binary_buckets(min_power, max_power)` is called
- **THEN** buckets are generated as `2^n` for n in [min_power, max_power]
- **AND** the count is `max_power - min_power + 1`
- **AND** suitable for IEC units (KiB/MiB/GiB)

#### Scenario: Binary buckets with zero
- **WHEN** `binary_buckets_with_zero(min_power, max_power)` is called
- **THEN** the result is the same as `binary_buckets` with a `0.0` bucket prepended

#### Scenario: Linear buckets
- **WHEN** `linear_buckets(start, width, count)` is called
- **THEN** `count` buckets are generated as an arithmetic progression starting at `start` with step `width`
- **AND** panics if count is 0 or width is <= 0

#### Scenario: Exponential buckets
- **WHEN** `exponential_buckets(start, factor, count)` is called
- **THEN** `count` buckets are generated as a geometric progression: `start * factor^i` for i in [0, count)
- **AND** panics if count is 0, start <= 0, or factor <= 1

#### Scenario: Add bucket to existing vector
- **WHEN** `add_bucket(new_bound, buckets)` is called
- **THEN** the new bound is inserted in sorted order into the bucket vector
- **AND** if the bound already exists, it is not duplicated

### Requirement: HistogramVec Timer (ic-metrics)

The HistogramVecTimer provides a drop-based timing mechanism for HistogramVec metrics where label values may not be fully known at creation time.

#### Scenario: Start timer with initial label values
- **WHEN** `HistogramVecTimer::start_timer(hist, label_names, label_values)` is called
- **THEN** the current instant is recorded as the start time
- **AND** the initial label values are stored
- **AND** in debug builds, the label names are validated against the histogram definition

#### Scenario: Update label value after timer creation
- **WHEN** `set_label(k, v)` is called on an active timer
- **THEN** the label value for the named label is updated
- **AND** the observation on drop will use the updated label values

#### Scenario: Set nonexistent label panics
- **WHEN** `set_label` is called with a label name not in the timer's label_names
- **THEN** the method panics with "No such label: {k}"

#### Scenario: Timer observation on drop
- **WHEN** a `HistogramVecTimer` is dropped
- **THEN** the elapsed time since creation is observed on the histogram
- **AND** the observation uses the current (possibly updated) label values
- **AND** the duration is recorded in seconds as f64

### Requirement: Adapter Metrics Registry (ic-metrics)

The AdapterMetricsRegistry manages remote process adapter metrics, collecting them via concurrent scraping.

#### Scenario: Register adapter metrics
- **WHEN** `metrics_registry.register_adapter(adapter_metrics)` is called
- **THEN** the `AdapterMetrics` instance is registered with the `AdapterMetricsRegistry`
- **AND** the adapter's metrics are namespaced to avoid collision with replica metrics

#### Scenario: Duplicate adapter registration fails
- **WHEN** `register` is called with an adapter that has the same name as an already registered adapter
- **THEN** an `Error::AlreadyReg` error is returned

#### Scenario: Concurrent adapter metrics gathering
- **WHEN** `gather(timeout)` is called on the AdapterMetricsRegistry
- **THEN** all registered adapters are scraped concurrently using `join_all`
- **AND** each scrape has the specified timeout
- **AND** the `adapter_metrics_scrape_duration_seconds` histogram records the duration and status for each adapter
- **AND** successful scrapes contribute their MetricFamily entries
- **AND** failed scrapes are silently ignored (empty Vec returned)

#### Scenario: Scrape duration tracking
- **WHEN** an adapter scrape completes (success or failure)
- **THEN** the scrape duration histogram is observed with labels [adapter_name, status_code]
- **AND** successful scrapes use the "success" status
- **AND** failed scrapes use the tonic error code as the status

### Requirement: Tokio Task Metrics Collection (ic-metrics)

The metrics crate supports collecting Tokio runtime task metrics via the tokio-metrics crate.

#### Scenario: Tokio task metrics exposition
- **WHEN** a `TokioTaskMetricsCollector` is created with a namespace
- **THEN** a `tokio_metrics::TaskMonitor` is returned for instrumenting async tasks
- **AND** the collector exposes Prometheus metrics for:
  - `tokio_task_dropped_count`: number of dropped tasks
  - `tokio_task_instrumented_count`: number of instrumented tasks
  - `long_delay_ratio`: ratio of long scheduling delays
  - `mean_idle_duration`: average idle time between polls
  - `mean_poll_duration`: average poll execution time
  - `mean_scheduled_duration`: average time in the scheduled queue
  - `mean_slow_poll_duration`: average duration of slow polls
  - `slow_poll_ratio`: ratio of slow polls to total polls
- **AND** the collector implements `prometheus::Collector` for integration with the registry

---

### Requirement: CPU Profile Collection (ic-pprof)

The IC pprof crate provides in-process CPU profiling with output in both pprof protobuf and SVG flamegraph formats.

#### Scenario: CPU profile collection
- **WHEN** `collect(duration, frequency)` is called
- **THEN** a `ProfilerGuard` is created on a blocking thread (to avoid 40-60ms latency on the async runtime)
- **AND** CPU samples are collected at the specified frequency (in Hz) for the given duration
- **AND** after the duration elapses, a `Report` is built from the collected samples
- **AND** thread names in frames are post-processed via `frames_post_processor`

#### Scenario: Thread name normalization
- **WHEN** a profiling frame's thread name is processed
- **THEN** the regex `^(?P<thread_name>[a-z-_ :]+?)(-?\d)*$` extracts the base name
- **AND** trailing digits (including optional leading dash) are stripped
- **AND** underscores and spaces in the base name are replaced with dashes
- **AND** if the regex does not match, the original thread name is used as-is

### Requirement: Pprof Profile Output Formats (ic-pprof)

The PprofCollector trait provides two output formats for CPU profiles.

#### Scenario: Pprof protobuf profile output
- **WHEN** `Pprof::profile(duration, frequency)` is called
- **THEN** a CPU profile is collected via `collect`
- **AND** the resulting report is encoded as a pprof protobuf message via `report.pprof()`
- **AND** the protobuf bytes are returned as `Vec<u8>`

#### Scenario: SVG flamegraph output
- **WHEN** `Pprof::flamegraph(duration, frequency)` is called
- **THEN** a CPU profile is collected via `collect`
- **AND** the resulting report is rendered as an SVG flamegraph
- **AND** the SVG bytes are returned as `Vec<u8>`

### Requirement: Profiling Error Handling (ic-pprof)

The profiling system provides typed error handling via the Error enum.

#### Scenario: Profile already in progress
- **WHEN** profiling fails because another profile is already running
- **THEN** an `Error::Pprof` variant is returned wrapping the underlying `pprof::Error`

#### Scenario: Protobuf encoding failure
- **WHEN** pprof protobuf encoding fails
- **THEN** an `Error::Encode` variant is returned wrapping the `prost::EncodeError`

#### Scenario: Internal blocking task failure
- **WHEN** the `spawn_blocking` task panics or is cancelled
- **THEN** an `Error::Internal` variant is returned

### Requirement: PprofCollector Trait (ic-pprof)

The `PprofCollector` trait provides an abstraction for CPU profiling implementations.

#### Scenario: Default implementation
- **WHEN** a component needs CPU profiling capabilities
- **THEN** it depends on the `PprofCollector` trait which provides async `profile` and `flamegraph` methods
- **AND** the default implementation is `Pprof` (a unit struct deriving Default)
- **AND** alternative implementations can be provided for testing or custom profiling behavior

#### Scenario: Trait bound requirements
- **WHEN** a type implements `PprofCollector`
- **THEN** it must also be `Send + Sync`
- **AND** both methods are async (require `#[async_trait]`)

---

### Requirement: ReloadHandles for Dynamic Tracing Layers (ic-tracing)

The IC tracing crate provides dynamic layer management for the `tracing` ecosystem, enabling on-demand distributed tracing with runtime-configurable layers.

#### Scenario: ReloadHandles initialization
- **WHEN** a `ReloadHandles` is created with a `Handle<Vec<BoxedRegistryLayer>, Registry>`
- **THEN** it wraps a `tracing_subscriber::reload::Handle` for dynamic layer management
- **AND** the handle allows adding and removing tracing layers at runtime without restarting the subscriber

#### Scenario: Pushing a new tracing layer
- **WHEN** `ReloadHandles::push(layer)` is called with a boxed `Layer<Registry>`
- **THEN** the layer is inserted at position 0 (front) of the active layer stack
- **AND** the layer stack can contain at most 5 elements (enforced by an external concurrency rate limiter)
- **AND** errors during modification are silently ignored

#### Scenario: Removing the oldest tracing layer
- **WHEN** `ReloadHandles::pop()` is called
- **THEN** the last (oldest) layer is removed from the active layer stack
- **AND** errors during modification are silently ignored
- **AND** this enables bounded resource usage for temporary tracing sessions

#### Scenario: ReloadHandles is Clone
- **WHEN** a ReloadHandles instance is cloned
- **THEN** the clone shares the same underlying reload handle
- **AND** modifications via either handle affect the same layer stack

### Requirement: Dynamic Dispatch for Tracing Layer Types (ic-tracing)

The tracing system uses type-erased layers for flexibility.

#### Scenario: BoxedRegistryLayer type erasure
- **WHEN** tracing layers need to be managed dynamically
- **THEN** layers are boxed as `Box<dyn Layer<Registry> + Send + Sync>` (type-erased `BoxedRegistryLayer`)
- **AND** this allows different layer implementations (Jaeger export, console output, buffer capture) to coexist in the same stack

### Requirement: SharedBuffer for Tracing Output (ic-tracing)

The SharedBuffer provides thread-safe buffered output for tracing data.

#### Scenario: SharedBuffer write
- **WHEN** data is written to a `SharedBuffer` via the `Write` trait
- **THEN** the data is appended to the internal `Arc<Mutex<Vec<u8>>>`
- **AND** the full buffer length is returned as the write count
- **AND** flush is a no-op that always succeeds

#### Scenario: SharedBuffer reset
- **WHEN** `reset()` is called on a SharedBuffer
- **THEN** the buffer is atomically drained and returned as `Vec<u8>`
- **AND** the internal buffer is left empty
- **AND** this is used to capture tracing output for HTTP response delivery

#### Scenario: SharedBuffer is Clone
- **WHEN** a SharedBuffer is cloned
- **THEN** both instances share the same underlying `Arc<Mutex<Vec<u8>>>`
- **AND** writes to either instance are visible to readers of both

---

### Requirement: Adapter Metrics Client (ic-adapter-metrics-client)

The adapter metrics client fetches Prometheus metrics from remote process adapters that expose a Unix Domain Socket (UDS) gRPC endpoint.

#### Scenario: AdapterMetrics construction
- **WHEN** `AdapterMetrics::new(name, uds_path, rt_handle)` is called
- **THEN** a gRPC channel is lazily connected to the specified UDS path
- **AND** the adapter is identified by its unique name
- **AND** the provided Tokio runtime handle is used for async operations

#### Scenario: Scrape metrics from adapter
- **WHEN** `scrape(timeout)` is called on an AdapterMetrics instance
- **THEN** a gRPC `ScrapeRequest` is sent to the adapter's metrics service
- **AND** the request has the specified timeout
- **AND** the response contains serialized `MetricFamily` entries

#### Scenario: Metric name prefixing
- **WHEN** metrics are received from an adapter scrape
- **THEN** each `MetricFamily` name is prefixed with `adapter_{name}_` where `{name}` is the adapter's unique name
- **AND** this prevents name collisions between adapters and replica metrics

#### Scenario: Scrape failure handling
- **WHEN** the adapter is unreachable or returns an error
- **THEN** a `tonic::Status` error is returned
- **AND** the calling code can handle the error gracefully without panicking

#### Scenario: AdapterMetrics is Clone
- **WHEN** an AdapterMetrics instance is cloned
- **THEN** the clone shares the same underlying gRPC channel (Channel is cheap to clone)

### Requirement: Adapter Metrics Server (ic-adapter-metrics-server)

The adapter metrics server provides a gRPC endpoint that exposes local Prometheus metrics from an adapter process.

#### Scenario: Start metrics gRPC server
- **WHEN** `start_metrics_grpc(metrics, logger, stream)` is called
- **THEN** a gRPC server is spawned on a Tokio task
- **AND** it listens on the provided stream (which can be a UDS listener or any AsyncRead/AsyncWrite)
- **AND** the `AdapterMetricsServiceServer` handles scrape requests

#### Scenario: Handle scrape request
- **WHEN** a `ScrapeRequest` is received by the server
- **THEN** the local `MetricsRegistry`'s Prometheus registry is gathered
- **AND** each MetricFamily is serialized to protobuf bytes
- **AND** the serialized bytes are returned in a `ScrapeResponse`

#### Scenario: Serialization failure
- **WHEN** a MetricFamily fails to serialize to bytes
- **THEN** a `Status::Internal` error with message "Failed to serialize metrics" is returned

#### Scenario: Server crash handling
- **WHEN** the gRPC server encounters a fatal error
- **THEN** the error is logged via the ReplicaLogger
- **AND** the adapter process is not panicked (the server error is contained)

### Requirement: Adapter Metrics Service Definition (ic-adapter-metrics-service)

The adapter metrics service defines the gRPC protocol for scraping adapter metrics.

#### Scenario: Service protocol definition
- **WHEN** the `ic-adapter-metrics-service` crate is built
- **THEN** prost-build and tonic-build generate Rust types from the proto definition
- **AND** `ScrapeRequest` and `ScrapeResponse` types are generated
- **AND** `AdapterMetricsServiceClient` and `AdapterMetricsServiceServer` are generated
- **AND** the `ScrapeResponse` contains a `metrics` field with `Vec<Vec<u8>>` (serialized MetricFamily entries)

### Requirement: Adapter Metrics Registry Integration (ic-metrics)

The AdapterMetricsRegistry within ic-metrics coordinates scraping of all registered adapters.

#### Scenario: Register adapter
- **WHEN** an AdapterMetrics instance is registered via `register(adapter_metrics)`
- **THEN** the adapter is added to the internal list
- **AND** if an adapter with the same name is already registered, `Error::AlreadyReg` is returned

#### Scenario: Gather metrics from all adapters
- **WHEN** `gather(timeout)` is called
- **THEN** all registered adapters are scraped concurrently via `join_all`
- **AND** the scrape_duration histogram records per-adapter timing with labels [adapter_name, status_code]
- **AND** successful scrapes use "success" as the status
- **AND** failed scrapes use the tonic error code string as the status
- **AND** results from all successful scrapes are flattened into a single Vec<MetricFamily>

#### Scenario: Adapter registry scrape metrics
- **WHEN** the `AdapterMetricsScrapeMetrics` is initialized
- **THEN** a `adapter_metrics_scrape_duration_seconds` histogram is registered
- **AND** the histogram uses decimal buckets from 0.001s to 0.5s plus a 10s bucket
- **AND** labels are [adapter, status_code]

---

### Requirement: Process-Level Metrics (ic-metrics, Linux only)

On Linux, the metrics system exposes OS-level process metrics via /proc.

#### Scenario: Process collector registration
- **WHEN** `MetricsRegistry::global()` is called on Linux
- **THEN** a `ProcessCollector` is registered with the Prometheus registry
- **AND** the collector exposes `process_threads` and other `/proc`-derived metrics
- **AND** duplicate registration attempts are silently ignored (`.ok()` on the Result)
