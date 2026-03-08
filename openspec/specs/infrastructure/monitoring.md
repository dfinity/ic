# Monitoring

**Crates**: `ic-metrics-tool`, `ic-tracing-jaeger-exporter`, `ic-dashboard`

The monitoring subsystem provides metrics collection, logging, distributed tracing, and CPU profiling capabilities for the Internet Computer replica and its components. It is designed around the Prometheus metrics ecosystem with support for adapter metrics from external processes.

## Requirements

### Requirement: Metrics Registry
The metrics system uses a centralized registry for creating and collecting metrics, avoiding Prometheus static globals to enable testing.

#### Scenario: Global metrics registry
- **WHEN** `MetricsRegistry::global()` is called
- **THEN** the Prometheus default registry is returned wrapped in a `MetricsRegistry`
- **AND** on Linux, a `ProcessCollector` is registered for process-level metrics including thread count
- **AND** an `AdapterMetricsRegistry` is created for scraping metrics from remote adapter processes

#### Scenario: New isolated metrics registry
- **WHEN** `MetricsRegistry::new()` is called
- **THEN** a fresh empty Prometheus registry is created
- **AND** this is useful for testing where metrics isolation is needed

#### Scenario: Metric type creation helpers
- **WHEN** metrics need to be created
- **THEN** the registry provides helper methods for all Prometheus metric types:
  - `histogram(name, help, buckets)` for latency/duration distributions
  - `histogram_vec(name, help, buckets, labels)` for labeled histograms
  - `int_gauge(name, help)` for integer gauges
  - `int_gauge_vec(name, help, labels)` for labeled integer gauges
  - `gauge(name, help)` for floating-point gauges
  - `gauge_vec(name, help, labels)` for labeled floating-point gauges
  - `int_counter(name, help)` for monotonic integer counters
  - `int_counter_vec(name, help, labels)` for labeled integer counters
- **AND** all metrics are automatically registered with the underlying Prometheus registry

### Requirement: Adapter Metrics
The metrics system supports collecting Prometheus metrics from external adapter processes (e.g., Bitcoin adapter, HTTPS outcalls adapter).

#### Scenario: Adapter metrics registration
- **WHEN** an adapter process needs to expose metrics
- **THEN** an `AdapterMetricsRegistry` manages the collection of metrics from remote processes
- **AND** adapter metrics are scraped via a dedicated endpoint

#### Scenario: Adapter metrics client
- **WHEN** the metrics endpoint is scraped
- **THEN** the `AdapterMetrics` client fetches metrics from each registered adapter
- **AND** results are merged with the local metrics registry

#### Scenario: Adapter metrics server
- **WHEN** an adapter process starts
- **THEN** it exposes a gRPC service (defined in protobuf) for reporting metrics
- **AND** the server collects metrics from the adapter's internal registry

### Requirement: Histogram Buckets
The metrics system provides predefined bucket configurations for common measurement patterns.

#### Scenario: Custom bucket configurations
- **WHEN** histograms are created for different use cases
- **THEN** the `buckets` module provides appropriate bucket boundaries
- **AND** these cover common patterns like latency distributions (microseconds to seconds)

### Requirement: Histogram Vec Timer
A convenience type for timing operations and recording the duration in a histogram.

#### Scenario: Timer-based histogram recording
- **WHEN** an operation needs to be timed
- **THEN** a `HistogramVecTimer` is created with a reference to a `HistogramVec`
- **AND** when the timer is dropped, the elapsed duration is recorded in the appropriate histogram bucket

### Requirement: Process Collector (Linux)
On Linux systems, additional process-level metrics are collected beyond what the default Prometheus process collector provides.

#### Scenario: Thread count metric
- **WHEN** the process collector runs on Linux
- **THEN** it collects the `process_threads` metric showing the number of OS threads
- **AND** this supplements the default Prometheus process collector metrics

### Requirement: Tokio Metrics Collector
Metrics about Tokio runtime performance are collected for monitoring async task execution.

#### Scenario: Tokio runtime metrics
- **WHEN** Tokio runtimes are running
- **THEN** the `TokioMetricsCollector` collects runtime metrics
- **AND** these include worker thread utilization, task counts, and scheduling latency

### Requirement: Logging
The logging system provides structured, asynchronous logging with configurable destinations and formats.

#### Scenario: Replica logger creation
- **WHEN** `new_replica_logger_from_config` is called with a `LoggerConfig`
- **THEN** a `ReplicaLogger` is created wrapping an slog `Logger`
- **AND** an `AsyncGuard` is returned that must be held to ensure log flushing

#### Scenario: Priority-based log handling
- **WHEN** log messages are emitted
- **THEN** high-priority messages (Error and Critical) are written synchronously to prevent loss on crash
- **AND** lower-priority messages are written asynchronously to minimize latency impact

#### Scenario: Async overflow strategy
- **WHEN** the async log buffer is full
- **THEN** in normal operation, messages are dropped and a report is logged (OverflowStrategy::DropAndReport)
- **AND** in system test environments (when `block_on_overflow` is true), logging blocks to prevent message loss

#### Scenario: Log format selection
- **WHEN** the log format is configured
- **THEN** `LogFormat::Json` produces JSON-formatted log output using `slog_json`
- **AND** `LogFormat::TextFull` produces human-readable text with UTC timestamps using `slog_term`

#### Scenario: Log destination selection
- **WHEN** the log destination is configured
- **THEN** `LogDestination::Stdout` writes to standard output
- **AND** `LogDestination::Stderr` writes to standard error
- **AND** `LogDestination::File(path)` writes to the specified file

#### Scenario: Async log buffer
- **WHEN** the async logger is initialized
- **THEN** the channel size is set to 10,240 entries
- **AND** the background thread name is configurable (defaults to "logger")

#### Scenario: No-op logger for testing
- **WHEN** `no_op_logger()` is called
- **THEN** a `ReplicaLogger` that discards all messages is returned
- **AND** this is useful for unit tests that do not need log output

### Requirement: Context Logger
The context logger provides a mechanism for adding contextual information to log messages.

#### Scenario: Context-aware logging
- **WHEN** logging within a specific context (e.g., a canister execution)
- **THEN** the context logger adds relevant key-value pairs to all log messages
- **AND** macros are provided for convenient context-aware logging

### Requirement: Distributed Tracing
The tracing system supports distributed tracing with configurable exporters.

#### Scenario: Tracing reload handles
- **WHEN** the tracing system is initialized
- **THEN** `ReloadHandles` provides a mechanism to dynamically add and remove tracing layers
- **AND** layers can be pushed (up to 5 concurrent layers, controlled by a rate limiter)
- **AND** layers can be popped (removed in LIFO order)

#### Scenario: Jaeger exporter
- **WHEN** Jaeger tracing export is enabled
- **THEN** the `jaeger_exporter` creates a tracing layer that exports spans to a Jaeger collector
- **AND** the layer is added to the reload handles for dynamic management

#### Scenario: Logging layer for tracing
- **WHEN** tracing-to-logging bridge is needed
- **THEN** the `logging_layer` creates a tracing layer that emits trace events as log messages
- **AND** this bridges the tracing and slog logging systems

#### Scenario: Tracing utilities
- **WHEN** working with the tracing system
- **THEN** the `utils` module provides helper functions for common tracing operations

### Requirement: CPU Profiling (pprof)
The pprof system provides in-process CPU profiling for performance analysis.

#### Scenario: CPU profile collection
- **WHEN** `collect(duration, frequency)` is called
- **THEN** a `ProfilerGuard` starts sampling the CPU at the given frequency (Hz)
- **AND** profiling runs for the specified duration
- **AND** a `Report` is generated with thread names normalized (numbers stripped, separators replaced with dashes)

#### Scenario: Protobuf profile output
- **WHEN** `Pprof::profile(duration, frequency)` is called
- **THEN** a CPU profile is collected and encoded in pprof protobuf format
- **AND** the result can be analyzed with standard pprof tools

#### Scenario: Flamegraph output
- **WHEN** `Pprof::flamegraph(duration, frequency)` is called
- **THEN** a CPU profile is collected and rendered as an SVG flamegraph
- **AND** the SVG can be viewed in a browser for visual performance analysis

#### Scenario: Thread name normalization
- **WHEN** profiling data is post-processed
- **THEN** thread names like "Main_Thread42" are normalized to "main-thread"
- **AND** trailing numbers, underscores, and spaces are cleaned up for better aggregation

#### Scenario: Non-blocking profiler initialization
- **WHEN** the profiler guard is created
- **THEN** it is spawned via `spawn_blocking` to avoid blocking the Tokio runtime
- **AND** the guard has a latency of 40-60 milliseconds for initialization
