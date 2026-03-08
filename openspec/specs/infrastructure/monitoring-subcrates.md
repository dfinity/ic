# Infrastructure: Monitoring Sub-crates

## Overview

This specification covers the adapter metrics client/server/service crates and the tracing logging layer, which together provide the monitoring infrastructure for IC replica process adapters.

---

## Crate: `ic-adapter-metrics-service`

**Path:** `rs/monitoring/adapter_metrics/service`

### Purpose

Defines the gRPC service interface for adapter metrics via protobuf. This crate generates the Rust types and service traits from a protobuf definition.

### Implementation

The crate's `lib.rs` includes the generated protobuf code:
```rust
include!(concat!(env!("OUT_DIR"), "/adapter_metrics.v1.rs"));
```

### Generated Types

- `ScrapeRequest` -- Empty request message for triggering a metrics scrape.
- `ScrapeResponse` -- Response containing serialized metrics: `{ metrics: Vec<Vec<u8>> }` where each byte vector is a protobuf-serialized `prometheus::proto::MetricFamily`.

### Generated Service Trait

- `AdapterMetricsService` -- gRPC service trait with a single RPC:
  - `scrape(ScrapeRequest) -> ScrapeResponse`

### Generated Client/Server

- `AdapterMetricsServiceClient` -- tonic-generated gRPC client.
- `AdapterMetricsServiceServer` -- tonic-generated gRPC server wrapper.

---

## Crate: `ic-adapter-metrics-client`

**Path:** `rs/monitoring/adapter_metrics/client`

### Purpose

A gRPC client that fetches Prometheus metrics from remote process adapters (e.g., the Bitcoin adapter, HTTPS outcalls adapter) over Unix Domain Sockets (UDS).

### Public Types

#### `AdapterMetrics`

```
#[derive(Clone)]
pub struct AdapterMetrics {
    name: &'static str,
    channel: Channel,
}
```

A cheaply cloneable metrics client (tonic `Channel` is cheaply cloneable per its documentation).

**Constructor:**
```
pub fn new(name: &'static str, uds_path: PathBuf, rt_handle: tokio::runtime::Handle) -> Self
```

- `name` -- Unique adapter identifier (e.g., `"btc"`, `"https_outcalls"`). Used as a metrics prefix.
- `uds_path` -- Path to the Unix Domain Socket where the adapter's metrics server listens.
- `rt_handle` -- Tokio runtime handle for async operations.

**Connection:** Uses `tonic::transport::Endpoint` with a lazy UDS connector. The HTTP URI `http://[::]:50152` is a placeholder (ignored by UDS transport). The `ExecuteOnTokioRuntime` executor ensures gRPC operations run on the provided runtime.

**Methods:**

| Method | Description |
|---|---|
| `get_name() -> &str` | Returns the adapter name. |
| `scrape(timeout: Duration) -> Result<Vec<MetricFamily>, Status>` | Fetches metrics from the adapter with the given timeout. |

### Metric Name Prefixing

All metric families returned by `scrape()` are prefixed with `adapter_<name>_` to avoid Prometheus metric name collisions. For example, a metric `requests_total` from the `btc` adapter becomes `adapter_btc_requests_total`.

### Error Handling

Returns `tonic::Status` on gRPC errors. Each `MetricFamily` is deserialized from protobuf bytes using `protobuf::Message::parse_from_bytes`; parse failures result in a default (empty) `MetricFamily`.

### Debug Implementation

`Debug` for `AdapterMetrics` shows only the `name` field (using `finish_non_exhaustive()`).

---

## Crate: `ic-adapter-metrics-server`

**Path:** `rs/monitoring/adapter_metrics/server`

### Purpose

A gRPC server that serves local Prometheus metrics from a process adapter over any async transport stream (typically a Unix Domain Socket listener).

### Internal Types

#### `Metrics`

```
struct Metrics {
    metrics: MetricsRegistry,
}
```

Implements `AdapterMetricsService`:
- `scrape()` gathers all metric families from the `MetricsRegistry`'s Prometheus registry.
- Each `MetricFamily` is serialized to protobuf bytes via `write_to_bytes()`.
- On serialization failure, returns `Status::Internal`.

### Public Functions

#### `start_metrics_grpc`

```
pub fn start_metrics_grpc<T, E>(
    metrics: MetricsRegistry,
    logger: ReplicaLogger,
    stream: impl Stream<Item = Result<T, E>> + Send + 'static,
)
where
    T: Send + Sync + Unpin + AsyncRead + AsyncWrite + Connected + 'static,
    E: Send + Sync + Unpin + Error + 'static,
```

Spawns a tokio task that runs a tonic gRPC server using the provided stream as the transport layer.

**Parameters:**
- `metrics` -- The `MetricsRegistry` whose Prometheus metrics will be served.
- `logger` -- `ReplicaLogger` for error reporting.
- `stream` -- An async stream of connections (e.g., from `tokio::net::UnixListener`).

**Behavior:**
- Creates an `AdapterMetricsServiceServer` wrapping the local `Metrics` instance.
- Calls `tonic::Server::builder().add_service(...).serve_with_incoming(stream)`.
- If the server crashes, logs the error but does **not** panic the adapter process.

---

## Crate: `ic-tracing-logging-layer`

**Path:** `rs/monitoring/tracing/logging_layer`

### Purpose

Constructs a `tracing_subscriber` formatting layer configured according to the IC logging configuration. Supports JSON and full-text log formats with configurable output destinations.

### Public Functions

#### `logging_layer`

```
pub fn logging_layer(
    config: &LoggingConfig,
    node_id: NodeId,
    subnet_id: SubnetId,
) -> (impl Layer<Registry> + Send + Sync, Option<WorkerGuard>)
```

Returns a tracing subscriber layer and an optional `WorkerGuard` (for non-blocking writers).

**Parameters:**
- `config` -- IC logging configuration specifying format, destination, level, and overflow behavior.
- `node_id` -- The node ID (stored but not yet used in formatting; reserved for future use).
- `subnet_id` -- The subnet ID (stored but not yet used in formatting; reserved for future use).

### Configuration Mapping

#### Log Format (`config.format`)

| `LogFormat` | Behavior |
|---|---|
| `Json` | Uses `tracing_subscriber::fmt::format::json()` with flattened events, UTC RFC 3339 timestamps, level, file, and line number. |
| `TextFull` | Uses `tracing_subscriber::fmt::format()` with UTC RFC 3339 timestamps, level, file, and line number. |

#### Log Destination (`config.log_destination`)

| `LogDestination` | Writer |
|---|---|
| `Stderr` | `std::io::stderr()` |
| `Stdout` | `std::io::stdout()` |
| `File(path)` | `std::fs::File::create(path)` (panics on failure). |

#### Overflow Behavior (`config.block_on_overflow`)

| Value | Behavior |
|---|---|
| `true` | Uses the writer directly (blocking on slow writes). No `WorkerGuard` returned. |
| `false` | Wraps the writer in `tracing_appender::non_blocking()` for async writes. Returns a `WorkerGuard` that must be held alive to ensure log flushing on shutdown. |

#### Log Level (`config.level`)

| IC `Level` | `tracing` `LevelFilter` |
|---|---|
| `Trace` | `TRACE` |
| `Debug` | `DEBUG` |
| `Info` | `INFO` |
| `Warning` | `WARN` |
| `Error` | `ERROR` |
| `Critical` | `ERROR` (mapped; TODO: remove this level) |

### Internal Types

#### `Formatter`

Wraps either a JSON or full-text formatter and implements `FormatEvent<S, N>` for the `tracing_subscriber` layer. The `node_id` and `subnet_id` are stored on the formatter but currently delegated transparently to the inner format.

#### `InnerFormat`

```
enum InnerFormat {
    Full(fmt::format::Format<Full, UtcTime<Rfc3339>>),
    Json(fmt::format::Format<Json, UtcTime<Rfc3339>>),
}
```
