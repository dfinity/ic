# HTTP Endpoints XNet Specification

- **Crate**: `ic-http-endpoints-xnet`
- **Source**: `rs/http_endpoints/xnet/`
- **Purpose**: Provides the HTTPS endpoint through which IC replica nodes serve cross-subnet (XNet) stream slices to other subnets. This enables the IC's cross-subnet messaging protocol by allowing a replica on one subnet to fetch certified stream data from a replica on another subnet.

## Requirements

### Requirement: XNet Endpoint Lifecycle

The XNet endpoint starts an HTTPS server that listens for incoming stream slice requests and shuts down gracefully.

#### Scenario: Endpoint creation and startup
- **WHEN** `XNetEndpoint::new` is called with a runtime handle, certified stream store, TLS config, registry client, and configuration
- **THEN** a TCP listener is started on the configured address (`xnet_ip_addr:xnet_port`)
- **AND** an axum router is created with a catch-all handler for all HTTP methods
- **AND** the actual bound address is recorded (which may differ from requested if port 0 was used)
- **AND** an info log message "XNet Endpoint listening on {address}" is emitted

#### Scenario: Fallback to localhost on invalid IP
- **WHEN** the configured `xnet_ip_addr` cannot be parsed as a valid IP address
- **THEN** the endpoint falls back to `127.0.0.1:0`
- **AND** the server starts on a random available port on localhost

#### Scenario: Graceful shutdown on drop
- **WHEN** the `XNetEndpoint` is dropped
- **THEN** a shutdown notification is sent via the internal `Notify` mechanism
- **AND** the HTTP server performs a graceful shutdown, completing in-flight requests
- **AND** info log messages "Shutting down XNet endpoint" and "XNet Endpoint shut down" are emitted

---

### Requirement: API Endpoint - List Streams

The `/api/v1/streams` endpoint returns a list of all subnet IDs for which certified streams are available.

#### Scenario: List available streams
- **WHEN** a request is made to `/api/v1/streams`
- **THEN** `CertifiedStreamStore::subnets_with_certified_streams()` is called
- **AND** the response is a JSON array of subnet ID strings
- **AND** the response has Content-Type `application/json` and status 200
- **AND** the response size is recorded in the `xnet_endpoint_response_size_bytes` histogram under the `streams` resource label

---

### Requirement: API Endpoint - Fetch Stream Slice

The `/api/v1/stream/{SubnetId}` endpoint returns a certified stream slice for the specified subnet.

#### Scenario: Fetch stream slice with all parameters
- **WHEN** a request is made to `/api/v1/stream/{SubnetId}?witness_begin={StreamIndex}&msg_begin={StreamIndex}&msg_limit={usize}&byte_limit={usize}`
- **THEN** `CertifiedStreamStore::encode_certified_stream_slice()` is called with the provided subnet ID, witness begin, message begin, message limit, and byte limit
- **AND** the response is a Protobuf-encoded `CertifiedStreamSlice`
- **AND** the response has Content-Type `application/x-protobuf`, header `X-Protobuf-Schema: certified_stream_slice.proto`, and header `X-Protobuf-Message: xnet.v1.CertifiedStreamSlice`
- **AND** the slice payload size is recorded in the `xnet_endpoint_slice_payload_size_bytes` histogram
- **AND** the response size is recorded under the `stream` resource label

#### Scenario: Fetch stream slice with default witness_begin
- **WHEN** a request is made to `/api/v1/stream/{SubnetId}?msg_begin={StreamIndex}` without a `witness_begin` parameter
- **THEN** `witness_begin` defaults to the value of `msg_begin`
- **AND** the stream slice is returned normally

#### Scenario: Fetch stream slice with no index parameters
- **WHEN** a request is made to `/api/v1/stream/{SubnetId}` without `msg_begin` or `witness_begin`
- **THEN** both `msg_begin` and `witness_begin` are passed as `None` to the certified stream store
- **AND** the store returns the stream slice starting from the stream's beginning

#### Scenario: Legacy index parameter support
- **WHEN** a request uses the `index` query parameter instead of `msg_begin`
- **THEN** the `index` value is treated as `msg_begin`
- **AND** the request is handled identically to using `msg_begin`

#### Scenario: No stream for subnet
- **WHEN** a request is made for a subnet ID that has no available stream
- **THEN** `encode_certified_stream_slice` returns `EncodeStreamError::NoStreamForSubnet`
- **AND** the response has status 204 No Content with an empty body

#### Scenario: Invalid slice begin (out of range)
- **WHEN** a request specifies a `msg_begin` that is outside the stream's message bounds
- **THEN** `encode_certified_stream_slice` returns `EncodeStreamError::InvalidSliceBegin`
- **AND** the response has status 416 Range Not Satisfiable
- **AND** the body contains an error message: "Requested slice begin {index} is outside of stream message bounds [{begin}, {end})"

#### Scenario: Invalid slice indices
- **WHEN** a request specifies invalid slice index parameters
- **THEN** `encode_certified_stream_slice` returns `EncodeStreamError::InvalidSliceIndices`
- **AND** the response has status 400 Bad Request

---

### Requirement: Request Validation and Error Handling

The endpoint validates incoming request URLs, parameters, and subnet IDs.

#### Scenario: Invalid subnet ID in URL path
- **WHEN** the subnet ID portion of `/api/v1/stream/{SubnetId}` cannot be parsed as a `PrincipalId`
- **THEN** the response has status 400 Bad Request
- **AND** the body contains "Invalid subnet ID: {subnet_id_str} in {stream_url}"

#### Scenario: Invalid query parameter value
- **WHEN** a query parameter value cannot be parsed as a `u64`
- **THEN** the response has status 400 Bad Request
- **AND** the body contains "Invalid query param: {param}"

#### Scenario: Unexpected query parameter
- **WHEN** a query parameter name is not one of `witness_begin`, `index`, `msg_begin`, `msg_limit`, or `byte_limit`
- **THEN** the response has status 400 Bad Request
- **AND** the body contains "Unexpected query param: {param}"

#### Scenario: Unknown API path
- **WHEN** a request is made to a path that does not match `/api/v1/streams` or `/api/v1/stream/...`
- **THEN** the response has status 404 Not Found
- **AND** the body contains "Not Found"
- **AND** the request duration is recorded under the `error` resource label

#### Scenario: Invalid URL construction
- **WHEN** the request URI cannot be joined with the base URL
- **THEN** a warning is logged with the message "Invalid URL {uri}: {error}"
- **AND** a 400 Bad Request response is returned

---

### Requirement: Concurrency Control

The endpoint limits the number of concurrent requests to prevent resource exhaustion.

#### Scenario: Request within concurrency limit
- **WHEN** a request arrives and a semaphore permit is available (limit: 4 concurrent requests)
- **THEN** the request is processed on a blocking Tokio task
- **AND** the semaphore permit is held for the duration of the request

#### Scenario: Request exceeding concurrency limit
- **WHEN** a request arrives but all 4 semaphore permits are taken
- **THEN** the response has status 503 Service Unavailable
- **AND** the body contains "Queue full"
- **AND** the request duration is recorded with a value of 0.0 under the `unknown` resource label and `503` status

#### Scenario: Parallel request execution
- **WHEN** multiple requests arrive simultaneously
- **THEN** up to `XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS` (4) requests execute in parallel
- **AND** requests are dispatched via `tokio::task::spawn_blocking` to avoid blocking the async runtime

---

### Requirement: TLS Configuration

The endpoint uses TLS for secure inter-node communication in production.

#### Scenario: TLS handshake in production
- **WHEN** a TCP connection is accepted in production mode
- **THEN** the latest registry version is fetched from the registry client
- **AND** a TLS server config is obtained from the crypto TLS component allowing connections from all nodes
- **AND** ALPN protocols are set to support both HTTP/2 (`h2`) and HTTP/1.1 (`http/1.1`)
- **AND** the connection is upgraded to TLS using `tokio_rustls::TlsAcceptor`

#### Scenario: TLS server config failure
- **WHEN** the TLS server config cannot be obtained from the crypto component
- **THEN** a warning is logged: "Failed to get server config from crypto {err}"
- **AND** the connection is dropped without serving a response

#### Scenario: TLS handshake failure
- **WHEN** the TLS handshake fails
- **THEN** a warning is logged: "Error setting up TLS stream: {err}"
- **AND** the `xnet_endpoint_closed_connections_total` counter is incremented

#### Scenario: No TLS in tests
- **WHEN** the endpoint is running in test mode (`#[cfg(test)]`)
- **THEN** TLS is bypassed and connections are served over plain TCP
- **AND** the TLS config and registry client are unused

---

### Requirement: Metrics Collection

The endpoint tracks operational metrics for monitoring and debugging.

#### Scenario: Request duration tracking
- **WHEN** any request is processed
- **THEN** the elapsed time is recorded in the `xnet_endpoint_request_duration_seconds` histogram
- **AND** the histogram is labeled with the resource type (`stream`, `streams`, `error`, `unknown`) and HTTP status code

#### Scenario: Slice payload size tracking
- **WHEN** a stream slice is successfully encoded
- **THEN** the payload size in bytes is recorded in the `xnet_endpoint_slice_payload_size_bytes` histogram

#### Scenario: Response size tracking
- **WHEN** a status-200 response is produced
- **THEN** the response body size in bytes is recorded in the `xnet_endpoint_response_size_bytes` histogram
- **AND** the histogram is labeled with the resource type (`stream` or `streams`)

#### Scenario: Connection counting
- **WHEN** a new TCP connection is accepted
- **THEN** the `xnet_endpoint_connections_total` counter is incremented

#### Scenario: Closed connection counting
- **WHEN** a connection fails during TLS handshake or HTTP serving
- **THEN** the `xnet_endpoint_closed_connections_total` counter is incremented
