# HTTP Endpoints

**Crates**: `ic-http-endpoints-public`, `ic-http-endpoints-metrics`, `ic-http-endpoints-async-utils`, `ic-read-state-response-parser`

## Requirements

### Requirement: HTTP Server Lifecycle

The HTTP server accepts both TLS-encrypted and plaintext connections, serving the IC public API and internal endpoints.

#### Scenario: Server startup
- **WHEN** the HTTP server is started
- **THEN** a TCP listener is bound to the configured address
- **AND** the health status is set to `Starting`
- **AND** a background task waits for certified state availability
- **AND** once certified state is available, status transitions to `WaitingForCertifiedState`

#### Scenario: Server initialization sequence
- **WHEN** the server is initializing
- **THEN** it first waits for certified state to become available
- **AND** then waits for the initial NNS certificate delegation
- **AND** only after both are available does it set health status to `Healthy`

#### Scenario: TLS connection handling
- **WHEN** a new TCP connection arrives with a TLS handshake byte (0x16)
- **THEN** TLS is negotiated using the node's server config (without client auth)
- **AND** ALPN protocols `h2` and `http/1.1` are advertised
- **AND** the connection proceeds as HTTPS

#### Scenario: Plaintext connection handling
- **WHEN** a new TCP connection arrives without a TLS handshake byte
- **THEN** the connection is handled as plain HTTP
- **AND** connection duration is tracked with the "insecure" label

#### Scenario: Connection read timeout
- **WHEN** a connection does not send any data within the configured read timeout
- **THEN** the connection is closed
- **AND** the `connection_setup_duration` metric is recorded with a timeout error label

#### Scenario: Port file creation
- **WHEN** a `port_file_path` is configured and the server binds to a port
- **THEN** the assigned port number is atomically written to the specified file path

#### Scenario: HTTP/2 concurrent streams limit
- **WHEN** serving an HTTP/2 connection
- **THEN** the maximum number of concurrent streams is limited to `http_max_concurrent_streams`

### Requirement: Call Endpoint (Ingress Messages)

Handles submission of update calls (ingress messages) to canisters.

#### Scenario: Asynchronous call (v2)
- **WHEN** a POST request is received at `/api/v2/canister/{effective_canister_id}/call`
- **THEN** the ingress message is validated (signature, size, canister willingness)
- **AND** the message is submitted to the ingress pool
- **AND** HTTP 202 Accepted is returned immediately

#### Scenario: Synchronous call (v3)
- **WHEN** a POST request is received at `/api/v3/canister/{effective_canister_id}/call`
- **THEN** the ingress message is validated and submitted
- **AND** the handler waits for the message to be certified (up to the configured timeout)
- **AND** if certified in time, a CBOR response with the certificate is returned
- **AND** if not certified in time, HTTP 202 Accepted is returned with a timeout explanation

#### Scenario: Synchronous call (v4)
- **WHEN** a POST request is received at `/api/v4/canister/{effective_canister_id}/call`
- **THEN** behavior is identical to v3 except the NNS delegation uses tree format for canister ranges

#### Scenario: Duplicate synchronous call detection
- **WHEN** a v3/v4 call request is received for a message ID already in certified state
- **THEN** the certificate is returned immediately without re-submitting the message

#### Scenario: Ingress pool full load shedding
- **WHEN** the ingress pool exceeds its threshold
- **THEN** the request is rejected with HTTP 503 Service Unavailable
- **AND** the message "Service is overloaded, try again later." is returned

#### Scenario: Ingress channel full load shedding
- **WHEN** the ingress channel capacity is zero (channel is full)
- **THEN** the request is rejected with HTTP 503 Service Unavailable

#### Scenario: Canister ID mismatch validation
- **WHEN** the `canister_id` in the message body does not match the `effective_canister_id` in the URL
- **AND** the canister_id is not the management canister (ic_00)
- **THEN** the request is rejected with HTTP 400 Bad Request

#### Scenario: Ingress message size validation
- **WHEN** the ingress message exceeds `max_ingress_bytes_per_message` from the registry
- **THEN** the request is rejected with HTTP 413 Payload Too Large

#### Scenario: Signature validation
- **WHEN** the ingress message signature is invalid
- **THEN** the request is rejected with the appropriate HTTP error

#### Scenario: Canister ingress filter check
- **WHEN** the canister rejects the ingress message via the ingress filter
- **THEN** the user error from the canister is returned in the response

### Requirement: Ingress Watcher

Tracks ingress messages from submission through certification to enable synchronous call responses.

#### Scenario: Subscription for certification
- **WHEN** a sync call handler subscribes to track a message ID
- **THEN** an `IngressCertificationSubscriber` is returned that can wait for certification
- **AND** the message is tracked in the internal state

#### Scenario: Duplicate subscription rejection
- **WHEN** a subscription for an already-tracked message ID is attempted
- **THEN** a `DuplicateSubscriptionError` is returned

#### Scenario: Message execution completion
- **WHEN** an ingress message completes execution at a certain height
- **THEN** the message status is updated from `InProgress` to `Completed(height)`

#### Scenario: Certification notification
- **WHEN** the certified height advances past a message's completion height
- **THEN** all subscribers waiting on that message are notified via `Notify`
- **AND** the message is removed from the tracking state

#### Scenario: Subscription cancellation on drop
- **WHEN** the `IngressCertificationSubscriber` is dropped before certification
- **THEN** the subscription is cancelled via a `CancellationToken`
- **AND** the message tracking state is cleaned up

#### Scenario: Lower certification height ignored
- **WHEN** a certification height notification is received that is lower than the current certified height
- **THEN** the lower height is ignored and the certified height is not decreased

### Requirement: Query Endpoint

Handles query calls to canisters with signed responses.

#### Scenario: Query execution (v2)
- **WHEN** a POST request is received at `/api/v2/canister/{effective_canister_id}/query`
- **THEN** the request is deserialized from CBOR
- **AND** the signature is validated against the registry
- **AND** the query is executed via the query execution service
- **AND** the response is signed by the node and returned as CBOR with NNS delegation (flat format)

#### Scenario: Query execution (v3)
- **WHEN** a POST request is received at `/api/v3/canister/{effective_canister_id}/query`
- **THEN** behavior is identical to v2 except the NNS delegation uses tree format for canister ranges

#### Scenario: Unhealthy replica query rejection
- **WHEN** a query request is received and the replica health status is not `Healthy`
- **THEN** HTTP 503 Service Unavailable is returned
- **AND** the response message includes the current health status

#### Scenario: Query canister ID mismatch
- **WHEN** the `canister_id` in the query does not match the `effective_canister_id` in the URL
- **AND** the canister_id is not the management canister
- **THEN** the request is rejected with HTTP 400 Bad Request

#### Scenario: Query response signing
- **WHEN** a query is successfully executed
- **THEN** the response is hashed and signed by the node's basic signer
- **AND** the signed response includes the node signature, timestamp, and node identity

#### Scenario: Query signing failure
- **WHEN** the node fails to sign the query response
- **THEN** HTTP 500 Internal Server Error is returned

### Requirement: Read State Endpoint

Provides certified state data to clients via the read_state API.

#### Scenario: Canister read state (v2)
- **WHEN** a POST request is received at `/api/v2/canister/{effective_canister_id}/read_state`
- **THEN** the requested state paths are validated
- **AND** a certificate with the matching certified state tree is returned
- **AND** a "time" path is always included in the response

#### Scenario: Canister read state (v3)
- **WHEN** a POST request is received at `/api/v3/canister/{effective_canister_id}/read_state`
- **THEN** behavior is identical to v2 except deprecated canister ranges paths are pruned for non-NNS subnets

#### Scenario: Subnet read state (v2)
- **WHEN** a POST request is received at `/api/v2/subnet/{subnet_id}/read_state`
- **THEN** subnet-level state paths are served with the NNS delegation (flat format)

#### Scenario: Subnet read state (v3)
- **WHEN** a POST request is received at `/api/v3/subnet/{subnet_id}/read_state`
- **THEN** behavior is identical to v2 except the NNS delegation uses tree format

#### Scenario: Certified state unavailable
- **WHEN** certified state is not yet available
- **THEN** HTTP 503 Service Unavailable is returned
- **AND** the message says "Certified state is not available yet. Please try again..."

#### Scenario: Path too long
- **WHEN** a read_state request includes a path that exceeds the maximum allowed depth
- **THEN** HTTP 400 Bad Request is returned with message "Failed to parse requested paths: path is too long."

### Requirement: Status Endpoint

Provides replica health and version information.

#### Scenario: Status response
- **WHEN** a GET request is received at `/api/v2/status`
- **THEN** a CBOR-encoded `HttpStatusResponse` is returned containing:
  - The root public key (NNS threshold key in DER format)
  - The replica implementation version
  - The replica binary hash (if available)
  - The current health status
  - The latest certified height

### Requirement: Dashboard Endpoint

Provides a human-readable HTML dashboard showing replica state.

#### Scenario: Dashboard rendering
- **WHEN** a GET request is received at `/_/dashboard`
- **THEN** the latest replicated state is read
- **AND** an HTML page is rendered showing subnet type, configuration, height, canisters, and replica version

#### Scenario: Dashboard redirect
- **WHEN** a GET request is received at `/` or `/_/`
- **THEN** a temporary redirect (HTTP 307) to `/_/dashboard` is returned

### Requirement: Health Status Management

The replica health status is dynamically updated based on the state of consensus and certified state.

#### Scenario: Certified state behind detection
- **WHEN** the certified state height significantly lags behind the finalized block height
- **AND** the current health status is `Healthy`
- **THEN** the health status transitions to `CertifiedStateBehind`

#### Scenario: Certified state caught up
- **WHEN** the certified state height is no longer behind the finalized height
- **AND** the current health status is `CertifiedStateBehind`
- **THEN** the health status transitions back to `Healthy`

#### Scenario: Health status atomic transitions
- **WHEN** a health status transition is attempted
- **THEN** it uses `compare_exchange` to ensure only valid transitions occur
- **AND** concurrent requests see consistent health status (lock-free atomic)

### Requirement: Request Size and Rate Limiting

The HTTP server enforces various limits to protect against resource exhaustion.

#### Scenario: Request body size limit
- **WHEN** a request body exceeds `max_request_size_bytes`
- **THEN** HTTP 413 Payload Too Large is returned

#### Scenario: Concurrent request limiting per endpoint
- **WHEN** the number of concurrent requests for an endpoint exceeds its configured limit
- **THEN** HTTP 429 Too Many Requests is returned for the excess requests
- **AND** other endpoints are not affected by one endpoint being at capacity

#### Scenario: Independent endpoint concurrency
- **WHEN** the query endpoint is at its concurrency limit
- **THEN** requests to the catch-up package endpoint are still accepted (different limit)

#### Scenario: Global request timeout
- **WHEN** a request processing takes longer than `request_timeout_seconds`
- **THEN** HTTP 504 Gateway Timeout is returned

### Requirement: CORS Support

The HTTP server supports Cross-Origin Resource Sharing for browser-based clients.

#### Scenario: Preflight CORS request
- **WHEN** an OPTIONS request is received at any endpoint
- **THEN** the response includes `Access-Control-Allow-Headers`, `Access-Control-Allow-Origin`, and `Access-Control-Allow-Methods` headers
- **AND** HTTP 200 OK is returned

#### Scenario: CORS on regular requests
- **WHEN** a regular (non-preflight) request is processed
- **THEN** the response includes the `Access-Control-Allow-Origin` header

#### Scenario: CORS on non-existing endpoints
- **WHEN** a preflight OPTIONS request is sent to a non-existing endpoint
- **THEN** CORS headers are still included in the response

### Requirement: Content Type Validation

Certain endpoints require specific content types.

#### Scenario: CBOR content type enforcement
- **WHEN** a POST request to the catch-up package endpoint lacks the `application/cbor` content type
- **THEN** HTTP 400 Bad Request is returned with message about unexpected content-type

#### Scenario: Invalid HTTP method
- **WHEN** a GET request is sent to a POST-only endpoint (e.g., catch-up package)
- **THEN** HTTP 405 Method Not Allowed is returned

### Requirement: Catch-Up Package Endpoint

Provides catch-up packages for consensus recovery.

#### Scenario: CUP retrieval
- **WHEN** a POST request is received at `/_/catch_up_package`
- **THEN** the catch-up package from the consensus pool cache is returned

### Requirement: Profiling Endpoints

Provides CPU profiling and tracing capabilities for debugging.

#### Scenario: Pprof home page
- **WHEN** a GET request is received at the pprof home route
- **THEN** an index page listing available profiling endpoints is returned

#### Scenario: Pprof profile
- **WHEN** a GET request is received at the pprof profile route
- **THEN** a CPU profile is collected and returned

#### Scenario: Pprof flamegraph
- **WHEN** a GET request is received at the pprof flamegraph route
- **THEN** a CPU flamegraph SVG is generated and returned

#### Scenario: Tracing flamegraph
- **WHEN** a GET request is received at the tracing flamegraph route
- **THEN** a tracing-based flamegraph is generated from the tracing subscriber
