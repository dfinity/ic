# Networking: HTTP Endpoints Capability Specification

**Source narrative**: `openspec/specs/networking/http-endpoints.md`
**Crates**: `ic-http-endpoints-public`, `ic-http-endpoints-metrics`, `ic-http-endpoints-async-utils`, `ic-read-state-response-parser`
**Key files**: `rs/http_endpoints/public/src/`, `rs/http_endpoints/public/tests/`

---

## REQ-HTTP-001: HTTP Server Lifecycle

The HTTP server MUST accept TLS and plaintext connections and transition health status through a defined initialization sequence.

### SCENARIO-HTTP-001: Server initialization sequence
**Given** the HTTP server starts
**When** initialization runs
**Then** it waits for certified state to become available
**And** then waits for the initial NNS certificate delegation
**And** only after both are available does health status become `Healthy`

### SCENARIO-HTTP-002: TLS connection handling
**Given** a new TCP connection arrives with a TLS handshake byte (0x16)
**When** the connection is accepted
**Then** TLS is negotiated using the node's server config without client auth
**And** ALPN protocols `h2` and `http/1.1` are advertised

### SCENARIO-HTTP-003: Plaintext connection handling
**Given** a new TCP connection arrives without a TLS handshake byte
**When** the connection is accepted
**Then** it is handled as plain HTTP
**And** connection duration is tracked with the "insecure" label

### SCENARIO-HTTP-004: Connection read timeout
**Given** a connection does not send data within the configured read timeout
**When** the timeout fires
**Then** the connection is closed
**And** the `connection_setup_duration` metric is recorded with a timeout error label

### SCENARIO-HTTP-005: HTTP/2 concurrent streams limit
**Given** an HTTP/2 connection is being served
**When** a new stream is opened
**Then** concurrent streams are limited to `http_max_concurrent_streams`

---

## REQ-HTTP-002: Call Endpoint (Ingress Submission)

The call endpoint MUST handle both asynchronous (v2) and synchronous (v3/v4) ingress message submission.

### SCENARIO-HTTP-006: Asynchronous call (v2)
**Given** a POST request arrives at `/api/v2/canister/{effective_canister_id}/call`
**When** the request is handled
**Then** the ingress message is validated (signature, size, canister willingness)
**And** the message is submitted to the ingress pool
**And** HTTP 202 Accepted is returned immediately

### SCENARIO-HTTP-007: Synchronous call (v3)
**Given** a POST request arrives at `/api/v3/canister/{effective_canister_id}/call`
**When** the request is handled
**Then** the message is validated, submitted, and the handler waits for certification
**And** if certified in time, a CBOR response with the certificate is returned
**And** if not certified in time, HTTP 202 Accepted is returned with a timeout explanation

### SCENARIO-HTTP-008: Duplicate synchronous call detection
**Given** a v3/v4 call request arrives for a message ID already in certified state
**When** the request is handled
**Then** the certificate is returned immediately without re-submitting the message

### SCENARIO-HTTP-009: Ingress pool full — load shedding
**Given** the ingress pool exceeds its threshold
**When** a call request arrives
**Then** the request is rejected with HTTP 503 Service Unavailable
**And** the message "Service is overloaded, try again later." is returned

### SCENARIO-HTTP-010: Canister ID mismatch validation
**Given** the `canister_id` in the message body does not match the `effective_canister_id` in the URL
**And** the canister_id is not the management canister
**When** validation runs
**Then** the request is rejected with HTTP 400 Bad Request

### SCENARIO-HTTP-011: Ingress message size validation
**Given** the ingress message exceeds `max_ingress_bytes_per_message` from the registry
**When** validation runs
**Then** the request is rejected with HTTP 413 Payload Too Large

---

## REQ-HTTP-003: Ingress Watcher

The ingress watcher MUST track ingress messages from submission through certification for synchronous call responses.

### SCENARIO-HTTP-012: Subscription for certification
**Given** a sync call handler subscribes to track a message ID
**When** the subscription is created
**Then** an `IngressCertificationSubscriber` is returned that can wait for certification
**And** the message is tracked in the internal state

### SCENARIO-HTTP-013: Duplicate subscription rejection
**Given** a subscription for an already-tracked message ID is attempted
**When** the subscription is created
**Then** a `DuplicateSubscriptionError` is returned

### SCENARIO-HTTP-014: Certification notification
**Given** the certified height advances past a message's completion height
**When** the watcher processes the height update
**Then** all subscribers waiting on that message are notified
**And** the message is removed from the tracking state

---

## REQ-HTTP-004: Query Endpoint

The query endpoint MUST execute canister query calls and return results.

### SCENARIO-HTTP-015: Execute query call
**Given** a POST request arrives at `/api/v2/canister/{canister_id}/query`
**When** the request is handled
**Then** the query is validated and executed against the canister
**And** the result is returned as CBOR with HTTP 200

### SCENARIO-HTTP-016: Read state request
**Given** a POST request arrives at `/api/v2/canister/{canister_id}/read_state` or `/api/v2/subnet/{subnet_id}/read_state`
**When** the request is handled
**Then** the requested state tree paths are returned with a certificate
**And** the response is CBOR-encoded

---

## REQ-HTTP-005: Health Status Management

The replica health status MUST be dynamically updated based on consensus and certified state.

### SCENARIO-HTTP-017: Certified state behind detection
**Given** the certified state height significantly lags behind the finalized block height
**And** the current health status is `Healthy`
**When** the lag is detected
**Then** the health status transitions to `CertifiedStateBehind`

### SCENARIO-HTTP-018: Health status atomic transitions
**Given** a health status transition is attempted
**When** the transition executes
**Then** it uses `compare_exchange` to ensure only valid transitions occur
**And** concurrent requests see consistent health status (lock-free atomic)

---

## REQ-HTTP-006: Request Size and Rate Limiting

The HTTP server MUST enforce size and concurrency limits to protect against resource exhaustion.

### SCENARIO-HTTP-019: Request body size limit
**Given** a request body exceeds `max_request_size_bytes`
**When** the request is received
**Then** HTTP 413 Payload Too Large is returned

### SCENARIO-HTTP-020: Concurrent request limiting per endpoint
**Given** the number of concurrent requests for an endpoint exceeds its configured limit
**When** a new request arrives
**Then** HTTP 429 Too Many Requests is returned
**And** other endpoints are not affected (independent limits)

### SCENARIO-HTTP-021: Global request timeout
**Given** a request takes longer than `request_timeout_seconds`
**When** the timeout fires
**Then** HTTP 504 Gateway Timeout is returned

---

## REQ-HTTP-007: CORS Support

The HTTP server MUST support Cross-Origin Resource Sharing for browser-based clients.

### SCENARIO-HTTP-022: Preflight CORS request
**Given** an OPTIONS request is received at any endpoint
**When** the request is handled
**Then** the response includes `Access-Control-Allow-Headers`, `Access-Control-Allow-Origin`, and `Access-Control-Allow-Methods` headers
**And** HTTP 200 OK is returned

### SCENARIO-HTTP-023: CORS on regular requests
**Given** a regular (non-preflight) request is processed
**When** the response is built
**Then** it includes the `Access-Control-Allow-Origin` header

---

## REQ-HTTP-008: Content Type Validation

Certain endpoints MUST require specific content types.

### SCENARIO-HTTP-024: CBOR content type enforcement
**Given** a POST request to the catch-up package endpoint lacks `application/cbor` content type
**When** validation runs
**Then** HTTP 400 Bad Request is returned

### SCENARIO-HTTP-025: Invalid HTTP method rejection
**Given** a GET request is sent to a POST-only endpoint
**When** the request is routed
**Then** HTTP 405 Method Not Allowed is returned

---

## REQ-HTTP-009: Catch-Up Package Endpoint

The server MUST provide catch-up packages via a dedicated endpoint.

### SCENARIO-HTTP-026: CUP retrieval
**Given** a POST request arrives at `/_/catch_up_package`
**When** the request is handled
**Then** the catch-up package from the consensus pool cache is returned

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-HTTP-001 | Server lifecycle | narrative | rs/http_endpoints/public/tests/ |
| REQ-HTTP-002 | Call endpoint | narrative | rs/http_endpoints/public/tests/test.rs |
| REQ-HTTP-003 | Ingress watcher | narrative | rs/http_endpoints/public/tests/ |
| REQ-HTTP-004 | Query endpoint | narrative | rs/http_endpoints/public/tests/ |
| REQ-HTTP-005 | Health status | narrative | rs/http_endpoints/public/tests/ |
| REQ-HTTP-006 | Rate limiting | narrative | rs/http_endpoints/public/tests/load_shed_test.rs |
| REQ-HTTP-007 | CORS support | narrative | rs/http_endpoints/public/tests/test.rs |
| REQ-HTTP-008 | Content type validation | narrative | rs/http_endpoints/public/tests/test.rs |
| REQ-HTTP-009 | CUP endpoint | narrative | rs/http_endpoints/public/tests/ |
