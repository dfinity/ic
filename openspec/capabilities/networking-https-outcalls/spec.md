# Networking: HTTPS Outcalls Capability Specification

**Source narrative**: `openspec/specs/networking/https-outcalls.md`
**Crates**: `ic-https-outcalls-adapter`, `ic-https-outcalls-adapter-client`, `ic-https-outcalls-consensus`, `ic-https-outcalls-pricing`, `ic-https-outcalls-service`
**Key files**: `rs/https_outcalls/adapter/`, `rs/https_outcalls/consensus/`

---

## REQ-HTTPS-001: HTTPS Outcalls Adapter

The adapter MUST execute HTTP requests on behalf of canisters in an isolated out-of-process gRPC service.

### SCENARIO-HTTPS-001: Adapter startup
**Given** the HTTPS outcalls adapter is started
**When** initialization completes
**Then** a gRPC server listens on a Unix domain socket or systemd socket
**And** the server has a global timeout of `http_request_timeout_secs`

### SCENARIO-HTTPS-002: Successful HTTPS outcall
**Given** a canister HTTP request is received via gRPC
**When** the request is executed
**Then** the URL is parsed and validated
**And** the HTTP method is mapped (GET, POST, HEAD, PUT, DELETE supported)
**And** request headers are validated and set
**And** the request is sent to the target server
**And** response status, headers, and body are returned

### SCENARIO-HTTPS-003: HTTPS-only enforcement
**Given** a request URL uses the HTTP scheme (not HTTPS) and the `http` feature is not enabled
**When** the request is received
**Then** the request is rejected with `InvalidInput` and message "Url need to specify https scheme"

### SCENARIO-HTTPS-004: Direct connection with SOCKS proxy fallback
**Given** a direct HTTPS connection to the target fails
**When** fallback is attempted
**Then** the adapter retries through configured SOCKS proxy addresses
**And** SOCKS proxies are tried in random order (up to `MAX_SOCKS_PROXY_TRIES = 2`)
**And** SOCKS proxy clients are cached for reuse

### SCENARIO-HTTPS-005: Response size limit enforcement
**Given** the response headers plus body exceed `max_response_size_bytes`
**When** the response is received
**Then** the request fails with `LimitExceeded` indicating the size limit exceeded

### SCENARIO-HTTPS-006: Too many headers rejected
**Given** a request includes more than 1024 headers (`HEADERS_LIMIT`)
**When** the request is received
**Then** it is rejected with "Too many headers"

### SCENARIO-HTTPS-017: Header name or value too large
**Given** a header name or value exceeds 8192 bytes (`HEADER_NAME_VALUE_LIMIT`)
**When** the request is received
**Then** it is rejected with "Header name or value exceeds size limit"

### SCENARIO-HTTPS-018: Default User-Agent header
**Given** the request does not include a `User-Agent` header
**When** the request is sent to the target
**Then** the adapter adds `User-Agent: ic/1.0` as a fallback header

### SCENARIO-HTTPS-019: Duplicate header name preservation
**Given** multiple headers share the same name (case-insensitive)
**When** the request is processed
**Then** all values are preserved under the same header name (not deduplicated)

---

## REQ-HTTPS-002: HTTPS Outcalls Client

The client MUST communicate with the adapter from within the replica process via gRPC.

### SCENARIO-HTTPS-007: Request submission to adapter
**Given** a canister HTTP request context is received
**When** the request is submitted
**Then** it is converted to `HttpsOutcallRequest` gRPC format
**And** sent to the adapter via the gRPC channel
**And** configured SOCKS proxy addresses are included

### SCENARIO-HTTPS-008: Response transform execution
**Given** the canister specifies a transform function
**When** the adapter returns a response
**Then** the transform function is executed as a query on the canister
**And** the transformed response is returned as the final result

### SCENARIO-HTTPS-020: Client-side response validation
**Given** the adapter returns a response
**When** the client validates it
**Then** headers and body are checked against IC constraints
**And** invalid headers or oversized responses are rejected with appropriate error codes

### SCENARIO-HTTPS-009: Adapter connection failure
**Given** the gRPC connection to the adapter cannot be established
**When** the failure occurs
**Then** a `BrokenCanisterHttpClient` is returned
**And** all requests through this client fail with an error

---

## REQ-HTTPS-003: HTTPS Outcalls Consensus

The consensus component MUST achieve subnet-wide agreement on HTTP response shares.

### SCENARIO-HTTPS-010: Payload building with threshold agreement
**Given** the canister HTTP payload builder constructs a payload for a block
**When** building runs
**Then** response shares are collected from the canister HTTP pool
**And** shares are grouped by callback ID
**And** only responses with sufficient agreement (threshold signatures) are included
**And** the payload respects `MAX_CANISTER_HTTP_PAYLOAD_SIZE`
**And** responses per block are limited to `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK`

### SCENARIO-HTTPS-011: Timeout handling
**Given** a canister HTTP request has been pending longer than `CANISTER_HTTP_TIMEOUT_INTERVAL`
**When** the timeout check runs
**Then** a timeout response is generated for that callback
**And** the timeout response includes a rejection with appropriate error code

### SCENARIO-HTTPS-012: Divergence detection
**Given** different replicas return different responses for the same HTTP request
**And** the shares meet divergence criteria
**When** divergence is detected
**Then** a `CanisterHttpResponseDivergence` record is created
**And** the divergent response is included in the payload

### SCENARIO-HTTPS-013: Payload validation
**Given** a proposed canister HTTP payload is validated
**When** validation runs
**Then** all included response proofs are verified cryptographically
**And** responses are checked against current request contexts in state
**And** payload size is verified against the maximum allowed size

---

## REQ-HTTPS-004: HTTPS Outcalls Pool Manager

The pool manager MUST handle the lifecycle of canister HTTP response shares.

### SCENARIO-HTTPS-014: Response share validation and promotion
**Given** new canister HTTP response shares arrive in the unvalidated pool
**When** validation runs
**Then** shares are validated against pending HTTP request contexts
**And** valid shares are moved to the validated pool
**And** invalid or duplicate shares are removed

### SCENARIO-HTTPS-015: Pool garbage collection
**Given** the pool manager runs its periodic check
**When** GC runs
**Then** shares for completed or expired requests are purged
**And** shares from nodes not in current subnet membership are removed

---

## REQ-HTTPS-005: HTTPS Outcalls Gossip Prioritization

The gossip component MUST prioritize which canister HTTP response shares to fetch from peers.

### SCENARIO-HTTPS-016: Share prioritization
**Given** determining which shares to fetch
**When** priority is computed
**Then** shares for requests with more existing shares (closer to completion) are prioritized
**And** shares that would complete a threshold are given highest priority

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-HTTPS-001 | Adapter | narrative | rs/https_outcalls/adapter/ |
| REQ-HTTPS-002 | Client | narrative | rs/https_outcalls/consensus/ |
| REQ-HTTPS-003 | Consensus agreement | narrative | rs/https_outcalls/consensus/src/payload_builder/tests.rs |
| REQ-HTTPS-004 | Pool manager | narrative | rs/https_outcalls/consensus/src/pool_manager.rs |
| REQ-HTTPS-005 | Gossip prioritization | narrative | rs/https_outcalls/consensus/ |
