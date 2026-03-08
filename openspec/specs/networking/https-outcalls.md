# HTTPS Outcalls (Canister HTTP Requests)

**Crates**: `ic-https-outcalls-adapter`, `ic-https-outcalls-adapter-client`, `ic-https-outcalls-consensus`, `ic-https-outcalls-pricing`, `ic-https-outcalls-service`

## Requirements

### Requirement: HTTPS Outcalls Adapter

The HTTPS outcalls adapter is an out-of-process gRPC service that executes HTTP requests on behalf of canisters, providing isolation from the replica process.

#### Scenario: Adapter startup
- **WHEN** the HTTPS outcalls adapter is started
- **THEN** a gRPC server is started listening on a Unix domain socket or systemd socket
- **AND** the server has a global timeout of `http_request_timeout_secs`

#### Scenario: Successful HTTPS outcall
- **WHEN** a canister HTTP request is received via gRPC
- **THEN** the URL is parsed and validated
- **AND** the HTTP method is mapped (GET, POST, HEAD, PUT, DELETE supported)
- **AND** request headers are validated and set
- **AND** the request is sent to the target server
- **AND** the response status, headers, and body are returned to the caller

#### Scenario: HTTPS-only enforcement
- **WHEN** a request URL uses the HTTP scheme (not HTTPS)
- **AND** the `http` feature is not enabled
- **THEN** the request is rejected with `InvalidInput` error and message "Url need to specify https scheme"

#### Scenario: Direct connection with SOCKS proxy fallback
- **WHEN** a direct HTTPS connection to the target fails
- **THEN** the adapter retries through configured SOCKS proxy addresses
- **AND** SOCKS proxies are tried in random order
- **AND** up to 2 SOCKS proxy attempts are made (`MAX_SOCKS_PROXY_TRIES`)
- **AND** SOCKS proxy clients are cached for reuse

#### Scenario: Response size limit enforcement
- **WHEN** the response headers plus body exceed `max_response_size_bytes`
- **THEN** the request fails with `LimitExceeded` error
- **AND** the error message indicates the size limit that was exceeded

#### Scenario: Header size exceeds response limit
- **WHEN** the response headers alone exceed `max_response_size_bytes`
- **THEN** the request fails with `LimitExceeded` error indicating header size exceeded the limit

#### Scenario: Header validation limits
- **WHEN** the request includes more than 1024 headers (`HEADERS_LIMIT`)
- **THEN** the request is rejected with "Too many headers"
- **WHEN** a header name or value exceeds 8192 bytes (`HEADER_NAME_VALUE_LIMIT`)
- **THEN** the request is rejected with "Header name or value exceeds size limit"

#### Scenario: Default user agent
- **WHEN** the request does not include a `User-Agent` header
- **THEN** the adapter adds `User-Agent: ic/1.0` as a fallback

#### Scenario: Duplicate header names
- **WHEN** multiple headers share the same name (case-insensitive)
- **THEN** all values are preserved under the same header name

#### Scenario: Network traffic metrics
- **WHEN** an HTTP request is executed
- **THEN** upload bytes (request size) and download bytes (response size) are tracked in metrics
- **AND** the `downloaded_bytes` metric is reported back to the caller in `CanisterHttpAdapterMetrics`

### Requirement: HTTPS Outcalls Client

The client component runs within the replica process and communicates with the adapter via gRPC.

#### Scenario: Request submission
- **WHEN** a canister HTTP request context is received
- **THEN** the request is converted to the gRPC `HttpsOutcallRequest` format
- **AND** the request is sent to the adapter via the gRPC channel
- **AND** SOCKS proxy addresses from the configuration are included

#### Scenario: Response transform execution
- **WHEN** the canister specifies a transform function
- **THEN** the HTTP response is first received from the adapter
- **AND** the transform function is executed as a query on the canister
- **AND** the transformed response is returned as the final result

#### Scenario: Response validation
- **WHEN** the adapter returns a response
- **THEN** the headers and body are validated against IC constraints
- **AND** invalid headers or oversized responses are rejected with appropriate error codes

#### Scenario: Adapter connection failure
- **WHEN** the gRPC connection to the adapter cannot be established
- **THEN** a `BrokenCanisterHttpClient` is returned
- **AND** all requests through this client fail with an error

#### Scenario: Budget tracking
- **WHEN** a canister HTTP request is processed
- **THEN** the pricing factory tracks network usage (request and response bytes)
- **AND** costs are calculated based on the adapter limits and pricing configuration

### Requirement: HTTPS Outcalls Consensus

The consensus component manages the agreement on HTTP outcall responses across subnet replicas.

#### Scenario: Payload building
- **WHEN** the canister HTTP payload builder constructs a payload for a block
- **THEN** it collects response shares from the canister HTTP pool
- **AND** groups shares by callback ID
- **AND** includes responses that have sufficient agreement (threshold signatures)
- **AND** respects the maximum payload size (`MAX_CANISTER_HTTP_PAYLOAD_SIZE`)
- **AND** limits responses per block to `CANISTER_HTTP_MAX_RESPONSES_PER_BLOCK`

#### Scenario: Timeout handling
- **WHEN** a canister HTTP request has been pending longer than `CANISTER_HTTP_TIMEOUT_INTERVAL`
- **THEN** a timeout response is generated for that callback
- **AND** the timeout response includes a rejection with appropriate error code

#### Scenario: Divergence detection
- **WHEN** different replicas return different responses for the same HTTP request
- **AND** the shares meet divergence criteria
- **THEN** a `CanisterHttpResponseDivergence` record is created
- **AND** the divergent response is included in the payload

#### Scenario: Single signature responses
- **WHEN** a canister HTTP request is configured for single-replica execution (non-replicated)
- **THEN** a single signature from any replica is sufficient
- **AND** no threshold signature aggregation is needed

#### Scenario: Payload validation
- **WHEN** a proposed canister HTTP payload is validated
- **THEN** all included response proofs are verified cryptographically
- **AND** the responses are checked against the current request contexts in state
- **AND** the payload size is verified against the maximum allowed size

### Requirement: HTTPS Outcalls Pool Manager

The pool manager handles the lifecycle of canister HTTP response shares.

#### Scenario: Response share processing
- **WHEN** new canister HTTP response shares arrive in the unvalidated pool
- **THEN** they are validated against the current set of pending HTTP request contexts
- **AND** valid shares are moved to the validated pool
- **AND** invalid or duplicate shares are removed

#### Scenario: Pool garbage collection
- **WHEN** the pool manager runs its periodic check
- **THEN** shares for completed or expired requests are purged
- **AND** shares from nodes not in the current subnet membership are removed

### Requirement: HTTPS Outcalls Gossip

The gossip component controls which canister HTTP response shares to fetch from peers.

#### Scenario: Share prioritization
- **WHEN** determining which shares to fetch
- **THEN** shares for requests with more existing shares (closer to completion) are prioritized
- **AND** shares that would complete a threshold are given highest priority
