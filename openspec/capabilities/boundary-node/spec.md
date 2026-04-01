# Boundary Node Capability Specification

**Source narrative**: `openspec/specs/boundary-node/spec.md`
**Crates**: `ic-boundary`
**Key files**: `rs/boundary_node/ic_boundary/`

---

## REQ-BN-001: HTTP Gateway Routing

The boundary node MUST route IC API requests to the correct replica nodes based on the registry routing table.

### SCENARIO-BN-001: Route query request to correct subnet
**Given** a client sends POST to `/api/v2/canister/{canister_id}/query`
**When** the request is handled
**Then** the boundary node looks up the canister ID in the routing table
**And** proxies the CBOR-encoded request to a healthy node in that subnet
**And** returns the replica's response with status 200 and `Content-Type: application/cbor`
**And** includes response headers `X-IC-Node-Id`, `X-IC-Subnet-Id`, `X-IC-Subnet-Type`, etc.

### SCENARIO-BN-002: Route call (update) request
**Given** a client sends POST to `/api/v2/canister/{canister_id}/call`
**When** the request is handled
**Then** the boundary node looks up the canister ID and proxies to a healthy node
**And** returns status 202 (Accepted)

### SCENARIO-BN-003: Route canister read_state request
**Given** a client sends POST to `/api/v2/canister/{canister_id}/read_state`
**When** the request is handled
**Then** the boundary node proxies to a healthy node with `X-IC-Canister-Id` header set

### SCENARIO-BN-004: Route subnet read_state request
**Given** a client sends POST to `/api/v2/subnet/{subnet_id}/read_state`
**When** the request is handled
**Then** the boundary node looks up the subnet ID and proxies to a healthy node

### SCENARIO-BN-005: Canister not found in routing table
**Given** a request is for a canister ID not in the routing table
**When** the request is handled
**Then** the boundary node returns an error `CanisterNotFound`

### SCENARIO-BN-006: No routing table available
**Given** the boundary node has not yet received a routing table from the registry
**When** a routing request arrives
**Then** all routing requests return an error indicating no routing table is available

---

## REQ-BN-002: Request Body Size Limit

The boundary node MUST enforce a maximum request body size of 4 MB.

### SCENARIO-BN-007: Request body within limit
**Given** a client sends a request with body ≤ 4 MB
**When** the request is processed
**Then** it is processed normally

### SCENARIO-BN-008: Request body exceeds limit
**Given** a client sends a request with body > 4 MB
**When** the request is received
**Then** the boundary node rejects it with an appropriate error

---

## REQ-BN-003: Status Endpoint

The boundary node MUST expose `/api/v2/status` returning CBOR system status.

### SCENARIO-BN-009: Healthy status response
**Given** a client sends GET to `/api/v2/status`
**When** the boundary node is healthy
**Then** it returns status 200 with `Content-Type: application/cbor`
**And** the CBOR body contains `replica_health_status: Healthy` and the NNS `root_key`

---

## REQ-BN-004: Health Check Endpoint

The boundary node MUST expose `/health` for load balancer probes.

### SCENARIO-BN-010: Healthy boundary node
**Given** sufficient subnets have sufficient healthy nodes
**When** GET `/health` is called
**Then** it returns HTTP 204 (No Content)

### SCENARIO-BN-011: Unhealthy boundary node
**Given** fewer than the threshold proportion of subnets are healthy
**When** GET `/health` is called
**Then** it returns HTTP 503 (Service Unavailable)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
## REQ-BN-005: Node Health Checking

The boundary node MUST periodically check replica health and exclude unhealthy nodes from routing.

### SCENARIO-BN-012: Healthy node included in routing table
**Given** a node responds to health checks with HTTP 200 and `replica_health_status: Healthy`
**And** the node's certified height is not lagging behind the subnet median by more than `max_height_lag`
**When** the routing table is updated
**Then** the node is included as a healthy routing target

### SCENARIO-BN-013: Node height lag excludes from routing
**Given** a node's certified height lags behind the subnet median by more than `max_height_lag`
**When** the routing table is updated
**Then** the node is excluded even if it reports healthy status

### SCENARIO-BN-014: Minimum height uses median for resilience
**Given** computing the minimum acceptable height for a subnet
**When** the threshold is computed
**Then** the system uses median height of healthy nodes minus `max_height_lag`
**And** this protects against malicious replicas sending artificially high heights

### SCENARIO-BN-015: Registry snapshot update restarts health checking
**Given** a new registry snapshot is published
**When** the snapshot is processed
**Then** all health check actors are stopped and restarted with the new node configuration

---

## REQ-BN-006: Response Caching

The boundary node MUST cache query responses to reduce load on replica nodes.

### SCENARIO-BN-016: Cache hit for identical anonymous query
**Given** an anonymous query (same canister ID, sender, method, ingress expiry, args) was recently made
**When** the identical query arrives again
**Then** the boundary node returns the cached response without forwarding to a replica

### SCENARIO-BN-017: Cache bypass for update calls
**Given** a call (update) request arrives
**When** the caching layer is checked
**Then** caching is bypassed with reason `IncorrectRequestType`

### SCENARIO-BN-018: Cache bypass for non-anonymous requests
**Given** a query request is made by a non-anonymous sender and `cache_non_anonymous` is not enabled
**When** the caching layer is checked
**Then** caching is bypassed with reason `NonAnonymous`

### SCENARIO-BN-019: Cache bypass for requests with nonce
**Given** a query request includes a nonce
**When** the caching layer is checked
**Then** caching is bypassed with reason `Nonce`

---

## REQ-BN-007: IP-Based Rate Limiting

The boundary node MUST enforce per-IP rate limits for call requests.

### SCENARIO-BN-020: Requests within IP rate limit allowed
**Given** a client makes fewer requests than the configured per-second IP rate limit
**When** requests arrive
**Then** all requests are processed normally

### SCENARIO-BN-021: Requests exceeding IP rate limit rejected
**Given** a client exceeds the configured per-second IP rate limit
**When** the excess request arrives
**Then** HTTP 429 Too Many Requests is returned

---

## REQ-BN-008: Subnet-Based Rate Limiting

The boundary node MUST enforce per-subnet rate limits for call requests.

### SCENARIO-BN-022: Requests exceeding subnet rate limit rejected
**Given** requests to a subnet exceed the per-second rate limit
**When** the excess request arrives
**Then** HTTP 429 Too Many Requests is returned

### SCENARIO-BN-023: Different subnets have independent limits
**Given** one subnet's rate limit is exhausted
**When** a request to a different subnet arrives
**Then** the request is processed normally (independent limits)

### SCENARIO-BN-024: Rate limit applies across API versions
**Given** the per-subnet rate limit is exhausted via `/api/v2/canister/{id}/call`
**When** a request via `/api/v3/canister/{id}/call` arrives for the same subnet
**Then** the v3 request is also rate limited

---

## REQ-BN-009: Bouncer (IP Firewall Rate Limiting)

The bouncer subsystem MUST detect abusive IPs and ban them via system firewall rules.

### SCENARIO-BN-025: Client exceeds burst size triggers ban
**Given** a client exceeds the configured burst size
**When** the burst is exceeded
**Then** the client's IP is banned and subsequent requests from that IP are rejected
**And** the ban decision is applied to the system firewall (nftables)

### SCENARIO-BN-026: Ban expires after configured duration
**Given** the ban duration has elapsed since an IP was banned
**When** the expiry fires
**Then** the IP is released from the ban list and firewall rules are updated

---

## REQ-BN-010: TLS Certificate Verification

The boundary node MUST verify TLS certificates presented by replica nodes using the IC registry as trust anchor.

### SCENARIO-BN-027: Valid TLS certificate from registered node
**Given** a replica node presents a TLS certificate during handshake
**And** the CommonName matches a node ID in the registry
**And** the certificate is signed by the public key stored in the registry
**And** the certificate is not expired
**When** TLS verification runs
**Then** the TLS connection is established successfully

### SCENARIO-BN-028: Certificate from unknown node rejected
**Given** a replica node presents a certificate for a node ID not in the routing table
**When** TLS verification runs
**Then** the TLS connection is rejected

### SCENARIO-BN-029: Only self-signed certificates accepted
**Given** a replica node sends more than one certificate (includes intermediates)
**When** TLS verification runs
**Then** the TLS connection is rejected (only self-signed certificates are expected)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-BN-001 | HTTP routing | linked | rs/boundary_node/ic_boundary/src/core.rs |
| REQ-BN-002 | Body size limit | linked | rs/boundary_node/ic_boundary/src/core.rs |
| REQ-BN-003 | Status endpoint | linked | rs/boundary_node/ic_boundary/src/core.rs |
| REQ-BN-004 | Health check | linked | rs/boundary_node/ic_boundary/src/core.rs |
| REQ-BN-005 | Node health checking | narrative | rs/boundary_node/ic_boundary/ |
| REQ-BN-006 | Response caching | narrative | rs/boundary_node/ic_boundary/ |
| REQ-BN-007 | IP rate limiting | narrative | rs/boundary_node/ic_boundary/ |
| REQ-BN-008 | Subnet rate limiting | narrative | rs/boundary_node/ic_boundary/ |
| REQ-BN-009 | Bouncer | narrative | rs/boundary_node/ic_boundary/ |
| REQ-BN-010 | TLS verification | narrative | rs/boundary_node/ic_boundary/ |
