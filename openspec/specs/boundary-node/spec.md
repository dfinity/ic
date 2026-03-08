# Boundary Node (ic_boundary) Specification

**Crates**: `ic-boundary`

This specification covers the IC Boundary Node HTTP gateway (`rs/boundary_node/ic_boundary/`), including routing, health checks, caching, rate limiting, TLS certificate verification, and the bouncer (IP-based firewall) subsystem.

---

## Requirements

### Requirement: HTTP Gateway Routing

The boundary node acts as an HTTP gateway that routes IC API requests (query, call, read_state) to the appropriate replica nodes based on the IC registry's routing table and canister-to-subnet mapping.

#### Scenario: Route query request to correct subnet
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/query`
- **THEN** the boundary node looks up the canister ID in the routing table to find the hosting subnet
- **AND** proxies the CBOR-encoded request to a healthy node in that subnet
- **AND** returns the replica's response with status 200 and `Content-Type: application/cbor`
- **AND** includes response headers `X-IC-Node-Id`, `X-IC-Subnet-Id`, `X-IC-Subnet-Type`, `X-IC-Sender`, `X-IC-Canister-Id`, `X-IC-Method-Name`, and `X-IC-Request-Type`

#### Scenario: Route call (update) request to correct subnet
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/call`
- **THEN** the boundary node looks up the canister ID in the routing table
- **AND** proxies the request to a healthy node in the target subnet
- **AND** returns status 202 (Accepted)

#### Scenario: Route v3 call request
- **WHEN** a client sends a POST request to `/api/v3/canister/{canister_id}/call`
- **THEN** the boundary node routes the request identically to v2 call requests
- **AND** returns status 202 (Accepted)

#### Scenario: Route v4 call request
- **WHEN** a client sends a POST request to `/api/v4/canister/{canister_id}/call`
- **THEN** the boundary node routes the request identically to v2/v3 call requests

#### Scenario: Route canister read_state request
- **WHEN** a client sends a POST request to `/api/v2/canister/{canister_id}/read_state`
- **THEN** the boundary node looks up the canister ID in the routing table
- **AND** proxies the request to a healthy node and returns the response with the `X-IC-Canister-Id` header set

#### Scenario: Route subnet read_state request
- **WHEN** a client sends a POST request to `/api/v2/subnet/{subnet_id}/read_state`
- **THEN** the boundary node looks up the subnet ID in the routing table
- **AND** proxies the request to a healthy node in that subnet with the `X-IC-Subnet-Id` header set

#### Scenario: Canister not found in routing table
- **WHEN** a client sends a request for a canister ID not present in the routing table
- **THEN** the boundary node returns an error indicating the canister was not found (`CanisterNotFound`)

#### Scenario: Subnet not found in routing table
- **WHEN** a client sends a subnet read_state request for a subnet ID not in the routing table
- **THEN** the boundary node returns an error indicating the subnet was not found (`SubnetNotFound`)

#### Scenario: No routing table available
- **WHEN** the boundary node has not yet received a routing table from the registry
- **THEN** all routing requests return an error indicating no routing table is available (`NoRoutingTable`)

---

### Requirement: Request Body Size Limit

The boundary node enforces a maximum request body size to prevent abuse.

#### Scenario: Request body within limit
- **WHEN** a client sends a request with body size less than or equal to 4 MB
- **THEN** the request is processed normally

#### Scenario: Request body exceeds limit
- **WHEN** a client sends a request with body size greater than 4 MB (MAX_REQUEST_BODY_SIZE)
- **THEN** the boundary node rejects the request with an appropriate error

---

### Requirement: Status Endpoint

The boundary node exposes a `/api/v2/status` endpoint that returns system status in CBOR format.

#### Scenario: Healthy status response
- **WHEN** a client sends a GET request to `/api/v2/status`
- **AND** the boundary node is healthy
- **THEN** it returns status 200 with `Content-Type: application/cbor`
- **AND** the CBOR body contains `replica_health_status: Healthy` and the NNS `root_key`
- **AND** response includes `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` headers

---

### Requirement: Health Check Endpoint

The boundary node exposes a `/health` endpoint for load balancer probes.

#### Scenario: Healthy boundary node
- **WHEN** all subnets have a sufficient proportion of healthy nodes
- **AND** sufficient subnets are healthy (above the `health_subnets_alive_threshold`)
- **THEN** GET `/health` returns HTTP 204 (No Content)

#### Scenario: Unhealthy boundary node - insufficient subnets
- **WHEN** fewer than the threshold proportion of subnets are healthy
- **THEN** GET `/health` returns HTTP 503 (Service Unavailable)

#### Scenario: Boundary node starting up
- **WHEN** the boundary node has not yet loaded a routing table or registry snapshot
- **THEN** GET `/health` returns HTTP 503 (Service Unavailable)
- **AND** the health status is `Starting`

#### Scenario: Zero subnets in snapshot
- **WHEN** the registry snapshot contains zero subnets
- **THEN** the health status is `CertifiedStateBehind` (unhealthy)

#### Scenario: Subnets with zero nodes
- **WHEN** all subnets in the registry snapshot have zero nodes
- **THEN** the health status is `CertifiedStateBehind` (unhealthy)

---

### Requirement: Node Health Checking

The boundary node periodically checks the health of replica nodes by querying their `/api/v2/status` endpoint and uses this information to build a routing table of healthy nodes.

#### Scenario: Healthy node included in routing table
- **WHEN** a node responds to health checks with HTTP 200
- **AND** the CBOR response indicates `replica_health_status: Healthy`
- **AND** the node's certified height is not lagging behind the subnet median by more than `max_height_lag`
- **THEN** the node is included in the routing table as a healthy node

#### Scenario: Unhealthy node excluded from routing table
- **WHEN** a node's health check fails (network error, non-200 status, unhealthy report)
- **THEN** the node is excluded from the routing table

#### Scenario: Node lagging behind excluded from routing table
- **WHEN** a node reports a certified height that lags behind the subnet median by more than `max_height_lag`
- **THEN** the node is excluded from the routing table even if it reports healthy status

#### Scenario: Minimum height calculation uses median
- **WHEN** computing the minimum acceptable height for a subnet
- **THEN** the system uses the median height of healthy nodes minus `max_height_lag`
- **AND** this makes the system resilient to malicious replicas sending artificially high heights

#### Scenario: Node health state change triggers immediate update
- **WHEN** a node's health status changes (healthy to unhealthy or vice versa)
- **THEN** the subnet actor immediately recalculates the healthy nodes list

#### Scenario: Latency changes trigger periodic updates
- **WHEN** a node's latency deviates by more than 15% from its moving average
- **OR** 10 health checks have passed since the last update
- **THEN** the node's height and average latency are updated

#### Scenario: Registry snapshot update restarts health checking
- **WHEN** a new registry snapshot is published
- **THEN** all health check actors are stopped and restarted with the new subnet/node configuration

#### Scenario: Nodes removed from registry are removed from routing table
- **WHEN** a new registry snapshot has fewer nodes than the previous one
- **THEN** the removed nodes no longer appear in the routing table after the health check restart

---

### Requirement: Response Caching

The boundary node caches responses for query requests to reduce load on replica nodes.

#### Scenario: Cache hit for identical anonymous query
- **WHEN** an anonymous query request is made
- **AND** an identical query (same canister ID, sender, method name, ingress expiry, and arguments) was recently made
- **THEN** the boundary node returns the cached response (cache hit)
- **AND** the cached response body matches the original response body

#### Scenario: Cache miss for first query
- **WHEN** a query request is made for the first time
- **THEN** the request is forwarded to a replica node (cache miss)

#### Scenario: Cache bypass for non-query requests
- **WHEN** a call (update) request is made
- **THEN** caching is bypassed with reason `IncorrectRequestType`

#### Scenario: Cache bypass for requests with nonce
- **WHEN** a query request includes a nonce
- **THEN** caching is bypassed with reason `Nonce`

#### Scenario: Cache bypass for non-anonymous requests
- **WHEN** a query request is made by a non-anonymous sender
- **AND** `cache_non_anonymous` is not enabled
- **THEN** caching is bypassed with reason `NonAnonymous`

#### Scenario: Cache bypass for non-2xx responses
- **WHEN** a query request results in a non-2xx response from the replica
- **THEN** caching is bypassed with reason `HTTPError`

---

### Requirement: IP-Based Rate Limiting

The boundary node supports per-IP rate limiting for call (update) requests.

#### Scenario: Requests within IP rate limit
- **WHEN** a client makes fewer requests than the configured per-second IP rate limit
- **THEN** all requests are processed normally (HTTP 200/202)

#### Scenario: Requests exceeding IP rate limit
- **WHEN** a client exceeds the configured per-second IP rate limit
- **THEN** subsequent requests return HTTP 429 (Too Many Requests)

---

### Requirement: Subnet-Based Rate Limiting

The boundary node supports per-subnet rate limiting for call (update) requests.

#### Scenario: Requests within subnet rate limit
- **WHEN** requests to a subnet are within the configured per-second rate limit
- **THEN** all requests are processed normally

#### Scenario: Requests exceeding subnet rate limit
- **WHEN** requests to a specific subnet exceed the per-second rate limit
- **THEN** subsequent requests to that subnet return HTTP 429 (Too Many Requests)

#### Scenario: Different subnets have independent limits
- **WHEN** one subnet's rate limit is exhausted
- **THEN** requests to a different subnet are still allowed (up to its own limit)

#### Scenario: Rate limit applies across API versions
- **WHEN** the per-subnet rate limit is exhausted via `/api/v2/canister/{id}/call`
- **THEN** requests via `/api/v3/canister/{id}/call` are also rate limited

---

### Requirement: Bouncer (IP Firewall-Based Rate Limiting)

The bouncer subsystem detects abusive IPs and bans them using system firewall rules.

#### Scenario: Requests within bouncer burst allowance
- **WHEN** a client makes fewer requests than the configured burst size
- **THEN** all requests are allowed

#### Scenario: Client exceeds burst size triggers ban
- **WHEN** a client exceeds the configured burst size
- **THEN** the client's IP is banned
- **AND** subsequent requests from that IP are rejected

#### Scenario: Banned IPs are applied to firewall
- **WHEN** an IP is banned by the bouncer
- **THEN** the ban decision is applied to the system firewall (nftables)

#### Scenario: Ban expires after configured duration
- **WHEN** the ban duration has elapsed since an IP was banned
- **THEN** the IP is released from the ban list
- **AND** the firewall rules are updated to remove the ban

#### Scenario: Different IPs have independent rate limit buckets
- **WHEN** one IP is banned
- **THEN** a different IP can still make requests up to the burst limit

---

### Requirement: TLS Certificate Verification

The boundary node verifies TLS certificates presented by replica nodes during connections using the IC registry as the source of trust.

#### Scenario: Valid TLS certificate from registered node
- **WHEN** a replica node presents a TLS certificate during the handshake
- **AND** the certificate's CommonName matches a node ID in the registry
- **AND** the certificate is signed by the public key stored in the registry for that node
- **AND** the certificate is not expired
- **THEN** the TLS connection is established successfully

#### Scenario: Certificate with mismatched CommonName
- **WHEN** a replica node presents a certificate whose CommonName does not match the expected DNS name
- **THEN** the TLS connection is rejected with `NotValidForName`

#### Scenario: Certificate from unknown node
- **WHEN** a replica node presents a certificate for a node ID not in the routing table
- **THEN** the TLS connection is rejected

#### Scenario: Intermediate certificates rejected
- **WHEN** a replica node sends more than one certificate (i.e., includes intermediates)
- **THEN** the TLS connection is rejected because only self-signed certificates are expected

#### Scenario: No routing table available during verification
- **WHEN** the boundary node has not yet loaded a routing table
- **THEN** TLS certificate verification fails with a general error

#### Scenario: TLS verification can be skipped
- **WHEN** the `--skip-replica-tls-verification` flag is set
- **THEN** the boundary node uses a no-op TLS verifier that accepts all certificates

---

### Requirement: TLS Configuration

The boundary node enforces TLS 1.3 for connections to replica nodes and supports HTTPS for client-facing connections.

#### Scenario: Client connections over HTTPS
- **WHEN** an HTTPS port is configured
- **THEN** the boundary node serves HTTPS using TLS 1.3
- **AND** supports ACME ALPN-01 certificate issuance or static certificate files

#### Scenario: TLS resolver fallback
- **WHEN** a static TLS certificate is not available
- **THEN** the boundary node falls back to ACME ALPN-01 for automatic certificate provisioning

#### Scenario: ACME certificate provisioning
- **WHEN** the boundary node starts with ACME configuration
- **THEN** it obtains a TLS certificate via the ACME ALPN-01 challenge
- **AND** the `/health` endpoint becomes accessible over HTTPS

---

### Requirement: Request Validation and Processing

The boundary node validates and preprocesses incoming requests before routing.

#### Scenario: CBOR request parsing
- **WHEN** a request is received on a canister endpoint
- **THEN** the boundary node parses the CBOR envelope to extract canister_id, sender, method_name, nonce, and ingress_expiry

#### Scenario: Request context enrichment
- **WHEN** a request is successfully parsed
- **THEN** the request context is enriched with request type (query, call, read_state), request size, and parsed fields

#### Scenario: Security headers on all responses
- **WHEN** any IC API response is returned
- **THEN** it includes `Content-Type: application/cbor`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`

---

### Requirement: Request Retry

The boundary node supports automatic retry of failed requests to different replica nodes.

#### Scenario: Failed request retried to different node
- **WHEN** a request to a replica node fails
- **AND** the retry count has not been exhausted
- **THEN** the request is retried to a different node in the same subnet

#### Scenario: Latency-based routing
- **WHEN** latency-based routing is enabled
- **THEN** the boundary node preferentially routes requests to lower-latency nodes

---

### Requirement: Load Shedding

The boundary node can shed load based on system resource utilization and request latency.

#### Scenario: System load shedding
- **WHEN** system CPU, memory, or load average exceeds configured thresholds
- **THEN** the boundary node returns a load shed error for new requests

#### Scenario: Latency-based load shedding
- **WHEN** request latency exceeds configured per-request-type thresholds
- **THEN** the boundary node returns a load shed error for new requests of that type

#### Scenario: Concurrency limiting
- **WHEN** the number of concurrent requests exceeds the configured maximum
- **THEN** additional requests are rejected

---

### Requirement: Salt Sharing and Log Anonymization

The boundary node supports anonymizing HTTP logs using a salt fetched from a canister.

#### Scenario: Anonymization salt fetching
- **WHEN** an anonymization canister ID is configured
- **THEN** the boundary node periodically fetches a salt from the canister
- **AND** uses the salt to anonymize request logs

---

### Requirement: Rate Limits Canister

The boundary node supports fetching rate limiting rules from a dedicated canister (`rs/boundary_node/rate_limits/`).

#### Scenario: Rate limit rules from canister
- **WHEN** a rate limit canister ID is configured
- **THEN** the boundary node periodically fetches rate limit rules from the canister
- **AND** applies those rules as a generic rate limiter

#### Scenario: Rate limit rules from file
- **WHEN** a rate limit file is configured instead of a canister
- **THEN** the boundary node loads rate limit rules from the file

---

### Requirement: GeoIP Middleware

The boundary node optionally enriches requests with geographic information.

#### Scenario: GeoIP database loaded
- **WHEN** a GeoIP database path is configured
- **THEN** the boundary node annotates requests with geographic location data based on client IP
