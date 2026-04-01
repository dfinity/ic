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
| REQ-BN-001 | HTTP routing | narrative | rs/boundary_node/ic_boundary/tests/ |
| REQ-BN-002 | Body size limit | narrative | rs/boundary_node/ic_boundary/tests/ |
| REQ-BN-003 | Status endpoint | narrative | rs/boundary_node/ic_boundary/tests/ |
| REQ-BN-004 | Health check | narrative | rs/boundary_node/ic_boundary/tests/ |
