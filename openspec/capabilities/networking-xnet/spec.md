# Networking: XNet Capability Specification

**Source narrative**: `openspec/specs/networking/xnet.md`
**Crates**: `ic-xnet-hyper`, `ic-xnet-payload-builder`, `ic-xnet-uri`
**Key files**: `rs/xnet/`, `rs/xnet/payload_builder/`

---

## REQ-XNET-001: XNet Endpoint

The XNet endpoint MUST serve certified stream slices over HTTPS to other subnets.

### SCENARIO-XNET-001: List available streams
**Given** a request is received at `/api/v1/streams`
**When** the request is handled
**Then** a JSON array of subnet IDs with available certified streams is returned

### SCENARIO-XNET-002: Fetch stream slice
**Given** a request is received at `/api/v1/stream/{SubnetId}`
**When** the request is handled
**Then** a certified stream slice for the given subnet is returned as protobuf
**And** the response content type is `application/x-protobuf`

### SCENARIO-XNET-003: Stream slice with query parameters
**Given** a stream request includes `msg_begin`, `witness_begin`, `msg_limit`, and/or `byte_limit`
**When** the request is handled
**Then** the slice begins at `msg_begin`
**And** contains at most `msg_limit` messages
**And** does not exceed `byte_limit` bytes

### SCENARIO-XNET-004: Non-existent stream returns 204
**Given** a stream is requested for a subnet with no available stream
**When** the request is handled
**Then** HTTP 204 No Content is returned

### SCENARIO-XNET-005: Invalid slice parameters
**Given** a stream request specifies a `msg_begin` out of range
**When** the request is handled
**Then** HTTP 416 Range Not Satisfiable is returned

### SCENARIO-XNET-006: Concurrent request limiting
**Given** more than `XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS` (4) concurrent requests are in progress
**When** a new request arrives
**Then** the request receives HTTP 503 Service Unavailable with "Queue full"

---

## REQ-XNET-002: XNet Payload Builder

The XNet payload builder MUST construct and validate cross-subnet message payloads for consensus.

### SCENARIO-XNET-007: Payload construction from remote subnets
**Given** the payload builder constructs a payload
**When** building runs
**Then** it queries remote subnets for certified stream slices
**And** slices are validated against expected stream indices
**And** total payload size respects the configured byte limit

### SCENARIO-XNET-008: Certified slice pool management
**Given** certified stream slices are fetched from remote subnets
**When** they are cached
**Then** they are stored in a `CertifiedSlicePool` for reuse
**And** expired or already-processed slices are garbage collected

### SCENARIO-XNET-009: Proximity-based subnet ordering
**Given** determining which remote subnets to query
**When** priority is computed
**Then** subnets are ordered by proximity (latency/hops)
**And** closer subnets are given priority for inclusion

### SCENARIO-XNET-010: Payload validation
**Given** a proposed XNet payload is validated
**When** validation runs
**Then** all included stream slices are verified against expected begin indices
**And** the payload size is checked against maximum allowed
**And** the certification is validated against the subnet's public key

### SCENARIO-XNET-011: Stream message limits per subnet type
**Given** constructing a payload
**When** message limits are applied
**Then** for system subnets the limit is `SYSTEM_SUBNET_STREAM_MSG_LIMIT`
**And** for application subnets the limit is `MAX_STREAM_MESSAGES`

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-XNET-001 | XNet endpoint | narrative | rs/xnet/tests/ |
| REQ-XNET-002 | XNet payload builder | narrative | rs/xnet/payload_builder/ |
