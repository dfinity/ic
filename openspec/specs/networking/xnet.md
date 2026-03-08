# Cross-Net (XNet) Messaging

**Crates**: `ic-xnet-hyper`, `ic-xnet-payload-builder`, `ic-xnet-uri`

## Requirements

### Requirement: XNet Endpoint

The XNet endpoint serves certified stream slices over HTTPS to other subnets for cross-subnet messaging.

#### Scenario: Endpoint startup
- **WHEN** the XNet endpoint is created
- **THEN** a TCP listener is bound to the configured address (`xnet_ip_addr:xnet_port`)
- **AND** TLS is configured to accept connections from all nodes (`SomeOrAllNodes::All`)
- **AND** ALPN protocols `h2` and `http/1.1` are advertised

#### Scenario: List available streams
- **WHEN** a request is received at `/api/v1/streams`
- **THEN** a JSON array of subnet IDs with available certified streams is returned

#### Scenario: Fetch stream slice
- **WHEN** a request is received at `/api/v1/stream/{SubnetId}`
- **THEN** a certified stream slice for the given subnet is returned as protobuf
- **AND** the response content type is `application/x-protobuf`
- **AND** `X-Protobuf-Schema` and `X-Protobuf-Message` headers are included

#### Scenario: Stream slice with query parameters
- **WHEN** a stream request includes query parameters `msg_begin`, `witness_begin`, `msg_limit`, and/or `byte_limit`
- **THEN** the stream slice begins at the specified message index
- **AND** the witness begins at `witness_begin` (or `msg_begin` if not specified)
- **AND** the slice contains at most `msg_limit` messages
- **AND** the slice does not exceed `byte_limit` bytes

#### Scenario: Non-existent stream
- **WHEN** a stream is requested for a subnet with no available stream
- **THEN** HTTP 204 No Content is returned

#### Scenario: Invalid slice begin index
- **WHEN** a stream request specifies a `msg_begin` that is out of range
- **THEN** HTTP 416 Range Not Satisfiable is returned

#### Scenario: Invalid slice indices
- **WHEN** a stream request specifies inconsistent indices
- **THEN** HTTP 400 Bad Request is returned

#### Scenario: Invalid subnet ID in URL
- **WHEN** the subnet ID in the URL cannot be parsed as a `PrincipalId`
- **THEN** HTTP 400 Bad Request is returned with "Invalid subnet ID" message

#### Scenario: Unknown URL path
- **WHEN** a request is received at an unrecognized URL path
- **THEN** HTTP 404 Not Found is returned

#### Scenario: Concurrent request limiting
- **WHEN** more than 4 concurrent requests are being processed (`XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS`)
- **THEN** excess requests receive HTTP 503 Service Unavailable with "Queue full"

#### Scenario: Graceful shutdown
- **WHEN** the `XNetEndpoint` is dropped
- **THEN** a shutdown notification is sent
- **AND** the HTTP server performs a graceful shutdown

### Requirement: XNet Payload Builder

The XNet payload builder constructs and validates cross-subnet message payloads for consensus blocks.

#### Scenario: Payload construction from remote subnets
- **WHEN** the payload builder is asked to construct a payload
- **THEN** it queries remote subnets for certified stream slices
- **AND** slices are validated against the expected stream indices
- **AND** the total payload size respects the configured byte limit

#### Scenario: Certified slice pool management
- **WHEN** certified stream slices are fetched from remote subnets
- **THEN** they are cached in a `CertifiedSlicePool` for reuse
- **AND** expired or already-processed slices are garbage collected

#### Scenario: Proximity-based subnet ordering
- **WHEN** deciding which remote subnets to query for stream slices
- **THEN** subnets are ordered by proximity (latency/hops)
- **AND** closer subnets are given priority for inclusion in the payload

#### Scenario: XNet client HTTP requests
- **WHEN** the payload builder needs to fetch a stream slice from a remote subnet
- **THEN** an HTTPS request is made to the remote subnet's XNet endpoint
- **AND** TLS mutual authentication is used
- **AND** the response is decoded from protobuf `CertifiedStreamSlice`

#### Scenario: Payload validation
- **WHEN** a proposed XNet payload is validated
- **THEN** all included stream slices are verified against expected begin indices
- **AND** the payload size is checked against the maximum allowed size
- **AND** the certification is validated against the subnet's public key

#### Scenario: Stream message limits
- **WHEN** constructing a payload for a system subnet
- **THEN** the stream message limit is `SYSTEM_SUBNET_STREAM_MSG_LIMIT`
- **AND** for application subnets, the limit is `MAX_STREAM_MESSAGES`
