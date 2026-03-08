# NNS Delegation Manager Specification

**Crate:** `ic-nns-delegation-manager`
**Path:** `rs/http_endpoints/nns_delegation_manager/`

## Overview

The NNS Delegation Manager is responsible for periodically fetching NNS delegation certificates from the NNS subnet and making them available to non-NNS subnets. These delegations allow non-NNS subnets to issue certified responses on behalf of the NNS. The module provides:

1. **NNSDelegationManager** -- A background task that periodically fetches delegations from the NNS subnet over TLS-secured HTTP connections.
2. **NNSDelegationReader** -- A reader (backed by a `tokio::sync::watch` channel) that provides the latest delegation to callers with configurable canister range filtering.
3. **NNSDelegationBuilder** -- A builder that parses raw NNS certificates, precomputes filtered variants, and constructs `CertificateDelegation` values on demand.
4. **CanisterRangesFilter** -- An enum controlling which canister range data is included in the returned delegation.
5. **DelegationManagerMetrics** -- Prometheus metrics tracking update counts, durations, delegation sizes, and errors.

## Requirements

### Requirement: Periodic Delegation Fetching

The delegation manager spawns a background task that periodically fetches the NNS delegation certificate from a randomly selected NNS subnet node.

#### Scenario: Non-NNS subnet fetches delegation on startup
- **WHEN** `start_nns_delegation_manager` is called with a `subnet_id` different from `nns_subnet_id`
- **THEN** the manager immediately fetches a delegation from a random NNS node
- **AND** the delegation is made available through the returned `NNSDelegationReader`
- **AND** the `NNSDelegationReader::get_delegation` returns `Some(CertificateDelegation)`

#### Scenario: NNS subnet returns no delegation
- **WHEN** `start_nns_delegation_manager` is called with `subnet_id` equal to `nns_subnet_id`
- **THEN** the manager does not attempt to fetch any delegation
- **AND** `NNSDelegationReader::get_delegation` returns `None`
- **AND** the reader is still marked as initialized (notifying waiters)

#### Scenario: Periodic refresh after interval
- **WHEN** the delegation manager has fetched an initial delegation
- **THEN** it waits for `DELEGATION_UPDATE_INTERVAL` (5 minutes in production, 5 seconds in tests) before fetching a new delegation
- **AND** a new fetch is not triggered before that interval elapses
- **AND** after the interval, a fresh delegation replaces the previous one if different

#### Scenario: Delegation is unchanged
- **WHEN** the delegation manager fetches a new delegation identical to the current one
- **THEN** the `watch::Sender` does not notify receivers of a change
- **AND** the existing delegation remains available

### Requirement: Delegation Validation

Fetched delegations are validated against the registry and the NNS root public key before being accepted.

#### Scenario: Valid delegation accepted
- **WHEN** a delegation is fetched from an NNS node
- **AND** the CBOR response can be deserialized into an `HttpReadStateResponse`
- **AND** the certificate contains a `/subnet/<subnet_id>/public_key` leaf matching the registry
- **AND** the delegation certificate passes `validate_subnet_delegation_certificate` with the NNS root threshold public key
- **THEN** the delegation is accepted and published to readers

#### Scenario: Invalid delegation rejected
- **WHEN** a delegation is fetched from an NNS node
- **AND** the CBOR response cannot be deserialized, or the public key does not match the registry, or the certificate fails validation
- **THEN** the delegation is rejected
- **AND** the `errors` metric counter is incremented
- **AND** the manager retries after a random backoff (1 to 15 seconds)
- **AND** the previously valid delegation (if any) remains available to readers

#### Scenario: Public key mismatch
- **WHEN** the public key in the fetched delegation certificate does not match the subnet's public key from the registry
- **THEN** an error is returned with a message indicating "invalid public key type in certificate"
- **AND** the delegation is not published

### Requirement: Canister Ranges Filtering

The `NNSDelegationReader` supports three canister range filtering modes, controlling which canister range information is included in the returned delegation.

#### Scenario: Flat filter retains old-format canister ranges
- **WHEN** `get_delegation(CanisterRangesFilter::Flat)` is called
- **THEN** the returned delegation includes the `/subnet/<subnet_id>/canister_ranges` leaf (old format)
- **AND** the `/canister_ranges` subtree (new format) is pruned from the certificate tree
- **AND** the delegation is still verifiable against the NNS root public key

#### Scenario: None filter removes all canister ranges
- **WHEN** `get_delegation(CanisterRangesFilter::None)` is called
- **THEN** the returned delegation does not include `/canister_ranges` (new format)
- **AND** the returned delegation does not include `/subnet/<subnet_id>/canister_ranges` (old format)
- **AND** the delegation is still verifiable against the NNS root public key (without canister ID verification)

#### Scenario: Tree filter retains only the relevant canister range leaf
- **WHEN** `get_delegation(CanisterRangesFilter::Tree(canister_id))` is called
- **AND** the `canister_id` falls within a canister range assigned to the subnet
- **THEN** the returned delegation includes only the `/canister_ranges/<subnet_id>/<lower_bound>` leaf containing the range that covers the canister
- **AND** the `/subnet/<subnet_id>/canister_ranges` leaf (old format) is pruned
- **AND** all other `/canister_ranges/<subnet_id>/*` leaves are pruned
- **AND** the delegation is verifiable for that specific canister ID

#### Scenario: Tree filter with canister out of range
- **WHEN** `get_delegation(CanisterRangesFilter::Tree(canister_id))` is called
- **AND** the `canister_id` is not covered by any range in the delegation
- **THEN** the returned delegation includes neither `/canister_ranges` nor `/subnet/<subnet_id>/canister_ranges`
- **AND** the delegation is still verifiable without a canister ID

### Requirement: Precomputed Delegations

The `NNSDelegationBuilder` precomputes delegations for the `Flat` and `None` filter modes to avoid repeated computation on every read.

#### Scenario: Flat and None delegations are precomputed
- **WHEN** a new `NNSDelegationBuilder` is created from a raw certificate
- **THEN** it immediately computes and caches the `Flat`-filtered delegation
- **AND** it immediately computes and caches the `None`-filtered delegation
- **AND** subsequent calls to `build_or_original(Flat)` and `build_or_original(None)` return clones without recomputation

#### Scenario: Tree delegations are computed on demand
- **WHEN** `build_or_original(Tree(canister_id))` is called
- **THEN** the delegation is computed dynamically for that specific canister ID
- **AND** the result is not cached (each call recomputes)

#### Scenario: Fallback to original delegation on build failure
- **WHEN** building a filtered delegation fails for any reason
- **THEN** a warning is logged (throttled to once per 30 seconds)
- **AND** the original unfiltered delegation is returned instead
- **AND** in debug builds, the failure causes a panic

### Requirement: Metadata Reporting

The reader can return delegation metadata alongside the delegation itself.

#### Scenario: Metadata matches filter type
- **WHEN** `get_delegation_with_metadata(CanisterRangesFilter::Flat)` is called
- **THEN** the returned metadata has format `CertificateDelegationFormat::Flat`

#### Scenario: Metadata for Tree filter
- **WHEN** `get_delegation_with_metadata(CanisterRangesFilter::Tree(_))` is called
- **THEN** the returned metadata has format `CertificateDelegationFormat::Tree`

#### Scenario: Metadata for None filter
- **WHEN** `get_delegation_with_metadata(CanisterRangesFilter::None)` is called
- **THEN** the returned metadata has format `CertificateDelegationFormat::Pruned`

### Requirement: TLS-Secured Connections to NNS Nodes

The delegation manager establishes TLS connections to NNS nodes using the IC's TLS infrastructure.

#### Scenario: Connecting to a random NNS node
- **WHEN** the manager needs to fetch a delegation
- **THEN** it selects a random node from the NNS subnet node list in the registry
- **AND** it establishes a TCP connection to that node's HTTP endpoint
- **AND** it performs a TLS handshake using the IC TLS configuration
- **AND** it sends a `read_state` HTTP POST request to `/api/v2/subnet/<nns_subnet_id>/read_state`

#### Scenario: Connection timeout
- **WHEN** the TCP/TLS connection to the NNS node cannot be established within `CONNECTION_TIMEOUT` (10 seconds in production)
- **THEN** the connection attempt fails with a timeout error
- **AND** the manager retries with a random backoff

#### Scenario: Request send timeout
- **WHEN** the HTTP request cannot be sent within `NNS_DELEGATION_REQUEST_SEND_TIMEOUT` (10 seconds in production)
- **THEN** the request fails with a timeout error
- **AND** the manager retries with a random backoff

#### Scenario: Response body timeout
- **WHEN** the HTTP response body is not fully received within `NNS_DELEGATION_BODY_RECEIVE_TIMEOUT` (5 minutes in production)
- **THEN** the response fails with a timeout error
- **AND** the manager retries with a random backoff

#### Scenario: Response body size limit
- **WHEN** the HTTP response body exceeds `config.max_delegation_certificate_size_bytes`
- **THEN** the response is rejected with a size limit error
- **AND** the manager retries with a random backoff

### Requirement: Read State Request Construction

The manager constructs a properly formatted `read_state` request to fetch the delegation certificate.

#### Scenario: Request paths
- **WHEN** a `read_state` request is constructed for `subnet_id`
- **THEN** it requests the path `/subnet/<subnet_id>/public_key`
- **AND** it requests the path `/subnet/<subnet_id>/canister_ranges` (old format)
- **AND** it requests the path `/canister_ranges/<subnet_id>` (new format)
- **AND** the sender is the anonymous principal (`[4]`)
- **AND** the content type is `application/cbor`

### Requirement: Metrics

The delegation manager exposes Prometheus metrics for observability.

#### Scenario: Update count metric
- **WHEN** a delegation fetch completes (success or failure)
- **THEN** the `nns_delegation_manager_updates_total` counter is incremented

#### Scenario: Update duration metric
- **WHEN** a delegation fetch completes
- **THEN** the `nns_delegation_manager_update_duration_seconds` histogram records the duration

#### Scenario: Error count metric
- **WHEN** a delegation fetch fails
- **THEN** the `nns_delegation_manager_errors_total` counter is incremented

#### Scenario: Delegation size metrics
- **WHEN** a delegation is successfully fetched
- **THEN** the `nns_delegation_manager_delegation_size_bytes` histogram records sizes for labels:
  - `both_canister_ranges` (original full delegation)
  - `no_canister_ranges` (None-filtered delegation)
  - `flat_canister_ranges` (Flat-filtered delegation)

### Requirement: Initialization Awaiting

The `NNSDelegationReader` supports waiting until the first delegation fetch completes.

#### Scenario: Wait until initialized
- **WHEN** `wait_until_initialized()` is called on a reader before the first fetch completes
- **THEN** the call blocks asynchronously until the delegation manager publishes its first value (which may be `None` on NNS subnet or `Some` on non-NNS)
- **AND** the method returns `Ok(())` on success

### Requirement: Cancellation Support

The delegation manager supports graceful shutdown via a `CancellationToken`.

#### Scenario: Cancellation stops the manager
- **WHEN** the `CancellationToken` passed to `start_nns_delegation_manager` is cancelled
- **THEN** the background delegation fetching task terminates
- **AND** the `JoinHandle` resolves
