# Canister Client

**Crates**: `ic-canister-client-sender`

## Requirements

### Requirement: Agent for IC Public Endpoints

The canister client provides an `Agent` abstraction for programmatic interaction with the IC public HTTP API, supporting update calls, query calls, and status checks.

#### Scenario: Agent creation
- **WHEN** an `Agent` is created with a URL and sender
- **THEN** it is configured with default timeouts (ingress: 6 minutes, query: 30 seconds)
- **AND** the sender's principal ID is used as the sender field in requests

#### Scenario: Query call execution
- **WHEN** `execute_query` is called with a canister ID, method name, and arguments
- **THEN** a signed query request is prepared with the sender's credentials
- **AND** the request is POSTed to `/api/v2/canister/{canister_id}/query`
- **AND** the CBOR response is parsed and the reply payload is returned
- **AND** if the status is not "replied", an error is returned with the reject message

#### Scenario: Update call execution with polling
- **WHEN** `execute_update` is called
- **THEN** the signed update request is POSTed to `/api/v2/canister/{effective_canister_id}/call`
- **AND** after a 2-second initial delay, the request status is polled via `read_state`
- **AND** polling uses exponential backoff (500ms to 10s, multiplier 1.2)
- **AND** polling continues until a terminal state ("replied", "done", or error) or the ingress timeout

#### Scenario: Update call terminal states
- **WHEN** polling the request status
- **AND** the status is "replied"
- **THEN** the reply payload is returned
- **WHEN** the status is "done"
- **THEN** an error is returned indicating the reply data has been pruned
- **WHEN** the status is "unknown", "received", or "processing"
- **THEN** polling continues

#### Scenario: Read state request
- **WHEN** `wait_ingress` is called with a message ID
- **THEN** a signed `read_state` request is prepared with the request status path
- **AND** the request is POSTed to `/api/v2/canister/{effective_canister_id}/read_state`
- **AND** the CBOR response is parsed to extract the request status

#### Scenario: Status endpoint query
- **WHEN** `get_status` is called
- **THEN** a GET request is made to `/api/v2/status`
- **AND** the CBOR response is deserialized into an `HttpStatusResponse`

#### Scenario: Health check
- **WHEN** `is_replica_healthy` is called
- **THEN** the status endpoint is queried
- **AND** `true` is returned only if the health status is `Healthy`

#### Scenario: Root key retrieval
- **WHEN** `root_key` is called
- **THEN** the status endpoint is queried
- **AND** the root key blob is returned (if present)

#### Scenario: CUP endpoint query
- **WHEN** `query_cup_endpoint` is called with optional catch-up package parameters
- **THEN** a POST request is made to `/_/catch_up_package`
- **AND** the protobuf-encoded `CatchUpPackage` response is decoded and returned

#### Scenario: Canister installation
- **WHEN** `install_canister` is called with `InstallCodeArgs`
- **THEN** an update call to the management canister (`IC_00`) with method `InstallCode` is executed

### Requirement: HTTP Client

The underlying HTTP client handles the actual HTTP communication with configurable behavior.

#### Scenario: POST with response
- **WHEN** `post_with_response` is called with a URL, path, body, and deadline
- **THEN** the request is sent as an HTTP POST
- **AND** the response body bytes are returned
- **AND** the operation respects the provided deadline

#### Scenario: GET with response
- **WHEN** `get_with_response` is called with a URL, path, and deadline
- **THEN** the request is sent as an HTTP GET
- **AND** the response body bytes are returned

### Requirement: Sender Authentication

The `Sender` component handles cryptographic signing of requests.

#### Scenario: Anonymous sender
- **WHEN** the sender is anonymous
- **THEN** requests are sent without signatures
- **AND** the sender principal is the anonymous principal

#### Scenario: Authenticated sender
- **WHEN** the sender has a key pair (Ed25519 or secp256k1)
- **THEN** requests are signed with the sender's private key
- **AND** the public key and signature are included in the request envelope

### Requirement: Read State Response Parser

Parses read_state responses to extract request status information.

#### Scenario: Request status parsing
- **WHEN** a read_state CBOR response is parsed
- **THEN** the request status (replied/rejected/done/unknown/received/processing) is extracted
- **AND** for "replied" status, the reply payload is extracted
- **AND** for "rejected" status, the reject code and message are extracted
