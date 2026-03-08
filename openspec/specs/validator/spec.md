# Validator Specification

**Crates**: `ic-validator`, `ic-validator-ingress-message`, `ic-validator-http-request-arbitrary`

This specification covers the Validator subsystem (`rs/validator/`), which validates HTTP requests (ingress messages, queries, and read state requests) submitted to the Internet Computer.

---

## Requirements

### Requirement: HTTP Request Validation

The `HttpRequestVerifier` trait validates IC HTTP requests including signature verification, expiry checks, and delegation chain validation.

#### Scenario: Valid signed ingress request
- **WHEN** a signed ingress request is submitted
- **AND** the request has not expired (ingress expiry is within the valid window)
- **AND** the signature is valid
- **AND** the delegation chain (if any) is valid
- **AND** the request's target canister is within the delegation's allowed targets
- **THEN** validation succeeds and returns the set of canister IDs common to all delegations

#### Scenario: Valid anonymous query request
- **WHEN** a query request is submitted with an anonymous sender
- **THEN** the ingress expiry check is skipped
- **AND** the request is validated (anonymous queries do not require signatures)

#### Scenario: Valid non-anonymous query request
- **WHEN** a query request is submitted with a non-anonymous sender
- **THEN** the ingress expiry is validated
- **AND** the signature and delegation chain are verified

---

### Requirement: Ingress Expiry Validation

Requests must have an ingress expiry within the permitted time window.

#### Scenario: Request within valid expiry window
- **WHEN** a request has an ingress expiry between `current_time - PERMITTED_DRIFT_AT_VALIDATOR` and `current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR`
- **THEN** the expiry check passes

#### Scenario: Expired request
- **WHEN** a request has an ingress expiry before the current time minus the permitted drift
- **THEN** validation fails with an expiry error

#### Scenario: Request expiry too far in future
- **WHEN** a request has an ingress expiry beyond `current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR`
- **THEN** validation fails with an expiry error

---

### Requirement: Delegation Chain Validation

The validator verifies delegation chains attached to requests.

#### Scenario: Maximum delegation chain length
- **WHEN** a request has more than 20 delegations (MAXIMUM_NUMBER_OF_DELEGATIONS)
- **THEN** validation fails immediately without further verification

#### Scenario: Maximum targets per delegation
- **WHEN** a single delegation specifies more than 1,000 targets (MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION)
- **THEN** validation fails immediately without further verification

#### Scenario: Valid delegation chain
- **WHEN** all delegations in the chain are correctly signed
- **AND** no delegation has expired
- **AND** the chain contains no cycles
- **THEN** validation succeeds

#### Scenario: Expired delegation
- **WHEN** any delegation in the chain has expired relative to the current time
- **THEN** validation fails

#### Scenario: Delegation chain with cycle
- **WHEN** the delegation chain contains a cycle (a public key appears more than once)
- **THEN** validation fails

#### Scenario: Target canister not in delegation scope
- **WHEN** the request targets a canister not in the intersection of all delegations' target sets
- **THEN** validation fails

---

### Requirement: Signature Verification

The validator supports multiple signature algorithms.

#### Scenario: Ed25519 signature
- **WHEN** a request or delegation is signed with Ed25519
- **THEN** the signature is verified using the Ed25519 algorithm

#### Scenario: ECDSA secp256r1 (P-256) signature
- **WHEN** a request or delegation is signed with ECDSA on the P-256 curve
- **THEN** the signature is verified accordingly

#### Scenario: ECDSA secp256k1 signature
- **WHEN** a request or delegation is signed with ECDSA on the secp256k1 curve
- **THEN** the signature is verified accordingly

#### Scenario: RSA SHA-256 signature
- **WHEN** a request or delegation is signed with RSA SHA-256
- **THEN** the signature is verified accordingly

#### Scenario: Canister signature
- **WHEN** a request or delegation uses a canister signature
- **THEN** the signature is verified against the root of trust provided by the `RootOfTrustProvider`
- **AND** if no canister signatures are involved, the root of trust provider is not queried

---

### Requirement: WebAuthn Signature Support

The validator supports WebAuthn signatures as defined in the IC specification.

#### Scenario: Valid WebAuthn signature
- **WHEN** a request includes a WebAuthn signature
- **THEN** the `validate_webauthn_sig` function verifies the signature according to the WebAuthn standard

---

### Requirement: Nonce Size Limit

The validator enforces a maximum nonce size.

#### Scenario: Nonce within size limit
- **WHEN** a request includes a nonce of 32 bytes or fewer (MAXIMUM_NUMBER_OF_BYTES_IN_NONCE)
- **THEN** the nonce is accepted

#### Scenario: Nonce exceeds size limit
- **WHEN** a request includes a nonce larger than 32 bytes
- **THEN** validation fails

---

### Requirement: Read State Path Limits

The validator enforces limits on read state request paths.

#### Scenario: Paths within limit
- **WHEN** a read state request specifies 1,000 or fewer paths (MAXIMUM_NUMBER_OF_PATHS)
- **THEN** the paths are accepted

#### Scenario: Too many paths
- **WHEN** a read state request specifies more than 1,000 paths
- **THEN** validation fails

#### Scenario: Labels per path within limit
- **WHEN** each path in a read state request has 127 or fewer labels (MAXIMUM_NUMBER_OF_LABELS_PER_PATH)
- **THEN** the paths are accepted

#### Scenario: Too many labels in a path
- **WHEN** a single path has more than 127 labels
- **THEN** validation fails

---

### Requirement: Canister ID Set

The validator returns a `CanisterIdSet` indicating which canisters the validated request is authorized to target.

#### Scenario: No delegations - all canisters allowed
- **WHEN** a request has no delegations (or delegations without target restrictions)
- **THEN** `CanisterIdSet::all()` is returned

#### Scenario: Delegations with targets - intersection returned
- **WHEN** a request has delegations with specified target canister IDs
- **THEN** the intersection of all delegations' target sets is returned

---

### Requirement: Ingress Message Validation (ingress_message crate)

The `ic_validator_ingress_message` crate (`rs/validator/ingress_message/`) provides additional validation for ingress messages used internally.

#### Scenario: Validate ingress request
- **WHEN** an internal component validates an ingress request
- **THEN** it uses the `HttpRequestVerifier` implementation with the appropriate root of trust provider

---

### Requirement: HTTP Request Test Utilities

The `http_request_test_utils` crate provides test helpers for constructing and validating HTTP requests.

#### Scenario: Construct test requests
- **WHEN** tests need to validate request handling
- **THEN** the test utilities provide builders for constructing valid and invalid HTTP requests with various signatures and delegation chains

---

### Requirement: Fuzz Testing Support

The validator includes fuzz testing targets for robustness.

#### Scenario: Fuzz signed ingress validation
- **WHEN** arbitrary byte sequences are provided as signed ingress messages
- **THEN** the validator handles them without panicking

#### Scenario: Fuzz request validation
- **WHEN** arbitrary HTTP request structures are provided
- **THEN** the validator handles them without panicking
