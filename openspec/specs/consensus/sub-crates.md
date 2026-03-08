# Consensus Sub-Crate Specifications

## Crate: ic-consensus-certification

The certification component is responsible for reaching consensus on parts of the replicated state produced by the upper layers by signing state hashes. It uses threshold BLS signatures to create certifications that attest to the correctness of the replicated state at a given height.

### Requirements

### Requirement: Certification Share Creation
Replicas that belong to the threshold committee at a given height must create and sign certification shares for state hashes provided by the state manager.

#### Scenario: Replica creates a certification share for a new state hash
- **WHEN** the state manager provides a (height, hash, witness) tuple for certification
- **AND** the replica belongs to the threshold committee at that height
- **AND** the replica has not already issued a share for that height
- **AND** an active high-threshold NiDKG ID exists for the height
- **THEN** the replica signs the hash using threshold signing with the NiDKG ID
- **AND** adds the resulting CertificationShare to the certification pool as a validated artifact

#### Scenario: Replica skips certification for non-committee heights
- **WHEN** the state manager provides a (height, hash, witness) tuple for certification
- **AND** the replica does NOT belong to the threshold committee at that height
- **THEN** no certification share is created for that height

#### Scenario: Replica skips duplicate share creation
- **WHEN** the state manager provides a (height, hash, witness) tuple for certification
- **AND** the replica has already issued a share at that height in the certification pool
- **THEN** no additional certification share is created

### Requirement: Certification Aggregation
When sufficiently many certification shares for the same (height, witness, hash) tuple are available, they must be aggregated into a full Certification.

#### Scenario: Shares are aggregated into a full certification
- **WHEN** enough certification shares for the same height exist in the pool
- **AND** the shares meet the threshold requirement for the committee
- **THEN** the shares are combined into a full Certification using threshold signature aggregation
- **AND** the full Certification is added to the certification pool

#### Scenario: Insufficient shares prevent aggregation
- **WHEN** certification shares exist for a height but do not meet the threshold
- **THEN** no full Certification is aggregated for that height

### Requirement: Certification Delivery
Full certifications must be delivered to the state manager so the certified state can be used by other components.

#### Scenario: Full certification is delivered to the state manager
- **WHEN** a full Certification exists in the pool for a given height
- **AND** the state manager has requested certification for that height
- **THEN** the Certification is delivered to the state manager
- **AND** the last certified height metric is updated

### Requirement: Certification Validation
Unvalidated certifications and shares received from peers must be cryptographically validated before acceptance.

#### Scenario: Valid full certification is accepted
- **WHEN** an unvalidated Certification is received for a height
- **AND** the height witness is valid for the certified hash
- **AND** the combined threshold signature is valid for the subnet at the registry version
- **THEN** the Certification is moved to the validated pool

#### Scenario: Invalid certification signature is rejected
- **WHEN** an unvalidated Certification is received for a height
- **AND** the combined threshold signature verification fails with an invalid artifact error
- **THEN** the Certification is marked as invalid

#### Scenario: Valid share is accepted after committee and signature checks
- **WHEN** an unvalidated CertificationShare is received
- **AND** the height witness is valid
- **AND** the signer belongs to the threshold committee at the share's height
- **AND** the signer has not already submitted a validated share at that height
- **AND** the threshold signature share is cryptographically valid
- **THEN** the share is moved to the validated pool

#### Scenario: Share from non-committee member is rejected
- **WHEN** an unvalidated CertificationShare is received
- **AND** the signer does NOT belong to the threshold committee at the share's height
- **THEN** the share is marked as invalid with reason "Signer does not belong to the committee"

#### Scenario: Duplicate share from same signer is removed
- **WHEN** an unvalidated CertificationShare is received
- **AND** the signer already has a validated share at that height
- **THEN** the share is removed from the unvalidated pool

### Requirement: Certification Pool Purging
Certification artifacts below the catch-up package height must be purged to prevent unbounded pool growth.

#### Scenario: Artifacts below CUP height are purged
- **WHEN** the catch-up package height increases
- **AND** the new purge height (CUP height minus MINIMUM_CHAIN_LENGTH) exceeds the previously purged height
- **THEN** all certification artifacts below the purge height are removed from the pool

### Requirement: Certification Bouncer (Artifact Priority)
The bouncer determines which certification artifacts should be fetched from peers.

#### Scenario: Artifacts below CUP height are unwanted
- **WHEN** a certification artifact is advertised with a height below the current CUP height
- **THEN** the bouncer returns Unwanted

#### Scenario: Artifacts at already-certified heights are unwanted
- **WHEN** a certification artifact is advertised for a height that already has a full certification
- **THEN** the bouncer returns Unwanted

#### Scenario: Artifacts above CUP height without certification are wanted
- **WHEN** a certification artifact is advertised for a height above the CUP height
- **AND** no full certification exists at that height
- **THEN** the bouncer returns Wants

---

## Crate: ic-consensus-cup-utils

This crate provides utility functions for constructing Catch-Up Packages (CUPs) from registry data. CUPs are used during genesis and subnet recovery to bootstrap a subnet with a valid initial state.

### Requirements

### Requirement: Registry CUP Construction
A CUP must be constructible from registry-stored CUP contents for a given subnet.

#### Scenario: Successful CUP construction from registry
- **WHEN** `make_registry_cup` is called with a valid registry client, subnet ID, and logger
- **AND** the registry contains valid CUP contents for the subnet at the latest version
- **AND** the registry contains a valid subnet record with a replica version
- **AND** the CUP contents include valid low-threshold and high-threshold NiDKG transcripts
- **THEN** a CatchUpPackage is returned containing:
  - A Block at the height specified in the CUP contents
  - A ValidationContext with the registry version and certified height equal to the CUP height
  - A RandomBeacon signed with the low-threshold DKG ID
  - The CUP signed with the high-threshold DKG ID
  - The state hash from the CUP contents

#### Scenario: CUP construction fails with missing replica version
- **WHEN** `make_registry_cup` is called
- **AND** the registry does not contain a replica version for the subnet at the registry version
- **THEN** None is returned
- **AND** a warning is logged

#### Scenario: CUP construction fails with missing DKG transcripts
- **WHEN** `make_registry_cup_from_cup_contents` is called
- **AND** the DKG summary is missing a current low-threshold or high-threshold transcript
- **THEN** None is returned
- **AND** a warning is logged

#### Scenario: CUP construction fails with invalid DKG summary
- **WHEN** `make_registry_cup_from_cup_contents` is called
- **AND** the NiDKG summary cannot be constructed from the CUP contents
- **THEN** None is returned
- **AND** a warning is logged

### Requirement: IDKG Bootstrap Summary in CUP
CUPs must include an IDKG summary when chain key configurations or initial dealings are present.

#### Scenario: IDKG summary bootstrapped from initial dealings
- **WHEN** CUP contents include ECDSA initializations or chain key initializations
- **THEN** the IDKG summary is constructed from those initial dealings using `make_bootstrap_summary_with_initial_dealings`
- **AND** the summary is included in the CUP's SummaryPayload

#### Scenario: IDKG summary bootstrapped from registry config
- **WHEN** CUP contents do NOT include initial dealings
- **AND** the registry has an IDKG chain key config enabled for the subnet
- **THEN** a bootstrap IDKG summary is created from the chain key config's key IDs
- **AND** the summary is included in the CUP's SummaryPayload

#### Scenario: No IDKG summary when no chain key config exists
- **WHEN** CUP contents do NOT include initial dealings
- **AND** the registry does NOT have an IDKG chain key config for the subnet
- **THEN** the IDKG summary in the CUP is None

### Requirement: NNS Recovery Registry Version Override
During NNS subnet recovery, the block validation context must reference the recovery registry version.

#### Scenario: Registry version overridden during NNS recovery
- **WHEN** the CUP contents include a `registry_store_uri` with a `registry_version`
- **THEN** the block's validation context uses the registry version from `registry_store_uri`
- **AND** this ensures the validation context points to a registry version that contains the NNS subnet record

#### Scenario: Normal registry version used without recovery
- **WHEN** the CUP contents do NOT include a `registry_store_uri`
- **THEN** the block's validation context uses the standard registry version passed to the function

---

## Crate: ic-consensus-features

This crate defines feature flags that control consensus behavior. It provides compile-time constants that gate experimental or incremental features.

### Requirements

### Requirement: Hashes-in-Blocks Feature Flag
The `HASHES_IN_BLOCKS_ENABLED` flag controls whether block proposals strip full ingress messages and IDKG dealings, replacing them with hashes.

#### Scenario: Hashes-in-blocks is enabled
- **WHEN** `HASHES_IN_BLOCKS_ENABLED` is `true`
- **THEN** block proposers strip all ingress messages and IDKG dealings from blocks before sending to peers
- **AND** block proposers include only hashes/references for the stripped content

#### Scenario: Receivers reconstruct blocks from hashes
- **WHEN** `HASHES_IN_BLOCKS_ENABLED` is `true`
- **AND** a block is received containing hashes instead of full content
- **THEN** the receiver reconstructs the block by looking up referenced ingress messages in the ingress pool
- **AND** the receiver looks up referenced IDKG dealings in the IDKG pool
- **AND** if artifacts are not found locally, the receiver fetches them from peers advertising the block

---

## Crate: ic-consensus-idkg

The IDKG (Interactive Distributed Key Generation) consensus crate orchestrates the creation of threshold key transcripts used for canister threshold signatures (ECDSA, Schnorr) and vetKD key derivation. It manages the full lifecycle of pre-signatures, signature shares, complaints, and openings.

### Requirements

### Requirement: IDKG Dealing Creation
Replicas that are dealers for a transcript configuration must create and submit dealings.

#### Scenario: Dealer creates a dealing for a requested transcript
- **WHEN** the finalized tip contains a transcript configuration
- **AND** this replica is listed as a dealer in that configuration
- **AND** this replica has not already issued a dealing for this transcript
- **AND** the transcript dependencies load successfully
- **THEN** the replica creates a dealing for the transcript and adds it to the validated pool

#### Scenario: Dealer sends complaint when dependencies fail to load
- **WHEN** the finalized tip contains a transcript configuration
- **AND** this replica is a dealer in that configuration
- **AND** loading the transcript dependencies fails
- **THEN** the replica sends a complaint for the transcript that failed to load

### Requirement: IDKG Dealing Validation
Dealings received from peer dealers must be publicly verified before acceptance.

#### Scenario: Valid dealing is moved to validated pool
- **WHEN** an unvalidated dealing is received
- **AND** the dealing's config ID matches a configuration in the finalized tip
- **AND** the dealer is listed in the configuration's dealer list
- **AND** no dealing from the same dealer for the same config exists in the validated pool
- **AND** the public cryptographic validation of the dealing succeeds
- **THEN** the dealing is moved to the validated pool

#### Scenario: Invalid dealing is removed from unvalidated pool
- **WHEN** an unvalidated dealing is received
- **AND** the public cryptographic validation of the dealing fails
- **THEN** the dealing is removed from the unvalidated pool

#### Scenario: Dealing from non-dealer is rejected
- **WHEN** an unvalidated dealing is received
- **AND** the dealing's dealer is NOT in the configuration's dealer list
- **THEN** the dealing is marked as invalid

### Requirement: IDKG Dealing Support (Private Verification)
Validated dealings must be privately verified by each replica to confirm they encrypt a correct share.

#### Scenario: Replica creates support for a valid dealing
- **WHEN** a validated dealing exists in the pool
- **AND** no support message from this replica exists for the dealing
- **AND** the private cryptographic validation succeeds
- **THEN** a dealing support message is created and added to the validated pool

### Requirement: Stale Artifact Removal
Dealings and support messages for configurations no longer in the finalized tip must be purged.

#### Scenario: Stale dealing is removed
- **WHEN** a validated or unvalidated dealing exists in the pool
- **AND** its config ID is NOT in the finalized tip's configurations
- **AND** the config ID is older than the finalized tip
- **THEN** the dealing is removed from the pool

### Requirement: Signature Share Creation
Replicas must create signature shares for pending signature requests.

#### Scenario: Signer creates a share for a pending request
- **WHEN** the certified state contains a signature request
- **AND** this replica is a signer for the request
- **AND** no signature share from this replica exists in the validated pool for this request
- **AND** the pre-signature and key transcripts load successfully
- **THEN** a signature share is created and added to the validated pool

#### Scenario: ECDSA signature share is created
- **WHEN** a signature request uses ECDSA threshold arguments
- **AND** the inputs (kappa_unmasked, lambda_masked, key_times_lambda, kappa_times_lambda) are available
- **THEN** an ECDSA signature share is created

#### Scenario: Schnorr signature share is created
- **WHEN** a signature request uses Schnorr threshold arguments
- **AND** the blinder transcript is available
- **THEN** a Schnorr signature share is created

#### Scenario: VetKD key share is created
- **WHEN** a signature request uses VetKD threshold arguments
- **AND** the NiDKG transcript data is available
- **THEN** a VetKD encrypted key share is created

### Requirement: Signature Share Validation
Signature shares from peers must be validated before acceptance.

#### Scenario: Valid signature share is accepted
- **WHEN** an unvalidated signature share is received
- **AND** the share's request ID matches a request in the certified state
- **AND** no share from the same signer for the same request exists in the validated pool
- **AND** cryptographic verification of the share succeeds
- **THEN** the share is moved to the validated pool

#### Scenario: Invalid signature share is rejected
- **WHEN** an unvalidated signature share is received
- **AND** cryptographic verification fails with a reproducible error
- **THEN** the share is removed from the unvalidated pool

### Requirement: Complaint Handling
When a transcript fails to load due to a corrupted dealing, a complaint must be filed and processed.

#### Scenario: Complaint is validated
- **WHEN** an unvalidated complaint is received
- **AND** the complaint's transcript ID matches an active transcript
- **AND** the complainer has not already filed a complaint for this transcript and dealer
- **AND** the complaint's cryptographic signature and content are valid
- **THEN** the complaint is moved to the validated pool

#### Scenario: Duplicate complaint is rejected
- **WHEN** an unvalidated complaint is received
- **AND** the complainer has already filed a complaint for the same transcript and dealer
- **THEN** the complaint is removed from the unvalidated pool

### Requirement: Opening Creation and Validation
In response to validated complaints, replicas must create openings to help reconstruct the corrupted share.

#### Scenario: Replica creates an opening for a peer's complaint
- **WHEN** a validated complaint exists from another replica
- **AND** this replica has not already sent an opening for this complaint
- **AND** the transcript for the complaint is available
- **THEN** the replica creates and signs an opening and adds it to the validated pool

#### Scenario: Replica does not create opening for own complaint
- **WHEN** a validated complaint exists
- **AND** the complaint was filed by this replica
- **THEN** no opening is created for that complaint

### Requirement: Inactive Transcript Purging
Transcripts no longer referenced by the blockchain or replicated state must be periodically purged from the crypto component.

#### Scenario: Inactive transcripts are purged periodically
- **WHEN** at least INACTIVE_TRANSCRIPT_PURGE_SECS (60 seconds) have elapsed since the last purge
- **THEN** active transcripts are collected from the finalized chain, pre-signature stashes, and ongoing signature requests
- **AND** `retain_active_transcripts` is called on the crypto component with only the active transcript set

#### Scenario: Active transcripts include chain, stash, and request transcripts
- **WHEN** active transcripts are collected
- **THEN** transcripts referenced by the finalized blockchain are included
- **AND** key transcripts from pre-signature stashes in the certified state are included
- **AND** transcripts paired with ongoing signature request contexts are included

### Requirement: IDKG Artifact Bouncer (Priority)
The bouncer determines which IDKG artifacts should be fetched based on height proximity.

#### Scenario: Cross-subnet dealings are always wanted
- **WHEN** a dealing or dealing support artifact is from a different subnet
- **THEN** the bouncer returns Wants regardless of height

#### Scenario: Local dealings within look-ahead range are wanted
- **WHEN** a dealing artifact's source height is at most LOOK_AHEAD (10) blocks ahead of the finalized height
- **THEN** the bouncer returns Wants

#### Scenario: Artifacts beyond look-ahead range are deferred
- **WHEN** an artifact's height exceeds finalized_height + LOOK_AHEAD (for dealings/complaints/openings) or certified_height + LOOK_AHEAD (for signature shares)
- **THEN** the bouncer returns MaybeWantsLater

### Requirement: IDKG Payload Building
Block makers must assemble IDKG payloads containing transcript configurations, completed transcripts, and aggregated signatures.

#### Scenario: Summary payload is created at DKG interval boundaries
- **WHEN** a summary block is being created
- **AND** a chain key config exists for the subnet
- **THEN** a summary payload is created containing the current key transcripts, resharing state, and pre-signature references

#### Scenario: Data payload includes newly completed transcripts
- **WHEN** a data block is being created
- **AND** transcript configurations have sufficient dealings and support in the pool
- **THEN** completed transcripts are aggregated and included in the data payload

#### Scenario: Bootstrap summary initializes key transcript creation
- **WHEN** `make_bootstrap_summary` is called with key IDs
- **THEN** an IDkgPayload is created with key transcripts in the Begin state
- **AND** subsequent data blocks will create the initial key transcripts via IDKG

### Requirement: IDKG Payload Verification
IDKG payloads must be verified by re-creating the expected payload from the same inputs and checking equality.

#### Scenario: Valid payload matches locally recreated payload
- **WHEN** an IDKG payload is being verified
- **THEN** newly completed artifacts are extracted from the payload
- **AND** these artifacts are independently validated
- **AND** a new payload is created from the same inputs
- **AND** the payloads are compared for equality

#### Scenario: Mismatched payload is rejected as invalid
- **WHEN** the locally recreated payload does not match the received payload
- **THEN** the payload is rejected with a DataPayloadMismatch or SummaryPayloadMismatch error

### Requirement: IDKG On-State-Change Scheduling
The IDKG component round-robins through its three subcomponents (pre-signer, signer, complaint handler) to ensure fair processing.

#### Scenario: Subcomponents are called in round-robin fashion
- **WHEN** `on_state_change` is called on the IDKG component
- **THEN** exactly one of pre_signer, signer, or complaint_handler is invoked per call
- **AND** the selection rotates across successive calls

---

## Crate: ic-consensus-vetkd

The vetKD (Verifiable Encrypted Threshold Key Derivation) consensus crate implements the payload builder for vetKD key derivation. It collects encrypted key shares from the IDKG pool, combines them into encrypted keys, and delivers responses to requesting canisters.

### Requirements

### Requirement: VetKD Payload Building
The payload builder must collect vetKD key shares, combine them, and produce a payload of agreements.

#### Scenario: Successful key derivation from sufficient shares
- **WHEN** the certified state contains a vetKD signature request context
- **AND** the key ID is enabled and the request has not expired
- **AND** sufficient encrypted key shares exist in the IDKG pool for the callback ID
- **AND** the shares can be combined into an encrypted key
- **THEN** a VetKdAgreement::Success is included in the payload with the encoded VetKdDeriveKeyResult

#### Scenario: Insufficient shares result in no agreement
- **WHEN** a vetKD request context exists
- **AND** the available key shares do not meet the reconstruction threshold
- **THEN** no agreement is included in the payload for that request (it is skipped)

#### Scenario: Non-vetKD contexts are skipped
- **WHEN** the certified state contains a signature request context
- **AND** the context is for ECDSA or Schnorr (not vetKD)
- **THEN** the context is skipped during payload building

#### Scenario: Already-delivered requests are skipped
- **WHEN** a vetKD request's callback ID appears in past payloads
- **THEN** the request is skipped during payload building

#### Scenario: Payload respects maximum size limit
- **WHEN** agreements are being assembled into a payload
- **AND** adding the next agreement would exceed max_payload_size
- **THEN** the agreement is not included and payload building stops

### Requirement: VetKD Request Rejection
Requests with invalid keys or that have expired must be rejected.

#### Scenario: Request with invalid key ID is rejected
- **WHEN** a vetKD request context references a key ID not in the set of valid (enabled) keys
- **THEN** a VetKdAgreement::Reject with VetKdErrorCode::InvalidKey is included in the payload

#### Scenario: Request expired by time is rejected
- **WHEN** a vetKD request context's batch_time is earlier than the expiry threshold (context_time minus signature_request_timeout_ns)
- **THEN** a VetKdAgreement::Reject with VetKdErrorCode::TimedOut is included in the payload

#### Scenario: Request expired by DKG interval is rejected
- **WHEN** a vetKD request context's VetKD arguments reference a height older than one full DKG interval before the current height
- **THEN** a VetKdAgreement::Reject with VetKdErrorCode::TimedOut is included in the payload
- **AND** this prevents use of NiDKG transcripts that may have been rotated out

### Requirement: VetKD Payload Validation
Payloads proposed by other replicas must be validated for correctness.

#### Scenario: Empty payload is always valid
- **WHEN** an empty payload (zero bytes) is being validated
- **THEN** validation succeeds

#### Scenario: Duplicate response is rejected
- **WHEN** a payload contains an agreement for a callback ID that was already delivered in past payloads
- **THEN** validation fails with InvalidVetKdPayloadReason::DuplicateResponse

#### Scenario: Missing context is rejected
- **WHEN** a payload contains an agreement for a callback ID not present in the certified state
- **THEN** validation fails with InvalidVetKdPayloadReason::MissingContext

#### Scenario: Non-vetKD context in payload is rejected
- **WHEN** a payload contains an agreement for a callback ID whose context is ECDSA or Schnorr
- **THEN** validation fails with InvalidVetKdPayloadReason::UnexpectedIDkgContext

#### Scenario: Successful agreement is cryptographically verified
- **WHEN** a payload contains a VetKdAgreement::Success
- **AND** the request context is valid (not expired, key enabled)
- **THEN** the encrypted key in the agreement is decoded and verified using `verify_encrypted_key`
- **AND** if verification fails with a reproducible error, the payload is rejected as invalid
- **AND** if verification fails with a transient error, a validation failure is returned

#### Scenario: Reject agreement must match expected rejection
- **WHEN** a payload contains a VetKdAgreement::Reject
- **AND** the expected rejection (based on key validity and expiry) does not match the received rejection
- **THEN** validation fails with InvalidVetKdPayloadReason::MismatchedAgreement

#### Scenario: Payload validation fails when VetKD is disabled
- **WHEN** a non-empty payload is being validated
- **AND** no chain key config exists in the registry for the subnet
- **THEN** validation fails with InvalidVetKdPayloadReason::Disabled

### Requirement: VetKD Response Delivery
Validated payload agreements must be converted into consensus responses for delivery to requesting canisters.

#### Scenario: Successful agreement is delivered as data response
- **WHEN** a VetKdAgreement::Success is in a validated payload
- **THEN** it is converted to a ConsensusResponse with ResponsePayload::Data containing the encrypted key result

#### Scenario: TimedOut rejection is delivered as reject response
- **WHEN** a VetKdAgreement::Reject(VetKdErrorCode::TimedOut) is in a validated payload
- **THEN** it is converted to a ConsensusResponse with a RejectContext containing RejectCode::SysTransient and message "VetKD request expired"

#### Scenario: InvalidKey rejection is delivered as reject response
- **WHEN** a VetKdAgreement::Reject(VetKdErrorCode::InvalidKey) is in a validated payload
- **THEN** it is converted to a ConsensusResponse with a RejectContext containing RejectCode::SysTransient and message "Invalid or disabled key_id in VetKD request"

### Requirement: VetKD Enabled Key Discovery
The payload builder must determine which vetKD keys are enabled by consulting the registry.

#### Scenario: Only enabled vetKD keys are considered
- **WHEN** the chain key config contains key configurations
- **THEN** only keys where `is_vetkd_key()` is true are included
- **AND** only keys that appear in the chain_key_enabled_subnets list for this subnet are included

#### Scenario: Request expiry is computed from config and DKG interval
- **WHEN** enabled keys and expiry are computed for a block height
- **THEN** the time-based expiry is context_time minus signature_request_timeout_ns
- **AND** the height-based expiry is the current height minus the DKG interval length

### Requirement: VetKD Metrics
The payload builder must record operational metrics for observability.

#### Scenario: Build and validate durations are recorded
- **WHEN** `build_payload` or `validate_payload` is called
- **THEN** the operation duration is recorded in the `vetkd_payload_build_duration` histogram

#### Scenario: Completed agreements are counted
- **WHEN** a key share combination succeeds
- **THEN** the `vetkd_payload_metrics` counter is incremented with label "vetkd_agreement_completed" and the key ID

#### Scenario: Errors are counted by type
- **WHEN** a payload building or validation error occurs
- **THEN** the `vetkd_payload_errors` counter is incremented with the appropriate error type label and key ID
