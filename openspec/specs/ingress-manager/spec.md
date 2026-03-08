# Ingress Manager Specification

**Crates**: `ic-ingress-manager`

This specification covers the Ingress Manager (`rs/ingress_manager/`), which is responsible for validating, selecting, and managing ingress messages for inclusion in IC consensus blocks.

---

## Requirements

### Requirement: Ingress Message Validation (Ingress Handler)

The ingress handler validates unvalidated ingress messages from the ingress pool and decides whether to move them to the validated section or discard them.

#### Scenario: Valid ingress message moved to validated pool
- **WHEN** an unvalidated ingress message passes all validation checks
- **AND** the ingress pool is not full for the originating peer
- **AND** the message's expiry is within the valid range (current_time to current_time + MAX_INGRESS_TTL)
- **THEN** the message is moved to the validated section of the ingress pool

#### Scenario: Invalid ingress message removed
- **WHEN** an unvalidated ingress message fails validation (e.g., invalid signature, bad format)
- **THEN** the message is removed from the unvalidated pool

#### Scenario: Ingress pool full - discard message
- **WHEN** the ingress pool has reached its limit for a given peer
- **THEN** all unvalidated messages from that peer are removed

#### Scenario: Message too large
- **WHEN** an ingress message exceeds the maximum allowed size (`max_ingress_bytes_per_message`)
- **THEN** the message is removed with reason `ingress_message_too_large`

#### Scenario: Message already known
- **WHEN** an ingress message has already been processed (exists in ingress history)
- **THEN** the message is removed with reason `ingress_message_already_known`

#### Scenario: Invalid request signature
- **WHEN** an ingress message's signature fails cryptographic validation
- **THEN** the message is removed with reason `invalid_request`

#### Scenario: Purge expired messages
- **WHEN** the consensus time advances
- **THEN** messages with expiry below the consensus time are purged from the pool

#### Scenario: Consensus time not initialized
- **WHEN** the consensus time has not been initialized
- **THEN** the ingress handler does not process any state changes

#### Scenario: Registry settings unavailable
- **WHEN** the ingress message settings cannot be retrieved from the registry
- **THEN** the ingress handler does not process any state changes

---

### Requirement: Ingress Payload Selection (Ingress Selector)

The ingress selector selects validated ingress messages for inclusion in consensus block payloads, enforcing fairness and size limits.

#### Scenario: Select messages within byte limit
- **WHEN** the ingress selector builds a payload
- **THEN** the total wire size of selected messages does not exceed the `wire_byte_limit`
- **AND** the total memory size does not exceed the `memory_byte_limit`

#### Scenario: Fair per-canister selection via round-robin
- **WHEN** multiple canisters have pending ingress messages
- **THEN** messages are selected using round-robin across canisters
- **AND** each canister receives an equal quota of the payload byte budget
- **AND** unused quota from canisters with fewer messages is redistributed proportionally

#### Scenario: Message ordering within canister queue
- **WHEN** messages for a single canister are available
- **THEN** they are sorted by pool arrival time (not expiry time) to prevent manipulation
- **AND** this prevents malicious users from getting priority by crafting specific expiry times

#### Scenario: Maximum messages per block
- **WHEN** the number of selected messages reaches `max_ingress_messages_per_block`
- **THEN** no additional messages are selected even if byte budget remains

#### Scenario: Minimum messages per block guarantee
- **WHEN** `max_ingress_messages_per_block` is configured to 0 in the registry
- **THEN** it is adjusted to at least 1 to always allow a single message per block

#### Scenario: Duplicate message detection - past payloads
- **WHEN** a message was already included in a past block payload
- **THEN** it is not selected again (deduplication via IngressPayloadCache)

#### Scenario: Duplicate message detection - ingress history
- **WHEN** a message's ID appears in the ingress history (already executed)
- **THEN** it is not selected for inclusion

#### Scenario: Message expiry validation
- **WHEN** a message's expiry is outside the valid range (context.time to context.time + MAX_INGRESS_TTL)
- **THEN** the message is not selected

#### Scenario: Cycles cost validation
- **WHEN** a message requires cycles to be inducted
- **THEN** the selector verifies the target canister has sufficient cycles
- **AND** accumulates cycles needed per canister to prevent double-spending

#### Scenario: Weakened inclusion rule after iterations
- **WHEN** more than 4 round-robin iterations have occurred without filling the payload
- **THEN** the per-canister quota enforcement is relaxed (weak inclusion rule)
- **AND** each canister is allowed more messages per iteration to ensure progress

---

### Requirement: Ingress Payload Validation

The ingress selector validates block payloads proposed by other nodes.

#### Scenario: Valid payload accepted
- **WHEN** a proposed payload contains messages that are all valid
- **AND** no message appears more than once
- **AND** the total size is within limits
- **THEN** the payload passes validation

#### Scenario: Payload with duplicate message rejected
- **WHEN** a proposed payload contains a message that was already included in a past payload
- **THEN** the payload is rejected as invalid

#### Scenario: Payload exceeds size limit rejected
- **WHEN** a proposed payload exceeds the maximum byte limit
- **THEN** the payload is rejected

#### Scenario: Payload exceeds message count limit rejected
- **WHEN** a proposed payload has more messages than `max_ingress_messages_per_block`
- **THEN** the payload is rejected with `IngressPayloadTooManyMessages`

---

### Requirement: Ingress Payload Cache Management

The ingress manager maintains a cache of message IDs from past payloads to prevent duplicate inclusion.

#### Scenario: Cache entries indexed by height and hash
- **WHEN** a payload is finalized
- **THEN** its message IDs are cached indexed by (Height, HashOfBatchPayload)
- **AND** this supports blockchain branching where multiple payloads may exist at the same height

#### Scenario: Cache purge below certified height
- **WHEN** the certified height increases
- **THEN** cache entries below the certified height are purged

---

### Requirement: Ingress Bouncer

The ingress bouncer (`rs/ingress_manager/src/bouncer.rs`) manages the lifecycle of ingress messages in the artifact pool.

#### Scenario: Bouncer determines message retention
- **WHEN** the bouncer evaluates an ingress message
- **THEN** it determines whether the message should be retained or dropped based on its validity and freshness

---

### Requirement: Deterministic Testing Support

The ingress manager supports deterministic testing through configurable random state.

#### Scenario: Deterministic hash map ordering
- **WHEN** `RandomStateKind::Deterministic` is used
- **THEN** hash map iteration order is deterministic across runs
- **AND** test results are repeatable

#### Scenario: Random hash map ordering in production
- **WHEN** `RandomStateKind::Random` is used (production default)
- **THEN** hash map iteration order is randomized as normal

---

### Requirement: Malicious Flag Support

The ingress manager supports disabling validation for testing malicious behavior.

#### Scenario: Validation disabled by malicious flag
- **WHEN** the `maliciously_disable_ingress_validation` flag is set
- **THEN** all ingress messages pass validation regardless of signature correctness
- **AND** `CanisterIdSet::all()` is returned for any request
