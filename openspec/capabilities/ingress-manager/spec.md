# Ingress Manager Capability Specification

**Source narrative**: `openspec/specs/ingress-manager/spec.md`
**Crates**: `ic-ingress-manager`
**Key files**: `rs/ingress_manager/src/ingress_handler.rs`, `rs/ingress_manager/src/ingress_selector.rs`

---

## REQ-ING-001: Ingress Message Validation

The ingress handler MUST validate unvalidated ingress messages and move them to the validated pool or discard them.

### SCENARIO-ING-001: Valid ingress message moved to validated pool
**Given** an unvalidated ingress message passes all validation checks
**And** the ingress pool is not full for the originating peer
**And** the message's expiry is within `current_time` to `current_time + MAX_INGRESS_TTL`
**When** the handler processes the message
**Then** the message is moved to the validated section of the ingress pool

### SCENARIO-ING-002: Invalid ingress message removed
**Given** an unvalidated ingress message fails validation (invalid signature, bad format)
**When** the handler processes the message
**Then** the message is removed from the unvalidated pool

### SCENARIO-ING-003: Ingress pool full — discard messages
**Given** the ingress pool has reached its limit for a given peer
**When** the handler processes messages from that peer
**Then** all unvalidated messages from that peer are removed

### SCENARIO-ING-004: Message too large
**Given** an ingress message exceeds `max_ingress_bytes_per_message`
**When** validation runs
**Then** the message is removed with reason `ingress_message_too_large`

### SCENARIO-ING-005: Message already known
**Given** an ingress message has already been processed (exists in ingress history)
**When** validation runs
**Then** the message is removed with reason `ingress_message_already_known`

### SCENARIO-ING-006: Invalid request signature
**Given** an ingress message's signature fails cryptographic validation
**When** validation runs
**Then** the message is removed with reason `invalid_request`

### SCENARIO-ING-007: Purge expired messages on consensus time advance
**Given** the consensus time advances
**When** purge runs
**Then** messages with expiry below the consensus time are purged from the pool

---

## REQ-ING-002: Ingress Payload Selection

The ingress selector MUST select validated messages for consensus block payloads with fairness and size limits.

### SCENARIO-ING-008: Select messages within byte limit
**Given** the ingress selector builds a payload
**When** messages are selected
**Then** total wire size of selected messages does not exceed `wire_byte_limit`
**And** total memory size does not exceed `memory_byte_limit`

### SCENARIO-ING-009: Fair per-canister round-robin selection
**Given** multiple canisters have pending ingress messages
**When** messages are selected
**Then** selection uses round-robin across canisters
**And** each canister receives an equal quota of the payload byte budget
**And** unused quota from canisters with fewer messages is redistributed proportionally

### SCENARIO-ING-010: Message ordering by pool arrival time
**Given** messages for a single canister are available
**When** messages are ordered within the canister queue
**Then** they are sorted by pool arrival time (not expiry time)
**And** this prevents priority manipulation via crafted expiry times

### SCENARIO-ING-011: Maximum messages per block limit
**Given** the number of selected messages reaches `max_ingress_messages_per_block`
**When** additional messages are considered
**Then** no additional messages are selected even if byte budget remains

### SCENARIO-ING-012: Minimum one message per block
**Given** `max_ingress_messages_per_block` is configured to 0 in the registry
**When** the limit is applied
**Then** it is adjusted to at least 1 to always allow a single message per block

### SCENARIO-ING-013: Duplicate detection via past payloads
**Given** a message was already included in a past block payload
**When** the selector considers it
**Then** it is not selected again (deduplication via IngressPayloadCache)

### SCENARIO-ING-014: Duplicate detection via ingress history
**Given** a message's ID appears in the ingress history (already executed)
**When** the selector considers it
**Then** it is not selected for inclusion

### SCENARIO-ING-015: Message expiry validation during selection
**Given** a message's expiry is outside the valid range
**When** the selector considers it
**Then** the message is not selected

### SCENARIO-ING-016: Cycles cost validation
**Given** a message requires cycles to be inducted
**When** the selector considers it
**Then** the target canister's cycle sufficiency is verified
**And** accumulated cycles per canister prevent double-spending

---

## REQ-ING-003: Ingress Payload Validation

The ingress selector MUST validate block payloads proposed by other nodes.

### SCENARIO-ING-017: Valid payload accepted
**Given** a proposed payload contains all-valid messages
**And** no message appears more than once
**And** total size is within limits
**When** validation runs
**Then** the payload passes validation

### SCENARIO-ING-018: Payload with duplicate message rejected
**Given** a proposed payload contains a message already in a past payload
**When** validation runs
**Then** the payload is rejected as invalid

### SCENARIO-ING-019: Payload exceeds size limit rejected
**Given** a proposed payload exceeds the maximum byte limit
**When** validation runs
**Then** the payload is rejected

### SCENARIO-ING-020: Payload exceeds message count limit rejected
**Given** a proposed payload has more messages than `max_ingress_messages_per_block`
**When** validation runs
**Then** the payload is rejected with `IngressPayloadTooManyMessages`

---

## REQ-ING-004: Ingress Payload Cache Management

The ingress manager MUST maintain a cache of past payload message IDs to prevent duplicate inclusion.

### SCENARIO-ING-021: Cache entries indexed by height and hash
**Given** a payload is finalized
**When** it is cached
**Then** its message IDs are cached indexed by (Height, HashOfBatchPayload)
**And** this supports blockchain branching where multiple payloads may exist at the same height

### SCENARIO-ING-022: Cache purge below certified height
**Given** the certified height increases
**When** GC runs
**Then** cache entries below the certified height are purged

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
## REQ-ING-005: Ingress Bouncer

The ingress bouncer MUST determine whether ingress messages should be retained or dropped in the artifact pool.

### SCENARIO-ING-023: Bouncer determines message retention
**Given** the bouncer evaluates an ingress message in the artifact pool
**When** the evaluation runs
**Then** it determines whether the message should be retained or dropped based on validity and freshness
**And** messages past their expiry are dropped

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-ING-001 | Message validation | linked | rs/ingress_manager/src/ingress_selector.rs |
| REQ-ING-002 | Payload selection | linked | rs/ingress_manager/src/ingress_selector.rs |
| REQ-ING-003 | Payload validation | linked | rs/ingress_manager/src/ingress_selector.rs |
| REQ-ING-004 | Payload cache | narrative | rs/ingress_manager/tests/ |
| REQ-ING-005 | Ingress bouncer | narrative | rs/ingress_manager/src/bouncer.rs |
| REQ-ING-004 | Payload cache | narrative | rs/ingress_manager/tests/ |
