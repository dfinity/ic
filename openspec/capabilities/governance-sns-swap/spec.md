# Governance: SNS Swap Capability Specification

**Source narrative**: `openspec/specs/governance/sns/sns-swap.md`, `openspec/specs/governance/sns/sns-lifecycle.md`
**Crates**: `ic-sns-swap`
**Key files**: `rs/sns/swap/src/`

---

## REQ-SWAP-001: Swap Lifecycle

The swap MUST follow a well-defined lifecycle: Pending → Adopted → Open → Committed|Aborted.

### SCENARIO-SWAP-001: Lifecycle states
**Given** the swap canister is created
**When** the lifecycle is queried
**Then** it supports states: Pending, Adopted, Open, Committed, Aborted
**And** Committed and Aborted are terminal states

### SCENARIO-SWAP-002: Adopted to Open transition
**Given** the swap is in `Adopted` state
**And** the current time reaches `decentralization_sale_open_timestamp_seconds`
**When** `try_open` runs
**Then** the lifecycle transitions to `Open`

### SCENARIO-SWAP-003: Open to Committed transition
**Given** the lifecycle is `Open`
**And** `min_direct_participation_threshold` is met
**And** either max ICP reached or swap duration elapsed
**When** `try_commit` runs
**Then** the lifecycle transitions to `Committed`

### SCENARIO-SWAP-004: Open to Aborted on insufficient participation
**Given** the lifecycle is `Open`
**And** the swap has ended but participation is NOT sufficient
**When** abort is evaluated
**Then** the swap transitions to `Aborted`

---

## REQ-SWAP-002: Direct Participation

Users MUST be able to participate by transferring ICP to the swap canister.

### SCENARIO-SWAP-005: Participation validation
**Given** a user attempts to participate
**When** validation runs
**Then** the swap must be `Open`
**And** the ICP target must not already be reached
**And** confirmation text must match if required by the swap configuration

### SCENARIO-SWAP-006: Confirmation text required
**Given** the swap requires confirmation text
**When** a participant provides matching text
**Then** participation proceeds

**When** the participant provides non-matching or no text
**Then** participation is rejected

---

## REQ-SWAP-003: Neurons' Fund Participation

The Neurons' Fund MUST provide matched funding based on a polynomial matching function.

### SCENARIO-SWAP-007: Matched funding scheme
**Given** `neurons_fund_participation` is true and constraints are set
**When** NF participation is computed
**Then** the amount follows a polynomial matching function
**And** it is capped at `max_neurons_fund_participation_icp_e8s`

---

## REQ-SWAP-004: Token Distribution (Neuron Baskets)

After commitment, SNS tokens MUST be distributed as neuron baskets with varying dissolve delays.

### SCENARIO-SWAP-008: Neuron basket generation
**Given** neuron recipes are created for a participant
**When** distribution runs
**Then** total SNS tokens are divided into `count` pieces (the basket size)
**And** each piece has increasing dissolve delay: 0, `dissolve_delay_interval_seconds`, 2x, etc.
**And** token amounts differ by at most 1 e8

### SCENARIO-SWAP-009: Token scaling
**Given** SNS tokens are distributed proportionally to ICP contributions
**When** scaling is computed
**Then** amount = `(amount_icp_e8s * total_sns_e8s) / total_icp_e8s` using 128-bit arithmetic

---

## REQ-SWAP-005: Swap Finalization

Finalization MUST distribute tokens, create neurons, and transition to operational state.

### SCENARIO-SWAP-010: Successful finalization steps
**Given** the swap is in `Committed` state
**When** finalization runs
**Then** steps execute in order:
  1. Sweep ICP to SNS treasury
  2. Settle Neurons' Fund with NNS governance
  3. Create SNS neuron recipes
  4. Sweep SNS tokens to neuron staking accounts
  5. Claim swap neurons in SNS governance
  6. Set governance mode to Normal
  7. Set SNS Root as sole controller of dapp canisters

### SCENARIO-SWAP-011: Aborted swap finalization
**Given** the swap is in `Aborted` state
**When** finalization runs
**Then** ICP is swept back to participants
**And** dapp controllers are restored to fallback controllers

### SCENARIO-SWAP-012: Auto-finalization
**Given** `should_auto_finalize` is true
**And** the swap has not already tried to auto-finalize
**When** periodic tasks run
**Then** `try_auto_finalize` calls `finalize` automatically
**And** `already_tried_to_auto_finalize` is set to prevent retries

---

## REQ-SWAP-006: Ticket Management

The swap MUST use a ticket system to manage participation requests.

### SCENARIO-SWAP-013: Ticket creation
**Given** a new participation request is initiated
**When** the ticket is created
**Then** a unique ticket ID is assigned from `next_ticket_id`
**And** the ticket tracks the buyer's principal and ICP amount

### SCENARIO-SWAP-014: Old ticket purging
**Given** periodic tasks run
**When** purging runs
**Then** old tickets are purged to prevent accumulation
**And** `purge_old_tickets_last_completion_timestamp_nanoseconds` tracks progress

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SWAP-001 | Swap lifecycle | narrative | rs/sns/swap/tests/ |
| REQ-SWAP-002 | Direct participation | narrative | rs/sns/swap/tests/ |
| REQ-SWAP-003 | Neurons' Fund | narrative | rs/sns/swap/tests/ |
| REQ-SWAP-004 | Token distribution | narrative | rs/sns/swap/tests/ |
| REQ-SWAP-005 | Finalization | narrative | rs/sns/swap/tests/ |
| REQ-SWAP-006 | Ticket management | narrative | rs/sns/swap/tests/ |
